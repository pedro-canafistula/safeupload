/* Original-stack, owned FCB/cache data path. See STAGED-WRITES.md for the
 * lock order, version retirement gate and the intentionally bounded namespace.
 * Every operation on one of our upper objects is completed or routed here. */
#include "Filter.h"
#include "Stage.h"
#include "StageSecurity.h"
#include "StagePublic.h"
#include "StageNativeRecords.h"
#include "StageBoundPublicationInternal.h"
#include <ntstrsafe.h>

#if SAFEUPLOAD_STAGING_PROTOTYPE
static NTSTATUS StageQueryNoReparseIdentity(PFLT_INSTANCE Instance,
    PUNICODE_STRING Name, BOOLEAN Directory, SAFEUPLOAD_STAGE_IDENTITY_V19 *Identity);
static VOID StageAdmissionTraceShutdown(VOID);
static NTSTATUS StageAdmissionProbeWorkerBody(_In_ PCUNICODE_STRING VolumeName,
    _In_ PCUNICODE_STRING RelativePath);
static NTSTATUS StageRegistryEntryProbeWorkerBody(_In_ PCUNICODE_STRING VolumeName,
    _In_ PCUNICODE_STRING RelativePath, _Out_ PSAFEUPLOAD_REGISTRY_ENTRY_STATUS Status);
_IRQL_requires_(PASSIVE_LEVEL)
static VOID StageDirectoryCollisionComplete(_In_ HANDLE Handle);
#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, StageQueryNoReparseIdentity)
#pragma alloc_text(PAGE, SafeUploadStageAdmissionTraceControl)
#pragma alloc_text(PAGE, SafeUploadStageAdmissionTraceReadBatch)
#pragma alloc_text(PAGE, SafeUploadStageAdmissionProbe)
#pragma alloc_text(PAGE, StageAdmissionProbeWorkerBody)
#pragma alloc_text(PAGE, SafeUploadStageRegistryEntryProbe)
#pragma alloc_text(PAGE, StageDirectoryCollisionComplete)
#pragma alloc_text(PAGE, StageRegistryEntryProbeWorkerBody)
#pragma alloc_text(PAGE, StageAdmissionTraceShutdown)
#endif
#endif

_IRQL_requires_max_(APC_LEVEL)
static BOOLEAN StageRenameShareAllowed(_In_ const SHARE_ACCESS *ShareAccess,
    _In_ PFILE_OBJECT FileObject);
struct _STAGE_STREAM;
static VOID StageOverlayBasic(_In_ const struct _STAGE_STREAM *Stream, _Inout_ PFILE_BASIC_INFORMATION Basic);
static VOID StageBasicWritten(_Inout_ struct _STAGE_STREAM *Stream);
static BOOLEAN StageBasicReadonly(_In_ const struct _STAGE_STREAM *Stream);
static VOID StageInitializeBasic(_Inout_ struct _STAGE_STREAM *Stream,
    _In_opt_ const struct _STAGE_STREAM *Previous, _In_ BOOLEAN Exists,
    _In_ ULONG Disposition, _In_ ULONG Attributes);
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageSetBasicInformation(_In_ PFLT_CALLBACK_DATA Data,
    _In_ struct _STAGE_STREAM *Stream, _In_ ACCESS_MASK GrantedAccess);
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageCaptureSealBasic(_In_ struct _STAGE_STREAM *Stream);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SafeUploadStageReleaseInstanceReferences)
#pragma alloc_text(PAGE, StageRenameShareAllowed)
#pragma alloc_text(PAGE, StageSetBasicInformation)
#pragma alloc_text(PAGE, StageCaptureSealBasic)
#endif

#define STAGE_TAG 'sUpS'
#define STAGE_LIMIT 128              /* allocated (live) versions; a released version returns its slot */
#define STAGE_TOMBSTONE_LIMIT 1024   /* renamed-away names hidden from their owner */
#define STAGE_EXIT_RING 64
#define STAGE_RETRY_FIRST_MS 250
#define STAGE_RETRY_DRAIN_MAX_MS 1000
#define STAGE_RETRY_EXCHANGE_MAX_MS 8000
#define STAGE_STATUS_READMIT ((NTSTATUS)0xE0535201L) /* internal: StageCreate asks its admission to run again */
#define STAGE_MAX_BYTES (16 * 1024 * 1024)
/* Storage features require their own logical inspection/reconstruction. */
#define STAGE_BASIC_ATTRIBUTES (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | \
    FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
#if SAFEUPLOAD_STAGING_PROTOTYPE
#define STAGE_ATTACH_LIMIT_PER_INSTANCE 32
#define STAGE_ATTACH_LIMIT_GLOBAL 128
#define STAGE_ATTACH_RETRY_MS 250
#endif

/* What a version waits on that Windows does not signal; only these arm the retry timer (owner decision 2026-10-10). */
#define STAGE_WAIT_NONE 0
#define STAGE_WAIT_DRAIN 1           /* no handle, but drain or the read-only reopen cannot finish: a user-mapped view, a section */
#define STAGE_WAIT_EXCHANGE 2        /* an exchange, or a discard deletion, needs timer retry */
#define STAGE_WAIT_SERVICE 3         /* seal/rename refusal or no service: retry at the next service connect */

typedef struct _STAGE_STREAM {
    FSRTL_ADVANCED_FCB_HEADER Header;
    FAST_MUTEX HeaderMutex;
    ERESOURCE Resource;
    ERESOURCE PagingResource;
    SECTION_OBJECT_POINTERS Sections;
    LIST_ENTRY Link;
    SHARE_ACCESS ShareAccess;
    PFILE_LOCK ByteLocks;
    struct _STAGE_VIEW *View;
    volatile LONG FileObjects;
    EX_RUNDOWN_REF PagingRundown;
    BOOLEAN ReadOnly;
    BOOLEAN Sealed;
    BOOLEAN Retired;            /* sealed, stage file deleted by the service, backing closed; released once unreferenced */
    BOOLEAN DiscardOnClose;     /* T5: namespace-pending delete; blocks creates and renames until discard acknowledgement */
    BOOLEAN DiscardDisposition; /* T5: ordinary disposition; separate from per-handle FILE_DISPOSITION_ON_CLOSE requests */
    ULONG DeleteOnCloseCount;   /* T5: active per-handle on-close requests; NamespaceResource then Resource */
    BOOLEAN Discarded;          /* T5: the service journaled it Discarded; terminal like Sealed, never inspected or published */
    NTSTATUS DrainStatus;
    /* Resource: logical app metadata, never the private backing's ACL/flags.
     * Positive times override service flush/close side effects. */
    FILE_BASIC_INFORMATION BasicOverrides;
    FILE_BASIC_INFORMATION SealBasic;
    BOOLEAN SealBasicValid;
    UNICODE_STRING StageName;
    WCHAR StageBuffer[SAFEUPLOAD_MAX_PATH_CHARS];
    PSAFEUPLOAD_EXCHANGE RenameExchange;
    PFLT_INSTANCE OriginalInstance;
    PFLT_INSTANCE BackingInstance;
    HANDLE BackingHandle;
    PFILE_OBJECT BackingObject;
    ULONG SectorSize;
    BOOLEAN ResourceInitialized;
    BOOLEAN PagingInitialized;
    USHORT VolumeLength;
    UNICODE_STRING Name;
    WCHAR NameBuffer[SAFEUPLOAD_MAX_PATH_CHARS];
    /* T4 lifetime (StageListLock): the work queue, the service's disposal, and RenameExchange changes (also under Resource). */
    LIST_ENTRY WorkLink;
    LIST_ENTRY ReservationLink;
    BOOLEAN WorkQueued;
    BOOLEAN ReservationLinked;
    BOOLEAN Listed;
    BOOLEAN Disposed;           /* SAFEUPLOAD_CONTROL_STAGE_DISPOSE: the service no longer needs this version */
    BOOLEAN DisposeDeferred;    /* a disposal that arrived during a rename exchange: applied if the rename aborts */
    UINT32 DisposeOutcome;
    UINT32 DeferredOutcome;
    UINT32 RenameCommits;       /* acknowledged rename commits; the journal counts the same (NamespaceTombstones) */
    /* NamespaceResource. */
    BOOLEAN HasTransferId;      /* set before the stream is listed; read under StageListLock afterwards */
    UCHAR Wait;                 /* STAGE_WAIT_* */
    GUID TransferId;            /* the stage basename's 32 hex digits ("N" form), the service's transfer ID */
#if SAFEUPLOAD_STAGING_PROTOTYPE
    /* Stage v19 exact-object lifetime. All namespace fields below are
     * serialized by StageNamespaceResource; RpcReferences is interlocked. */
    BOOLEAN BoundAllocation;
    PSAFEUPLOAD_STAGE_WRITER_LEASE AllocationWriterLease; /* Only an unresolved V23 reply owns this reference. */
    PSAFEUPLOAD_STAGE_WRITER_LEASE PublicationWriterLease; /* Closed evidence; never extends the app's share lifetime. */
    BOOLEAN PublicationEvidenceClosed; /* NamespaceResource; published only after local close completes. */
    BOOLEAN BoundSeedDurable; /* No authenticated completion producer yet; never inferred from an ACK. */
    BOOLEAN PrivateCancellationBusy;
    BOOLEAN PrivateCancellationAccepted;
    BOOLEAN MvpPublicationObserved; /* V28 proved publication won; not a cancellation or disposal ACK. */
    SAFEUPLOAD_PRIVATE_CANCEL_REQUEST PrivateCancellation; /* exact retry after a lost reply */
    SAFEUPLOAD_STAGE_SEED_COMPLETION SeedCompletion;
    SAFEUPLOAD_STAGE_IDENTITY_V19 StageIdentity;
    GUID DriverInstanceId;
    BOOLEAN StageIdentityValid;
    BOOLEAN ExpectedStageIdentityValid;
    SAFEUPLOAD_STAGE_IDENTITY_V19 ExpectedStageIdentity;
    ULONGLONG DestinationGeneration;
    BOOLEAN OwnerExited;
    BOOLEAN PrivateDeleteReserved;      /* global same-name barrier until last private handle cleanup */
    BOOLEAN DiscardRpcPending;
    BOOLEAN DiscardRpcInFlight;
    BOOLEAN SealRpcPending;
    BOOLEAN SealRpcInFlight;
    BOOLEAN RenameRpcPending;
    BOOLEAN RenameRpcInFlight;
    UCHAR RenameWait; /* Persistent obligation cause, including across collection/reply. */
    UCHAR HandleReceiptWait;
    UCHAR AllocationRecoveryWait;
    ULONGLONG RenameRetryAfter; /* Interrupt-time deadline of the failed attempt's retry arm. */
    ULONGLONG HandleReceiptRetryAfter;
    ULONGLONG AllocationRecoveryRetryAfter;
    BOOLEAN AllocationRpcInFlight;
    UINT32 DiscardRpcKind;
    GUID DeleteReservationId;
    BOOLEAN AllocationReceiptPending;
    BOOLEAN AllocationRecoveryPending;
    BOOLEAN AllocationRecoveryInFlight;
    BOOLEAN AllocationTupleKnown;
    /* v20: no protected create is exposed above this filter until the
     * exact manifest attachment transaction has a CompletionPermitted ACK. */
    BOOLEAN AttachCompletionPending;
    BOOLEAN AttachLifecycleInFlight;     /* one attach worker owns binding/replay through CREATE completion */
    BOOLEAN AttachCompletionFence;       /* closes same-version re-open until synthetic CREATE completion returns */
    BOOLEAN AttachTerminalPending;        /* exact op14 abort; ordinary kind-5 cleanup owns retirement */
    BOOLEAN AttachRetirePending;         /* op16 durable delete needs exact replay until ACK */
    BOOLEAN AttachAcknowledged;
    BOOLEAN AttachPrepareKnown;
    BOOLEAN AttachPrepareMayExist;
    BOOLEAN AttachCommitKnown;
    BOOLEAN AttachCommitMayExist;
    UINT32 AttachCommitResult;
    BOOLEAN AttachCompletionMayExist;
    BOOLEAN AttachCompletionKnown;
    SAFEUPLOAD_REQUEST AttachPrepareRequest;
    SAFEUPLOAD_REQUEST AttachCommitRequest;
    SAFEUPLOAD_REQUEST AttachAbortRequest;
    SAFEUPLOAD_REQUEST AttachCompletionRequest;
    SAFEUPLOAD_REQUEST AttachRetireRequest;
    BOOLEAN AnyHandleCleanupObserved; /* monotonic for this stage identity */
    BOOLEAN HandleReceiptPending;
    BOOLEAN HandleReceiptInFlight;
    BOOLEAN HandleReceiptAcknowledged;
    BOOLEAN HandleReceiptRequestValid;
    SAFEUPLOAD_REQUEST HandleReceiptRequest;
    SAFEUPLOAD_STAGE_ALLOCATE_V19 AllocationIntent;
    SAFEUPLOAD_REQUEST AllocationRequest;
    ULONG AllocationRecoveryProcessId;
    SAFEUPLOAD_STAGE_IDENTITY_V19 AllocationParentDirectoryIdentity;
    struct _STAGE_STREAM *AllocationReceiptParent;
    LONG AllocationReceiptReferences;
    UINT32 RpcKindSnapshot;
    ULONG RpcProcessIdSnapshot;
    SAFEUPLOAD_VOLUME_KIND RpcVolumeKindSnapshot;
    UINT64 RpcGenerationSnapshot;
    LONG64 RpcViewGenerationSnapshot;
    GUID RpcReservationSnapshot;
    GUID RpcTransferIdSnapshot;
    SAFEUPLOAD_STAGE_IDENTITY_V19 RpcIdentitySnapshot;
    PSAFEUPLOAD_EXCHANGE RpcRenameExchangeSnapshot;
    LONG RpcReferences;
    LIST_ENTRY RpcLink;                 /* worker-local queue while NamespaceResource is dropped */
    LIST_ENTRY RecoveryLink;             /* allocation receipt replay queue */
#endif
} STAGE_STREAM, *PSTAGE_STREAM;

typedef enum _STAGE_ADMISSION_TOKEN_OWNER {
    StageAdmissionTokenDispatch = 0,
    StageAdmissionTokenPostOperation = 1,
    StageAdmissionTokenPaging = 2,
    StageAdmissionTokenAttach = 3
} STAGE_ADMISSION_TOKEN_OWNER;

typedef struct _STAGE_ADMISSION_TOKEN_SLOT {
    PVOID Token;
    PVOID Transaction;
    STAGE_ADMISSION_TOKEN_OWNER Owner;
    LONG64 DirectorySequence;
    BOOLEAN DirectoryMutation;
    BOOLEAN DirectoryCollision;
} STAGE_ADMISSION_TOKEN_SLOT, *PSTAGE_ADMISSION_TOKEN_SLOT;

/* Internal token discriminator; no wire or persisted layout changes. */
#define STAGE_EPOCH_DIRECTORY_COLLISION 0x80000000UL
/* Counts reservations as well as live probe handles, including lower CREATEs. */
#define STAGE_DIRECTORY_COLLISION_LIMIT 16
static volatile LONG StageDirectoryCollisionHolds;

#if SAFEUPLOAD_STAGING_PROTOTYPE
/* Captured on the original CREATE before it is queued. Variable inputs are
 * owned copies, never pointers into a caller buffer or a later thread token.
 * This describes the request; only an NTFS-checked backend grants authority. */
typedef struct _STAGE_ATTACH_TRANSACTION {
    LIST_ENTRY QueueLink;
    LIST_ENTRY LookupLink;
    PFLT_CALLBACK_DATA CallbackData;
    /* Keep Filter Manager's immutable pointer snapshot for StageCreate. The
     * separately owned references below are mutable so the transaction can
     * release them without assigning through FLT_RELATED_OBJECTS' const
     * members. */
    FLT_RELATED_OBJECTS RelatedObjects;
    PFLT_FILTER ReferencedFilter;
    PFLT_INSTANCE ReferencedInstance;
    PFLT_VOLUME ReferencedVolume;
    PFILE_OBJECT ReferencedFileObject;
    PFLT_INSTANCE InstanceIdentity; /* raw lookup key after object refs are released */
    PFLT_FILE_NAME_INFORMATION NameInfo;
    PSTAGE_STREAM Stream;
    PSAFEUPLOAD_ADMISSION_EPOCH_TOKEN AdmissionToken;
    PEPROCESS RequestorProcess;
    SECURITY_CLIENT_CONTEXT OriginalSubject;
    BOOLEAN OriginalSubjectValid;
    SAFEUPLOAD_STAGE_CREATE_INPUT CreateInput;
    /* Per-original-CREATE lease, prepared only behind the NotReady bound gate.
     * The attach worker owns it until binding transfers it to one STAGE_HANDLE. */
    PSAFEUPLOAD_STAGE_WRITER_LEASE WriterLease;
    ACCESS_MASK WriterGrantedAccess;
    PSAFEUPLOAD_STAGE_NATIVE_RECORD NativeRecord;
    SAFEUPLOAD_STAGE_NATIVE_SNAPSHOT NativeSnapshot;
    UINT64 NativeGeneration;
    UINT64 NativePrepareRevision;
    UINT64 NativePrepareAuthority;
    SAFEUPLOAD_PUBLIC_RELAY_REPLY PublicOpenReceipt;
    BOOLEAN OrdinaryPublicOpen;
    BOOLEAN NativePath;
    ULONG RequestorProcessId;
    SAFEUPLOAD_VOLUME_KIND VolumeKind;
    LONG64 ExpectedGeneration;
    LONG64 DirectorySequence; /* Captured before the original name lookup. */
    BOOLEAN PrivateNamespace;
    BOOLEAN ById;
    BOOLEAN OwnNameInfo;
    BOOLEAN NameInfoIsSynthetic;
    volatile LONG CancelRequested;
    volatile LONG TeardownRequested;
    volatile LONG QueueAborted;
    volatile LONG CancelCallbackState; /* 0 uncalled, 1 running, 2 exited */
    volatile LONG ExposeClaimed;
    volatile LONG PreOpReturnCommitted;
    volatile LONG CompletionClaimed;
    KEVENT PreOpReturnEvent;
    KEVENT CancelCallbackExited;
    KEVENT Completed;
    BOOLEAN LookupLinked;
    BOOLEAN CancelRegistered;
    BOOLEAN StreamCreated;
    BOOLEAN ServiceRequestMayExist;
    BOOLEAN PrepareKnown;
    BOOLEAN CommitKnown;
    BOOLEAN CompletionMayExist;
    BOOLEAN CompletionKnown;
    BOOLEAN NeedsAttachCommit;
    BOOLEAN UnexposedRetirementAllowed;
    BOOLEAN BindingInstalled;
    BOOLEAN WorkerOwnsCompletion;
    BOOLEAN WorkItemQueued;
    BOOLEAN CompletionDecisionSuccess;
    GUID DriverInstanceId;
    SAFEUPLOAD_STAGE_IDENTITY_V19 ParentDirectoryIdentity;
    volatile LONG References;
    SAFEUPLOAD_REQUEST PrepareRequest;
    SAFEUPLOAD_REQUEST CommitRequest;
    SAFEUPLOAD_REQUEST AbortRequest;
    SAFEUPLOAD_REQUEST CompletionRequest;
    SAFEUPLOAD_REQUEST RetireRequest;
} STAGE_ATTACH_TRANSACTION, *PSTAGE_ATTACH_TRANSACTION;

typedef struct _STAGE_ATTACH_INSTANCE_TOMBSTONE {
    LIST_ENTRY Link;
    PFLT_INSTANCE Instance;
} STAGE_ATTACH_INSTANCE_TOMBSTONE, *PSTAGE_ATTACH_INSTANCE_TOMBSTONE;
#endif

typedef struct _STAGE_HANDLE {
    PSTAGE_STREAM Stream;
    ACCESS_MASK GrantedAccess;
    BOOLEAN Cleaned;
    BOOLEAN DeleteOnClose;      /* T5: this handle's FILE_DELETE_ON_CLOSE / FILE_DISPOSITION_ON_CLOSE request */
#if SAFEUPLOAD_STAGING_PROTOTYPE
    PSAFEUPLOAD_STAGE_WRITER_LEASE WriterLease; /* Independent CREATE; duplicates share until CLEANUP. */
#endif
    ULONG LockOwnerCount;
    PEPROCESS LockOwners[16]; /* Duplicate handles can issue locks in other processes. */
} STAGE_HANDLE, *PSTAGE_HANDLE;

static LIST_ENTRY StageStreams;
static KSPIN_LOCK StageListLock;
static ERESOURCE StageNamespaceResource;
static volatile ULONG StageStreamCount;
static volatile ULONG StageReservedStreamCount;
static volatile LONG64 StageLastUnloadVeto;
static LONG64 StageNamespaceSequence;
#if SAFEUPLOAD_STAGING_PROTOTYPE
/* NamespaceResource admits one file OR directory namespace mutation at a time. Lower
 * completion releases this atomic fence without taking a pageable resource.
 * New private creates/retargets refuse while it is owned; sequence changes
 * reject queued CREATEs whose name was captured before/during the mutation. */
static volatile LONG StageDirectoryMutationActive;
static volatile LONG64 StageDirectorySequence;
#endif
static volatile LONG StageFileObjects;
#if SAFEUPLOAD_STAGING_PROTOTYPE
/* False until FltStartFiltering returns success. The early CREATE gate makes
 * startup-failure teardown independent of staged FILE_OBJECT lifetimes. */
static volatile LONG StageFilteringReady;
/* Single owner under the shared file/directory fence, retained until post. */
static UCHAR StageMvpNamespaceCompletionTag;
static PFLT_FILE_NAME_INFORMATION StageMvpNamespaceCreateName; /* CREATE post is PASSIVE, including drain. */
static FILE_ID_INFORMATION StageMvpNamespaceCreateIdentity;
static PVOID StageMvpNamespaceRegistryContext;
static BOOLEAN StageMvpNamespaceCreateCallback;
static PVOID StageMvpNamespaceCreateContext; /* Single fenced native CREATE; legacy read/taint post context. */
#endif
static BOOLEAN StageStopping;
#if SAFEUPLOAD_STAGING_PROTOTYPE
/* A voluntary unload closes admission first but leaves the worker and service
 * port alive until exact empty/allocation cleanup ACKs arrive. */
static BOOLEAN StageUnloadPrepareWork;
/* Independent unload gate: rollback never reopens StageAttachAccepting, which
 * is also latched closed after an attachment allocation failure. Writers
 * publish this gate under StageAttachLock; CREATE reads it atomically. */
static volatile LONG StageUnloadAdmissionClosed;
/* Once exact unload cleanup may have reached the service, a veto cannot
 * reopen staging admission. Keep cleanup/reconnect work alive and require a
 * later unload retry to finish the transaction. */
static volatile LONG StageUnloadQuarantined;
static volatile LONG StageMandatoryTeardown;
static EX_RUNDOWN_REF StageOwnedCallbackBodies;
static BOOLEAN StageMandatoryLocalDrained;
#endif
static LIST_ENTRY StageViews;
static KEVENT StageWorkerStop;
static HANDLE StageWorkerHandle;
static BOOLEAN StageInitialized;
#if SAFEUPLOAD_STAGING_PROTOTYPE
static KSPIN_LOCK StageAttachLock;
static LIST_ENTRY StageAttachLookup;
static LIST_ENTRY StageAttachTearingDownInstances;
static KEVENT StageAttachDrained;
static KEVENT StageAttachChanged;
static LIST_ENTRY StageAttachQueue;
static KEVENT StageAttachQueueEvent;
static KEVENT StageAttachThreadStop;
static HANDLE StageAttachThreadHandle;
static volatile LONG StageAttachActiveCount;
/* CREATE captures in progress: reserved under StageAttachLock before the
 * first allocation or reference, converted to an active count when the
 * transaction becomes visible, or returned after its captured resources are
 * freed. Active + capturing never exceeds the global/per-instance limits. */
static PFLT_INSTANCE StageAttachCaptures[STAGE_ATTACH_LIMIT_GLOBAL];
static volatile LONG StageAttachCaptureCount;
static volatile LONG StageAttachStopping;
static BOOLEAN StageAttachAccepting;
static BOOLEAN StageAttachThreadRunning;
#endif
/* T4: the worker sleeps until an event queues a stream (StageListLock) or a sweep is requested. */
static LIST_ENTRY StageWorkQueue;
static KEVENT StageWorkEvent;
static KTIMER StageRetryTimer;
static KDPC StageRetryDpc;
static ULONG StageRetryMs;
static BOOLEAN StageRetryArmed;
static ULONGLONG StageRetryDueTime; /* NamespaceResource; scheduling hint only, never arming authority. */
static volatile LONG StageRetryFired;
static BOOLEAN StageSweepRequested;          /* StageListLock: service connected; recheck every version */
static BOOLEAN StageExitOverflow;            /* StageListLock: an exit did not fit the ring */
static BOOLEAN StageExitSweepPending;        /* NamespaceResource: an overflow sweep is still owed */
static ULONGLONG StageExitOverflowTime;      /* NamespaceResource: interrupt time of the last overflow */
#define STAGE_EXIT_SETTLE_100NS (10LL * 1000 * 1000) /* 1 s: an exiting process is signalled well within it */
static PEPROCESS StageExitRing[STAGE_EXIT_RING]; /* StageListLock: exited processes, referenced (no PID reuse) */
static ULONG StageExitCount;
static LIST_ENTRY StageTombstones;           /* NamespaceResource */
static LIST_ENTRY StageAllocationReservations; /* NamespaceResource; names held across V19 allocate RPC */
static ULONG StageTombstoneCount;
static ULONG StageViewCount;                 /* NamespaceResource */
static SAFEUPLOAD_STAGE_LIFETIME_COUNTERS StageCounters; /* interlocked */
#if SAFEUPLOAD_STAGING_PROTOTYPE
static GUID StageDriverInstanceId;
static volatile LONG StageReconcileNeeded;
static volatile LONG StageReconcileInFlight;
static volatile LONG StageServiceGeneration;
static BOOLEAN StageServiceAvailable; /* NamespaceResource; receipt eligibility, not receipt ownership. */
static UCHAR StageReconcileWait;
static SAFEUPLOAD_REQUEST StageEpochDrainRequest;
static UINT64 StageEpochDrainNonce;
static BOOLEAN StageEpochDrainRequestValid;
#endif

/* Native spin-lock transitions are isolated from callers in resident SAL helpers. */
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_raises_(DISPATCH_LEVEL)
__declspec(noinline) static VOID StageStreamAcquireSpinLock(
    _In_ PKSPIN_LOCK Lock, _Out_ _At_(*OldIrql, _IRQL_saves_) PKIRQL OldIrql)
{
    KeAcquireSpinLock(Lock, OldIrql);
}

_IRQL_requires_(DISPATCH_LEVEL)
__declspec(noinline) static VOID StageStreamReleaseSpinLock(
    _In_ PKSPIN_LOCK Lock, _In_ _IRQL_restores_ KIRQL OldIrql)
{
    KeReleaseSpinLock(Lock, OldIrql);
}

#if SAFEUPLOAD_STAGING_PROTOTYPE
/* Serialize attach admission closure with the active-count publication in
 * StageAttachQueueCreate. This lock is never nested with NamespaceResource. */
static VOID StageSetUnloadAdmissionClosed(_In_ BOOLEAN Closed)
{
    KIRQL irql;
    StageStreamAcquireSpinLock(&StageAttachLock, &irql);
    InterlockedExchange(&StageUnloadAdmissionClosed, Closed ? 1 : 0);
    StageStreamReleaseSpinLock(&StageAttachLock, irql);
}

/* Caller owns NamespaceResource, matching StageWorkerPass's lock order. No
 * producer holds StageListLock while waiting for NamespaceResource. */
static BOOLEAN StageWorkerHasPendingWork(VOID)
{
    KIRQL irql;
    BOOLEAN pending;
    StageStreamAcquireSpinLock(&StageListLock, &irql);
    pending = !IsListEmpty(&StageWorkQueue) || StageSweepRequested ||
        StageExitOverflow || StageExitCount != 0 ||
        InterlockedCompareExchange(&StageRetryFired, 0, 0) != 0;
    StageStreamReleaseSpinLock(&StageListLock, irql);
    return pending || StageExitSweepPending;
}
#endif

#if SAFEUPLOAD_STAGING_PROTOTYPE
// Static storage is nonpaged and gives the callback path a bounded ring with
// no allocation or lifetime race. An odd control state means tracing is on.
volatile LONG SafeUploadAdmissionTraceControlState;
volatile LONG SafeUploadAdmissionTraceSectionEvents;
static volatile LONG AdmissionTraceLifetimeEvents;
#define STAGE_TRACE_WATCH_SLOTS 64
// Section object pointers of streams that got a writable CreateSection while the lifetime option was on.
// Observe-only: it only widens which cleanup/close events are recorded. A full table drops new entries.
static volatile PVOID AdmissionTraceWatch[STAGE_TRACE_WATCH_SLOTS];
DECLSPEC_ALIGN(8) static SAFEUPLOAD_ADMISSION_TRACE_ENTRY AdmissionTraceRing[
    SAFEUPLOAD_ADMISSION_TRACE_RING_ENTRIES];
DECLSPEC_ALIGN(8) static volatile LONG64 AdmissionTraceNextSequence;
static volatile LONG AdmissionTraceWriterBusy;
static SAFEUPLOAD_ADMISSION_TRACE_COUNTERS AdmissionTraceCounters;
static EX_RUNDOWN_REF AdmissionTraceRundown;
static FAST_MUTEX AdmissionTraceControlMutex;
static BOOLEAN AdmissionTraceRundownClosed;

static LONG StageAdmissionTraceNextState(_In_ LONG CurrentState, _In_ BOOLEAN Enable)
{
    ULONG nextState = (((ULONG)CurrentState & 0x7ffffffeUL) + 2UL) & 0x7ffffffeUL;
    if (Enable) nextState |= 1UL;
    return (LONG)nextState;
}

static VOID StageAdmissionTraceReset(VOID)
{
    ULONG index;
    InterlockedExchange64(&AdmissionTraceNextSequence, 0);
    for (index = 0; index < SAFEUPLOAD_ADMISSION_TRACE_RING_ENTRIES; index += 1) {
        InterlockedExchange64((volatile LONG64 *)&AdmissionTraceRing[index].Sequence, 0);
    }
    InterlockedExchange(&AdmissionTraceWriterBusy, 0);
    RtlZeroMemory(&AdmissionTraceCounters, sizeof(AdmissionTraceCounters));
    for (index = 0; index < STAGE_TRACE_WATCH_SLOTS; index += 1) {
        InterlockedExchangePointer((PVOID volatile *)&AdmissionTraceWatch[index], NULL);
    }
}

static VOID StageAdmissionTraceSnapshotCounters(
    _Out_ PSAFEUPLOAD_ADMISSION_TRACE_COUNTERS Destination)
{
    Destination->TotalEvents = (UINT64)InterlockedCompareExchange64(
        (volatile LONG64 *)&AdmissionTraceCounters.TotalEvents, 0, 0);
    Destination->PagingWrites = (UINT64)InterlockedCompareExchange64(
        (volatile LONG64 *)&AdmissionTraceCounters.PagingWrites, 0, 0);
    Destination->NonPagingWrites = (UINT64)InterlockedCompareExchange64(
        (volatile LONG64 *)&AdmissionTraceCounters.NonPagingWrites, 0, 0);
    Destination->SectionAcquires = (UINT64)InterlockedCompareExchange64(
        (volatile LONG64 *)&AdmissionTraceCounters.SectionAcquires, 0, 0);
    Destination->SectionReleases = (UINT64)InterlockedCompareExchange64(
        (volatile LONG64 *)&AdmissionTraceCounters.SectionReleases, 0, 0);
    Destination->InstanceSetups = (UINT64)InterlockedCompareExchange64(
        (volatile LONG64 *)&AdmissionTraceCounters.InstanceSetups, 0, 0);
    Destination->LostEntries = (UINT64)InterlockedCompareExchange64(
        (volatile LONG64 *)&AdmissionTraceCounters.LostEntries, 0, 0);
}

BOOLEAN SafeUploadStageAdmissionTraceBegin(_In_ LONG TraceState)
{
    if ((TraceState & 1) == 0 || !ExAcquireRundownProtection(&AdmissionTraceRundown)) {
        return FALSE;
    }

    KeMemoryBarrier();
    if (SafeUploadAdmissionTraceControlState != TraceState) {
        ExReleaseRundownProtection(&AdmissionTraceRundown);
        return FALSE;
    }

    return TRUE;
}

VOID SafeUploadStageAdmissionTraceEnd(VOID)
{
    ExReleaseRundownProtection(&AdmissionTraceRundown);
}

static BOOLEAN StageAdmissionTraceRecordInternal(
    _In_ const SAFEUPLOAD_ADMISSION_TRACE_ENTRY *Entry,
    _In_ BOOLEAN WaitForWriter)
{
    SAFEUPLOAD_ADMISSION_TRACE_ENTRY copy;
    PSAFEUPLOAD_ADMISSION_TRACE_ENTRY slot;
    LARGE_INTEGER timestamp;
    LONGLONG signedSequence;
    LONGLONG lastCommittedSequence;
    UINT64 sequence;
    ULONG index;

    InterlockedIncrement64((volatile LONG64 *)&AdmissionTraceCounters.TotalEvents);
    switch (Entry->EventKind) {
    case SAFEUPLOAD_ADMISSION_TRACE_EVENT_PAGING_WRITE:
        InterlockedIncrement64((volatile LONG64 *)&AdmissionTraceCounters.PagingWrites);
        break;
    case SAFEUPLOAD_ADMISSION_TRACE_EVENT_UNOWNED_NONPAGING_WRITE:
        InterlockedIncrement64((volatile LONG64 *)&AdmissionTraceCounters.NonPagingWrites);
        break;
    case SAFEUPLOAD_ADMISSION_TRACE_EVENT_SECTION_ACQUIRE:
        InterlockedIncrement64((volatile LONG64 *)&AdmissionTraceCounters.SectionAcquires);
        break;
    case SAFEUPLOAD_ADMISSION_TRACE_EVENT_SECTION_RELEASE:
        InterlockedIncrement64((volatile LONG64 *)&AdmissionTraceCounters.SectionReleases);
        break;
    case SAFEUPLOAD_ADMISSION_TRACE_EVENT_INSTANCE_SETUP:
        InterlockedIncrement64((volatile LONG64 *)&AdmissionTraceCounters.InstanceSetups);
        break;
    default:
        break;
    }

    // Callback writers drop on reservation contention. The explicit probe
    // may wait here while appending its one user-requested entry.
    while (InterlockedCompareExchange(&AdmissionTraceWriterBusy, 1, 0) != 0) {
        if (!WaitForWriter) {
            InterlockedIncrement64((volatile LONG64 *)&AdmissionTraceCounters.LostEntries);
            return FALSE;
        }
        YieldProcessor();
    }

    lastCommittedSequence = InterlockedCompareExchange64(&AdmissionTraceNextSequence, 0, 0);
    signedSequence = lastCommittedSequence + 1;
    sequence = (UINT64)signedSequence;
    index = (ULONG)((sequence - 1ULL) &
        ((UINT64)SAFEUPLOAD_ADMISSION_TRACE_RING_ENTRIES - 1ULL));
    slot = &AdmissionTraceRing[index];

    if (sequence > SAFEUPLOAD_ADMISSION_TRACE_RING_ENTRIES) {
        InterlockedIncrement64((volatile LONG64 *)&AdmissionTraceCounters.LostEntries);
    }

    // Zero marks an in-progress overwrite. The reader-visible high-water mark
    // is updated only after the slot sequence is committed below.
    InterlockedExchange64((volatile LONG64 *)&slot->Sequence, 0);
    KeQuerySystemTime(&timestamp);
    copy = *Entry;
    copy.Sequence = sequence;
    copy.Timestamp = (UINT64)timestamp.QuadPart;
    RtlCopyMemory(&slot->Timestamp,
                  &copy.Timestamp,
                  sizeof(copy) - FIELD_OFFSET(SAFEUPLOAD_ADMISSION_TRACE_ENTRY, Timestamp));
    KeMemoryBarrier();
    InterlockedExchange64((volatile LONG64 *)&slot->Sequence, (LONG64)sequence);
    KeMemoryBarrier();
    InterlockedExchange64(&AdmissionTraceNextSequence, signedSequence);
    InterlockedExchange(&AdmissionTraceWriterBusy, 0);
    return TRUE;
}

VOID SafeUploadStageAdmissionTraceRecord(
    _In_ const SAFEUPLOAD_ADMISSION_TRACE_ENTRY *Entry)
{
    (VOID)StageAdmissionTraceRecordInternal(Entry, FALSE);
}

VOID SafeUploadStageAdmissionTraceNoteLost(_In_ LONG TraceState)
{
    if (SafeUploadStageAdmissionTraceBegin(TraceState)) {
        InterlockedIncrement64((volatile LONG64 *)&AdmissionTraceCounters.LostEntries);
        SafeUploadStageAdmissionTraceEnd();
    }
}

VOID SafeUploadStageAdmissionTraceNoteTicketLost(VOID)
{
    /* Caller holds recorder rundown or an outstanding ticket, so CLEAR cannot
     * pass its off-state/drain check before this explicit loss is visible. */
    InterlockedIncrement64((volatile LONG64 *)&AdmissionTraceCounters.LostEntries);
}

NTSTATUS SafeUploadStageAdmissionTraceControl(_In_ UINT32 Command, _In_ UINT32 Options)
{
    LONG state;
    LONG64 lostBeforeClose;
    BOOLEAN wasEnabled;
    NTSTATUS status = STATUS_SUCCESS;

    PAGED_CODE();
    ExAcquireFastMutex(&AdmissionTraceControlMutex);
    state = InterlockedCompareExchange(&SafeUploadAdmissionTraceControlState, 0, 0);
    wasEnabled = (state & 1) != 0;

    if (Command == SAFEUPLOAD_CONTROL_ADMISSION_TRACE_ENABLE) {
        InterlockedExchange(&SafeUploadAdmissionTraceSectionEvents,
                            (Options & SAFEUPLOAD_ADMISSION_TRACE_OPTION_SECTION_EVENTS) != 0 ? 1 : 0);
        InterlockedExchange(&AdmissionTraceLifetimeEvents,
                            (Options & SAFEUPLOAD_ADMISSION_TRACE_OPTION_FILE_LIFETIME) != 0 ? 1 : 0);
        if (!wasEnabled) {
            if (AdmissionTraceRundownClosed) {
                ExReInitializeRundownProtection(&AdmissionTraceRundown);
                AdmissionTraceRundownClosed = FALSE;
            }
            InterlockedExchange(&SafeUploadAdmissionTraceControlState,
                                StageAdmissionTraceNextState(state, TRUE));
        }
    } else if (Command == SAFEUPLOAD_CONTROL_ADMISSION_TRACE_DISABLE ||
               Command == SAFEUPLOAD_CONTROL_ADMISSION_TRACE_CLEAR) {
        lostBeforeClose = InterlockedCompareExchange64(
            (volatile LONG64 *)&AdmissionTraceCounters.LostEntries, 0, 0);
        InterlockedExchange(&SafeUploadAdmissionTraceControlState,
                            StageAdmissionTraceNextState(state, FALSE));
        if (!AdmissionTraceRundownClosed) {
            ExWaitForRundownProtectionRelease(&AdmissionTraceRundown);
            AdmissionTraceRundownClosed = TRUE;
        }

        /* The off-state plus drained recorder rundown closes admission for new
         * observer tickets. Refuse disable/clear while an already paired W
         * ticket is live, then reopen recording so its matching end is retained. */
        if (SafeUploadStageWritersObserverTicketsOutstanding() != 0 ||
            InterlockedCompareExchange64((volatile LONG64 *)&AdmissionTraceCounters.LostEntries, 0, 0) !=
                lostBeforeClose) {
            /* A W_END may retire during the off-state window and record an
             * explicit loss before dropping its outstanding count. Do not let
             * CLEAR erase that loss and turn an unmatched pair into a clean run. */
            if (wasEnabled) {
                ExReInitializeRundownProtection(&AdmissionTraceRundown);
                AdmissionTraceRundownClosed = FALSE;
                state = InterlockedCompareExchange(&SafeUploadAdmissionTraceControlState, 0, 0);
                InterlockedExchange(&SafeUploadAdmissionTraceControlState,
                                    StageAdmissionTraceNextState(state, TRUE));
            }
            status = STATUS_DEVICE_BUSY;
        } else if (Command == SAFEUPLOAD_CONTROL_ADMISSION_TRACE_CLEAR) {
            StageAdmissionTraceReset();
            if (wasEnabled) {
                ExReInitializeRundownProtection(&AdmissionTraceRundown);
                AdmissionTraceRundownClosed = FALSE;
                state = InterlockedCompareExchange(&SafeUploadAdmissionTraceControlState, 0, 0);
                InterlockedExchange(&SafeUploadAdmissionTraceControlState,
                                    StageAdmissionTraceNextState(state, TRUE));
            }
        }
    } else {
        status = STATUS_INVALID_PARAMETER;
    }

    ExReleaseFastMutex(&AdmissionTraceControlMutex);
    return status;
}

NTSTATUS SafeUploadStageAdmissionTraceReadBatch(
    _In_ UINT64 Cursor,
    _In_ UINT64 SnapshotSequence,
    _Out_ PSAFEUPLOAD_ADMISSION_TRACE_BATCH Batch)
{
    UINT64 latest;
    UINT64 snapshot;
    UINT64 oldest;
    UINT64 scan;

    PAGED_CODE();
    if (Batch == NULL) return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(Batch, sizeof(*Batch));
    ExAcquireFastMutex(&AdmissionTraceControlMutex);
    latest = (UINT64)InterlockedCompareExchange64(&AdmissionTraceNextSequence, 0, 0);
    snapshot = SnapshotSequence == 0 ? latest : SnapshotSequence;
    if (snapshot > latest || (Cursor != 0 && Cursor - 1ULL > snapshot)) {
        ExReleaseFastMutex(&AdmissionTraceControlMutex);
        return STATUS_INVALID_PARAMETER;
    }

    oldest = latest > SAFEUPLOAD_ADMISSION_TRACE_RING_ENTRIES ?
        latest - SAFEUPLOAD_ADMISSION_TRACE_RING_ENTRIES + 1ULL : 1ULL;
    scan = Cursor == 0 ? oldest : Cursor;
    if (scan < oldest) scan = oldest;

    Batch->Control.Version = SAFEUPLOAD_PROTOCOL_VERSION;
    Batch->Control.StructSize = sizeof(*Batch);
    Batch->Control.Command = SAFEUPLOAD_CONTROL_ADMISSION_TRACE_READ_BATCH;
    Batch->EntryCount = 0;
    Batch->Cursor = scan;
    Batch->SnapshotSequence = snapshot;

    while (scan <= snapshot && Batch->EntryCount < SAFEUPLOAD_ADMISSION_TRACE_BATCH_ENTRIES) {
        SAFEUPLOAD_ADMISSION_TRACE_ENTRY copy;
        PSAFEUPLOAD_ADMISSION_TRACE_ENTRY slot;
        UINT64 before;
        UINT64 after;
        ULONG index = (ULONG)((scan - 1ULL) &
            ((UINT64)SAFEUPLOAD_ADMISSION_TRACE_RING_ENTRIES - 1ULL));

        slot = &AdmissionTraceRing[index];
        before = (UINT64)InterlockedCompareExchange64((volatile LONG64 *)&slot->Sequence, 0, 0);
        if (before == scan) {
            RtlCopyMemory(&copy, slot, sizeof(copy));
            KeMemoryBarrier();
            after = (UINT64)InterlockedCompareExchange64((volatile LONG64 *)&slot->Sequence, 0, 0);
            if (before == after && copy.Sequence == after) {
                Batch->Entries[Batch->EntryCount] = copy;
                Batch->EntryCount += 1;
            } else if (after <= scan || copy.Sequence != before) {
                // If an overwrite has not committed, leave the cursor here
                // so a later read can retry publication.
                break;
            }
        } else if (before < scan) {
            // Sequence tickets are published after their slots commit; this
            // mismatch is a slot transition, so do not skip the cursor.
            break;
        }

        if (scan == 0xffffffffffffffffULL) break;
        scan += 1ULL;
    }

    Batch->NextCursor = scan;
    StageAdmissionTraceSnapshotCounters(&Batch->Counters);
    ExReleaseFastMutex(&AdmissionTraceControlMutex);
    return STATUS_SUCCESS;
}

static VOID StageAdmissionTraceShutdown(VOID)
{
    LONG state;

    PAGED_CODE();
    ExAcquireFastMutex(&AdmissionTraceControlMutex);
    state = InterlockedCompareExchange(&SafeUploadAdmissionTraceControlState, 0, 0);
    InterlockedExchange(&SafeUploadAdmissionTraceControlState,
                        StageAdmissionTraceNextState(state, FALSE));
    if (!AdmissionTraceRundownClosed) {
        ExWaitForRundownProtectionRelease(&AdmissionTraceRundown);
        AdmissionTraceRundownClosed = TRUE;
    }
    ExReleaseFastMutex(&AdmissionTraceControlMutex);
}

static VOID StageAdmissionTraceFillOperation(
    _Out_ PSAFEUPLOAD_ADMISSION_TRACE_ENTRY Entry,
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects,
    _In_ UINT32 EventKind,
    _In_ BOOLEAN OwnedStream)
{
    PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
    KIRQL irql = KeGetCurrentIrql();

    RtlZeroMemory(Entry, sizeof(*Entry));
    Entry->EventKind = EventKind;
    Entry->Irql = irql;
    Entry->MajorFunction = Data->Iopb->MajorFunction;
    Entry->MinorFunction = Data->Iopb->MinorFunction;
    Entry->IrpFlags = Data->Iopb->IrpFlags;
    Entry->OwnedStream = OwnedStream ? 1u : 0u;
    Entry->AdmissionRecordState = 0;
    Entry->MmDoesResult = SAFEUPLOAD_ADMISSION_TRACE_MMDOES_NOT_APPLICABLE;
    Entry->StreamContextState = SAFEUPLOAD_ADMISSION_TRACE_CONTEXT_NOT_QUERIED;
    Entry->VolumeKind = SafeUploadVolumeUnknown;
    if (KeGetCurrentIrql() <= APC_LEVEL) Entry->ProcessId = FltGetRequestorProcessId(Data);
    if (Objects->Instance != NULL) Entry->Instance = (UINT64)(ULONG_PTR)Objects->Instance;
    if (fileObject != NULL) {
        Entry->TargetFileObject = (UINT64)(ULONG_PTR)fileObject;
        Entry->SectionObjectPointer = (UINT64)(ULONG_PTR)fileObject->SectionObjectPointer;
    } else {
        Entry->StreamContextState = SAFEUPLOAD_ADMISSION_TRACE_CONTEXT_NOT_APPLICABLE;
    }
}

static BOOLEAN StageTraceWatchContains(_In_opt_ PVOID SectionObjectPointer)
{
    ULONG index;
    if (SectionObjectPointer == NULL) return FALSE;
    for (index = 0; index < STAGE_TRACE_WATCH_SLOTS; index += 1) {
        if (AdmissionTraceWatch[index] == SectionObjectPointer) return TRUE;
    }
    return FALSE;
}

static VOID StageTraceWatchAdd(_In_opt_ PVOID SectionObjectPointer)
{
    ULONG index;
    if (SectionObjectPointer == NULL || StageTraceWatchContains(SectionObjectPointer)) return;
    for (index = 0; index < STAGE_TRACE_WATCH_SLOTS; index += 1) {
        if (InterlockedCompareExchangePointer((PVOID volatile *)&AdmissionTraceWatch[index],
                                              SectionObjectPointer, NULL) == NULL) return;
    }
}

// Observe-only. Records IRP_MJ_CLEANUP (last user handle gone) and IRP_MJ_CLOSE (last reference gone)
// of a file object that was opened with write access or whose stream got a writable CreateSection while
// tracing, so the gap between the two, and the lifetime of any internal file object a section keeps, can
// be measured. It runs only when tracing and the file-lifetime option are on, reads no paged data,
// takes no lock beyond the ring's try-lock, and never alters the operation.
static VOID StageTraceFileLifetime(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects,
    _In_ UINT32 EventKind)
{
    LONG traceState = SafeUploadAdmissionTraceControlState;
    PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
    SAFEUPLOAD_ADMISSION_TRACE_ENTRY entry;

    if ((traceState & 1) == 0 || AdmissionTraceLifetimeEvents == 0) return;
    if (fileObject == NULL) return;
    if (!fileObject->WriteAccess && !StageTraceWatchContains(fileObject->SectionObjectPointer)) return;
    if (!SafeUploadStageAdmissionTraceBegin(traceState)) return;
    StageAdmissionTraceFillOperation(&entry, Data, Objects, EventKind, FALSE);
    entry.MmDoesResult = SAFEUPLOAD_ADMISSION_TRACE_MMDOES_SKIPPED;
    SafeUploadStageAdmissionTraceRecord(&entry);
    SafeUploadStageAdmissionTraceEnd();
}

// Observe-only. With the file-lifetime option on, remembers the stream of every writable CreateSection and
// records that event even when the (noisy) section option is off, so cleanup/close of the file objects that
// stream's section keeps alive can be attributed to it.
static VOID StageTraceWritableCreateSection(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects)
{
    LONG traceState = SafeUploadAdmissionTraceControlState;
    PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
    SAFEUPLOAD_ADMISSION_TRACE_ENTRY entry;
    UINT32 protection;

    if ((traceState & 1) == 0 || AdmissionTraceLifetimeEvents == 0 || fileObject == NULL) return;
    if (Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType != SyncTypeCreateSection) return;
    protection = Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection;
    if ((protection & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) == 0) return;
    StageTraceWatchAdd(fileObject->SectionObjectPointer);
    if (SafeUploadAdmissionTraceSectionEvents != 0) return;   // the section hook records it
    if (!SafeUploadStageAdmissionTraceBegin(traceState)) return;
    StageAdmissionTraceFillOperation(&entry, Data, Objects, SAFEUPLOAD_ADMISSION_TRACE_EVENT_SECTION_ACQUIRE, FALSE);
    entry.MmDoesResult = SAFEUPLOAD_ADMISSION_TRACE_MMDOES_SKIPPED;
    entry.SyncType = (UINT32)Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType;
    entry.PageProtection = protection;
    entry.SyncParametersValid = 1;
    SafeUploadStageAdmissionTraceRecord(&entry);
    SafeUploadStageAdmissionTraceEnd();
}


static NTSTATUS StageAdmissionProbeWorkerBody(
    _In_ PCUNICODE_STRING VolumeName,
    _In_ PCUNICODE_STRING RelativePath)
{
    SAFEUPLOAD_ADMISSION_TRACE_ENTRY entry;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    UNICODE_STRING fullPath;
    PFLT_VOLUME volume = NULL;
    PFLT_INSTANCE instance = NULL;
    PFLT_CONTEXT instanceContext = NULL;
    HANDLE probeHandle = NULL;
    PFILE_OBJECT probeFileObject = NULL;
    HANDLE identityHandle = NULL;
    PFILE_OBJECT identityObject = NULL;
    PSECTION_OBJECT_POINTERS sectionObjectPointer = NULL;
    PWCHAR fullPathBuffer = NULL;
    FLT_FILESYSTEM_TYPE fileSystemType;
    SAFEUPLOAD_VOLUME_KIND volumeKind = SafeUploadVolumeUnknown;
    ULONG fullPathBytes;
    LONG traceState;
    UINT32 probeStage;
    NTSTATUS status;

    PAGED_CODE();
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    traceState = InterlockedCompareExchange(&SafeUploadAdmissionTraceControlState, 0, 0);
    if ((traceState & 1) == 0) return STATUS_DEVICE_NOT_READY;

    RtlZeroMemory(&entry, sizeof(entry));
    entry.EventKind = SAFEUPLOAD_ADMISSION_TRACE_EVENT_EXPLICIT_PROBE;
    entry.ProcessId = HandleToULong(PsGetCurrentProcessId());
    entry.Irql = KeGetCurrentIrql();
    entry.MmDoesResult = SAFEUPLOAD_ADMISSION_TRACE_MMDOES_SKIPPED;
    entry.StreamContextState = SAFEUPLOAD_ADMISSION_TRACE_CONTEXT_NOT_APPLICABLE;
    entry.VolumeKind = SafeUploadVolumeUnknown;
    entry.ProbeStage = SAFEUPLOAD_ADMISSION_PROBE_STAGE_VOLUME_LOOKUP;
    probeStage = SAFEUPLOAD_ADMISSION_PROBE_STAGE_VOLUME_LOOKUP;

    status = FltGetVolumeFromName(SafeUploadData.Filter, VolumeName, &volume);
    if (!NT_SUCCESS(status)) goto Record;

    probeStage = SAFEUPLOAD_ADMISSION_PROBE_STAGE_INSTANCE_LOOKUP;
    status = FltGetVolumeInstanceFromName(SafeUploadData.Filter, volume, NULL, &instance);
    if (!NT_SUCCESS(status)) goto Record;
    entry.Instance = (UINT64)(ULONG_PTR)instance;

    probeStage = SAFEUPLOAD_ADMISSION_PROBE_STAGE_INSTANCE_CONTEXT;
    status = FltGetInstanceContext(instance, &instanceContext);
    if (!NT_SUCCESS(status)) goto Record;
    volumeKind = ((PSAFEUPLOAD_INSTANCE_CONTEXT)instanceContext)->VolumeKind;
    entry.CanaryState = (UINT32)InterlockedCompareExchange(
        &((PSAFEUPLOAD_INSTANCE_CONTEXT)instanceContext)->CanaryState, 0, 0);
    if (entry.CanaryState >= SAFEUPLOAD_CANARY_PASSED) {
        entry.CanaryStatus = (UINT32)((PSAFEUPLOAD_INSTANCE_CONTEXT)instanceContext)->CanaryStatus;
        entry.CanaryChecks = ((PSAFEUPLOAD_INSTANCE_CONTEXT)instanceContext)->CanaryChecks;
        entry.CanaryCleanupStatus = (UINT32)((PSAFEUPLOAD_INSTANCE_CONTEXT)instanceContext)->CanaryCleanupStatus;
    } else {
        entry.CanaryStatus = entry.CanaryCleanupStatus = (UINT32)STATUS_PENDING;
    }
    entry.VolumeKind = (UINT32)volumeKind;
    FltReleaseContext(instanceContext);
    instanceContext = NULL;

    if (volumeKind != SafeUploadVolumeFixed) {
        probeStage = SAFEUPLOAD_ADMISSION_PROBE_STAGE_VOLUME_KIND;
        status = STATUS_NOT_SUPPORTED;
        goto Record;
    }

    probeStage = SAFEUPLOAD_ADMISSION_PROBE_STAGE_FILESYSTEM_TYPE;
    status = FltGetFileSystemType(instance, &fileSystemType);
    if (!NT_SUCCESS(status)) goto Record;
    if (fileSystemType != FLT_FSTYPE_NTFS) {
        status = STATUS_NOT_SUPPORTED;
        goto Record;
    }

    if (InterlockedCompareExchange(&SafeUploadAdmissionTraceControlState, 0, 0) != traceState) {
        status = STATUS_DEVICE_NOT_READY;
        goto Cleanup;
    }

    fullPathBytes = (ULONG)VolumeName->Length + (ULONG)RelativePath->Length;
    probeStage = SAFEUPLOAD_ADMISSION_PROBE_STAGE_PATH_ALLOCATION;
    fullPathBuffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_PAGED, fullPathBytes, SAFEUPLOAD_POOL_TAG);
    if (fullPathBuffer == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Record;
    }

    RtlCopyMemory(fullPathBuffer, VolumeName->Buffer, VolumeName->Length);
    RtlCopyMemory((PUCHAR)fullPathBuffer + VolumeName->Length,
                  RelativePath->Buffer,
                  RelativePath->Length);
    fullPath.Buffer = fullPathBuffer;
    fullPath.Length = (USHORT)fullPathBytes;
    fullPath.MaximumLength = (USHORT)fullPathBytes;

    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));
    InitializeObjectAttributes(&objectAttributes,
        &fullPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    probeStage = SAFEUPLOAD_ADMISSION_PROBE_STAGE_LOWER_OPEN;
    status = FltCreateFileEx2(SafeUploadData.Filter,
        instance,
        &probeHandle,
        &probeFileObject,
        FILE_READ_ATTRIBUTES,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_COMPLETE_IF_OPLOCKED,
        NULL,
        0,
        IO_STOP_ON_SYMLINK,
        NULL);
    if (status == STATUS_STOPPED_ON_SYMLINK && ioStatusBlock.Information != 0)
        ExFreePool((PVOID)ioStatusBlock.Information);
    if (status != STATUS_SUCCESS) goto Record;
    status = SafeUploadStageOpenByIdentity(instance, VolumeName, probeFileObject,
        &identityHandle, &identityObject, &probeStage);
    if (status != STATUS_SUCCESS) goto Record;
    entry.ProbeStatus = (UINT32)status;
    if (identityObject != NULL) {
        sectionObjectPointer = identityObject->SectionObjectPointer;
        entry.TargetFileObject = (UINT64)(ULONG_PTR)identityObject;
        entry.SectionObjectPointer = (UINT64)(ULONG_PTR)sectionObjectPointer;
    }
    if (sectionObjectPointer != NULL && KeGetCurrentIrql() == PASSIVE_LEVEL) {
        entry.MmDoesResult = MmDoesFileHaveUserWritableReferences(sectionObjectPointer) ?
            SAFEUPLOAD_ADMISSION_TRACE_MMDOES_YES :
            SAFEUPLOAD_ADMISSION_TRACE_MMDOES_NO;
    }
    if (identityObject != NULL) {
        /* Reuses AdmissionRecordState (a constant until now): H(F) of the probed stream, bit 31 = untracked. */
        entry.AdmissionRecordState = SafeUploadStageWritersSnapshot(instance, identityObject);
        /* SetupFlags is unused by probe entries; it carries C(F) of the probed stream. */
        entry.SetupFlags = SafeUploadStageSectionsInFlight(sectionObjectPointer);
    }
    if (sectionObjectPointer == NULL) status = STATUS_INVALID_FILE_FOR_SECTION;
    if (status == STATUS_SUCCESS) probeStage = SAFEUPLOAD_ADMISSION_PROBE_STAGE_COMPLETE;

Record:
    entry.ProbeStage = probeStage;
    entry.ProbeStatus = (UINT32)status;
    if (!SafeUploadStageAdmissionTraceBegin(traceState)) {
        status = STATUS_DEVICE_NOT_READY;
        goto Cleanup;
    }
    (VOID)StageAdmissionTraceRecordInternal(&entry, TRUE);
    SafeUploadStageAdmissionTraceEnd();
    status = STATUS_SUCCESS;

Cleanup:
    if (identityHandle != NULL) FltClose(identityHandle);
    if (identityObject != NULL) ObDereferenceObject(identityObject);
    if (instanceContext != NULL) FltReleaseContext(instanceContext);
    if (fullPathBuffer != NULL) ExFreePoolWithTag(fullPathBuffer, SAFEUPLOAD_POOL_TAG);
    if (probeHandle != NULL) FltClose(probeHandle);
    if (probeFileObject != NULL) ObDereferenceObject(probeFileObject);
    if (instance != NULL) FltObjectDereference(instance);
    if (volume != NULL) FltObjectDereference(volume);
    return status;
}

NTSTATUS SafeUploadStageAdmissionDeleteStreamContext(_In_ PCUNICODE_STRING VolumeName,
    _In_ PCUNICODE_STRING RelativePath)
{
    PFLT_VOLUME volume = NULL;
    PFLT_VOLUME cVolume = NULL;
    PFLT_INSTANCE instance = NULL;
    PSAFEUPLOAD_INSTANCE_CONTEXT instanceContext = NULL;
    PSAFEUPLOAD_STREAM_CONTEXT streamContext = NULL;
    HANDLE handle = NULL;
    PFILE_OBJECT fileObject = NULL;
    PWCHAR fullPathBuffer = NULL;
    UNICODE_STRING fullPath;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK ioStatus;
    FLT_FILESYSTEM_TYPE fileSystemType;
    ULONG fullPathBytes;
    NTSTATUS status;
    UNICODE_STRING cDrive = RTL_CONSTANT_STRING(L"\\??\\C:");

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    if (VolumeName == NULL || RelativePath == NULL || VolumeName->Length == 0 ||
        RelativePath->Length < sizeof(WCHAR) * 2 ||
        VolumeName->Length > MAXUSHORT - RelativePath->Length ||
        (VolumeName->Length % sizeof(WCHAR)) != 0 || (RelativePath->Length % sizeof(WCHAR)) != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    status = FltGetVolumeFromName(SafeUploadData.Filter, VolumeName, &volume);
    if (!NT_SUCCESS(status)) goto Exit;
    status = FltGetVolumeFromName(SafeUploadData.Filter, &cDrive, &cVolume);
    if (!NT_SUCCESS(status)) goto Exit;
    if (cVolume != volume) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }
    status = FltGetVolumeInstanceFromName(SafeUploadData.Filter, volume, NULL, &instance);
    if (!NT_SUCCESS(status)) goto Exit;

    status = FltGetInstanceContext(instance, (PFLT_CONTEXT *)&instanceContext);
    if (!NT_SUCCESS(status)) goto Exit;
    if (instanceContext->VolumeKind != SafeUploadVolumeFixed) {
        status = STATUS_NOT_SUPPORTED;
        goto Exit;
    }
    status = FltGetFileSystemType(instance, &fileSystemType);
    if (!NT_SUCCESS(status)) goto Exit;
    if (fileSystemType != FLT_FSTYPE_NTFS) {
        status = STATUS_NOT_SUPPORTED;
        goto Exit;
    }
    FltReleaseContext(instanceContext);
    instanceContext = NULL;

    fullPathBytes = (ULONG)VolumeName->Length + (ULONG)RelativePath->Length;
    fullPathBuffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_PAGED, fullPathBytes, SAFEUPLOAD_POOL_TAG);
    if (fullPathBuffer == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    /* Bounded copies: MaximumLength is exactly the validated sum, so both appends must fit. */
    fullPath.Buffer = fullPathBuffer;
    fullPath.Length = 0;
    fullPath.MaximumLength = (USHORT)fullPathBytes;
    RtlCopyUnicodeString(&fullPath, VolumeName);
    status = RtlAppendUnicodeStringToString(&fullPath, RelativePath);
    if (!NT_SUCCESS(status) || fullPath.Length != fullPathBytes) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    InitializeObjectAttributes(&attributes, &fullPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    RtlZeroMemory(&ioStatus, sizeof(ioStatus));
    status = FltCreateFileEx2(SafeUploadData.Filter, instance, &handle, &fileObject,
        FILE_READ_ATTRIBUTES, &attributes, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_COMPLETE_IF_OPLOCKED,
        NULL, 0, IO_STOP_ON_SYMLINK, NULL);
    if (status == STATUS_STOPPED_ON_SYMLINK && ioStatus.Information != 0)
        ExFreePool((PVOID)ioStatus.Information);
    if (!NT_SUCCESS(status)) goto Exit;

    status = FltGetStreamContext(instance, fileObject, (PFLT_CONTEXT *)&streamContext);
    if (!NT_SUCCESS(status)) goto Exit;
    if ((SafeUploadStageWritersSnapshot(instance, fileObject) &
         ~SAFEUPLOAD_WRITERS_UNTRACKED_BIT) == 0) {
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }

    if (!SafeUploadStageWritersInvalidateLifetime(streamContext)) {
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    FltDeleteContext((PFLT_CONTEXT)streamContext);
    status = STATUS_SUCCESS;

Exit:
    if (streamContext != NULL) FltReleaseContext(streamContext);
    if (handle != NULL) FltClose(handle);
    if (fileObject != NULL) ObDereferenceObject(fileObject);
    if (instanceContext != NULL) FltReleaseContext(instanceContext);
    if (fullPathBuffer != NULL) ExFreePoolWithTag(fullPathBuffer, SAFEUPLOAD_POOL_TAG);
    if (instance != NULL) FltObjectDereference(instance);
    if (cVolume != NULL) FltObjectDereference(cVolume);
    if (volume != NULL) FltObjectDereference(volume);
    return status;
}

typedef struct _STAGE_ADMISSION_PROBE_WORK {
    KEVENT Done;
    PCUNICODE_STRING VolumeName;
    PCUNICODE_STRING RelativePath;
    NTSTATUS Status;
} STAGE_ADMISSION_PROBE_WORK;

static VOID StageAdmissionProbeWorker(PFLT_GENERIC_WORKITEM WorkItem, PVOID FltObject, PVOID Context)
{
    STAGE_ADMISSION_PROBE_WORK *work = Context;
    UNREFERENCED_PARAMETER(FltObject);
    work->Status = StageAdmissionProbeWorkerBody(work->VolumeName, work->RelativePath);
    FltFreeGenericWorkItem(WorkItem);
    KeSetEvent(&work->Done, IO_NO_INCREMENT, FALSE);
    /* The waiting message callback owns work; do not touch it after signaling. */
}

NTSTATUS SafeUploadStageAdmissionProbe(_In_ PCUNICODE_STRING VolumeName,
    _In_ PCUNICODE_STRING RelativePath)
{
    STAGE_ADMISSION_PROBE_WORK work;
    PFLT_GENERIC_WORKITEM item;
    NTSTATUS status;
    PAGED_CODE();
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    /* Only the explicit control message calls this routine. No probe I/O runs on its caller's
     * thread, and no I/O callback waits on this work item. The message's rundown protects unload. */
    KeInitializeEvent(&work.Done, NotificationEvent, FALSE);
    work.VolumeName = VolumeName;
    work.RelativePath = RelativePath;
    work.Status = STATUS_UNSUCCESSFUL;
    if (!ExAcquireRundownProtection(&SafeUploadData.ChannelRundown)) return STATUS_FLT_DELETING_OBJECT;
    item = FltAllocateGenericWorkItem();
    if (item == NULL) {
        ExReleaseRundownProtection(&SafeUploadData.ChannelRundown);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    status = FltQueueGenericWorkItem(item, SafeUploadData.Filter, StageAdmissionProbeWorker,
        DelayedWorkQueue, &work);
    if (!NT_SUCCESS(status)) {
        FltFreeGenericWorkItem(item);
        ExReleaseRundownProtection(&SafeUploadData.ChannelRundown);
        return status;
    }
    (VOID)KeWaitForSingleObject(&work.Done, Executive, KernelMode, FALSE, NULL);
    ExReleaseRundownProtection(&SafeUploadData.ChannelRundown);
    return work.Status;
}

typedef struct _STAGE_REGISTRY_PROBE_WORK {
    KEVENT Done;
    PCUNICODE_STRING VolumeName;
    PCUNICODE_STRING RelativePath;
    PSAFEUPLOAD_REGISTRY_ENTRY_STATUS Status;
    NTSTATUS CompletionStatus;
} STAGE_REGISTRY_PROBE_WORK, *PSTAGE_REGISTRY_PROBE_WORK;

static VOID StageRegistryEntryProbeWorker(PFLT_GENERIC_WORKITEM WorkItem, PVOID FltObject, PVOID Context)
{
    PSTAGE_REGISTRY_PROBE_WORK work = Context;
    UNREFERENCED_PARAMETER(FltObject);
    work->CompletionStatus = StageRegistryEntryProbeWorkerBody(work->VolumeName,
        work->RelativePath, work->Status);
    FltFreeGenericWorkItem(WorkItem);
    KeSetEvent(&work->Done, IO_NO_INCREMENT, FALSE);
}

NTSTATUS SafeUploadStageRegistryEntryProbe(_In_ PCUNICODE_STRING VolumeName,
    _In_ PCUNICODE_STRING RelativePath, _Out_ PSAFEUPLOAD_REGISTRY_ENTRY_STATUS Status)
{
    STAGE_REGISTRY_PROBE_WORK work;
    PFLT_GENERIC_WORKITEM item;
    NTSTATUS result;
    PAGED_CODE();
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    KeInitializeEvent(&work.Done, NotificationEvent, FALSE);
    work.VolumeName = VolumeName;
    work.RelativePath = RelativePath;
    work.Status = Status;
    work.CompletionStatus = STATUS_UNSUCCESSFUL;
    if (!ExAcquireRundownProtection(&SafeUploadData.ChannelRundown)) return STATUS_FLT_DELETING_OBJECT;
    item = FltAllocateGenericWorkItem();
    if (item == NULL) {
        ExReleaseRundownProtection(&SafeUploadData.ChannelRundown);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    result = FltQueueGenericWorkItem(item, SafeUploadData.Filter, StageRegistryEntryProbeWorker,
        DelayedWorkQueue, &work);
    if (!NT_SUCCESS(result)) {
        FltFreeGenericWorkItem(item);
        ExReleaseRundownProtection(&SafeUploadData.ChannelRundown);
        return result;
    }
    (VOID)KeWaitForSingleObject(&work.Done, Executive, KernelMode, FALSE, NULL);
    ExReleaseRundownProtection(&SafeUploadData.ChannelRundown);
    return work.CompletionStatus;
}

static NTSTATUS StageRegistryEntryProbeWorkerBody(_In_ PCUNICODE_STRING VolumeName,
    _In_ PCUNICODE_STRING RelativePath, _Out_ PSAFEUPLOAD_REGISTRY_ENTRY_STATUS Result)
{
    PFLT_VOLUME volume = NULL;
    PFLT_INSTANCE instance = NULL;
    PFILE_OBJECT sourceObject = NULL;
    PFLT_FILE_NAME_INFORMATION normalizedName = NULL;
    HANDLE sourceHandle = NULL;
    PWCHAR fullNameBuffer = NULL;
    UNICODE_STRING fullName;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io = {0};
    ULONG fullNameBytes;
    NTSTATUS status;

    PAGED_CODE();
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    RtlZeroMemory(Result, sizeof(*Result));
    if (VolumeName->Length > MAXUSHORT - RelativePath->Length ||
        VolumeName->Length + RelativePath->Length == 0) return STATUS_NAME_TOO_LONG;
    fullNameBytes = (ULONG)VolumeName->Length + RelativePath->Length;
    fullNameBuffer = ExAllocatePool2(POOL_FLAG_PAGED, fullNameBytes, SAFEUPLOAD_POOL_TAG);
    if (fullNameBuffer == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(fullNameBuffer, VolumeName->Buffer, VolumeName->Length);
    RtlCopyMemory((PUCHAR)fullNameBuffer + VolumeName->Length,
        RelativePath->Buffer, RelativePath->Length);
    fullName.Buffer = fullNameBuffer;
    fullName.Length = fullName.MaximumLength = (USHORT)fullNameBytes;

    status = FltGetVolumeFromName(SafeUploadData.Filter, VolumeName, &volume);
    if (!NT_SUCCESS(status)) goto Exit;
    status = FltGetVolumeInstanceFromName(SafeUploadData.Filter, volume, NULL, &instance);
    if (!NT_SUCCESS(status)) goto Exit;
    /* A tracked Activating name can be answered from memory. Do this before
     * opening the target: NTFS may block that open behind the very TxF
     * transaction the diagnostic is meant to report. */
    if (SafeUploadStageWritersRegistrySnapshotByName(
            instance, volume, &fullName, Result)) {
        status = STATUS_SUCCESS;
        goto Exit;
    }
    InitializeObjectAttributes(&attributes, &fullName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = FltCreateFileEx2(SafeUploadData.Filter, instance, &sourceHandle, &sourceObject,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attributes, &io, NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_COMPLETE_IF_OPLOCKED,
        NULL, 0, IO_STOP_ON_SYMLINK, NULL);
    if (status == STATUS_STOPPED_ON_SYMLINK && io.Information != 0)
        ExFreePool((PVOID)io.Information);
    if (status != STATUS_SUCCESS) goto Exit;
    status = FltGetFileNameInformationUnsafe(sourceObject, instance,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &normalizedName);
    if (!NT_SUCCESS(status)) goto Exit;
    status = FltParseFileNameInformation(normalizedName);
    if (!NT_SUCCESS(status)) goto Exit;
    if (normalizedName->Stream.Length != 0) {
        /* This path resolves an ADS or an ambiguous stream; it is outside the file key. */
        status = STATUS_NOT_SUPPORTED;
        goto Exit;
    }
    status = SafeUploadStageWritersRegistryEvaluate(instance, VolumeName,
        &normalizedName->Name, sourceObject, Result);

Exit:
    if (normalizedName != NULL) FltReleaseFileNameInformation(normalizedName);
    if (sourceHandle != NULL) FltClose(sourceHandle);
    if (sourceObject != NULL) ObDereferenceObject(sourceObject);
    if (instance != NULL) FltObjectDereference(instance);
    if (volume != NULL) FltObjectDereference(volume);
    if (fullNameBuffer != NULL) ExFreePoolWithTag(fullNameBuffer, SAFEUPLOAD_POOL_TAG);
    return status;
}
#endif

/* A name the owner renamed away stays logically absent for that owner (pre-T4 this was a per-view list pointing at the version).
 * The record keeps only the renamed version's transfer ID, so versions and views can be released independently. One record per
 * owner and name; a view that takes the name again removes it; the owner's exit frees its records. NamespaceResource. */
typedef struct _STAGE_TOMBSTONE {
    LIST_ENTRY Link;
    PEPROCESS Owner;           /* referenced: the PID cannot be reused while the record lives */
    ULONG OwnerProcessId;
    LONG64 Sequence;
    WCHAR TransferId[32];      /* the renamed version's stage GUID: the service's durable tombstone owner */
    UNICODE_STRING TransferName;
    UNICODE_STRING Name;
} STAGE_TOMBSTONE, *PSTAGE_TOMBSTONE;

typedef struct _STAGE_VIEW {
    LIST_ENTRY Link;
    PEPROCESS Owner;
    ULONG OwnerProcessId;
    PSECURITY_DESCRIPTOR Security;
    BOOLEAN AssignedSecurity;
    BOOLEAN Detached; /* Replaced name; held objects retain this version/view. */
    FILE_ID_INFORMATION Identity; /* Private logical file, independent of its versions. */
    FILE_ID_INFORMATION PhysicalIdentity;
    FILE_ID_INFORMATION ParentIdentity;
    BOOLEAN PhysicalExists;
    LONG64 Generation;          /* unique per view (StageNamespaceSequence): admission compares this, never the pointer */
    PSTAGE_STREAM Current;      /* valid while attached; a detached view's current version may already be released */
    ULONG Streams;              /* allocated versions whose View is this view; freed at zero once detached */
    UNICODE_STRING Name;
    WCHAR NameBuffer[SAFEUPLOAD_MAX_PATH_CHARS];
} STAGE_VIEW, *PSTAGE_VIEW;

static FLT_PREOP_CALLBACK_STATUS StagePreOperation(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, PVOID *CompletionContext,
    PSTAGE_ADMISSION_TOKEN_SLOT AdmissionSlot);
#if SAFEUPLOAD_STAGING_PROTOTYPE
static NTSTATUS StageAttachQueueCreate(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, PFLT_FILE_NAME_INFORMATION Name,
    SAFEUPLOAD_VOLUME_KIND VolumeKind, LONG64 ExpectedGeneration,
    BOOLEAN PrivateNamespace, BOOLEAN ById, BOOLEAN TakeNameOwnership,
    PSTAGE_ADMISSION_TOKEN_SLOT AdmissionSlot);
static VOID StageAttachCancelCallback(PFLT_CALLBACK_DATA Data);
static BOOLEAN StageAttachNativeEligible(PFLT_CALLBACK_DATA Data);
static KSTART_ROUTINE StageAttachWorkerThread;
static VOID StageAttachTransactionDereference(PSTAGE_ATTACH_TRANSACTION Transaction);
static VOID StageAttachReleaseRelatedObjects(PSTAGE_ATTACH_TRANSACTION Transaction);
static VOID StageAttachCommitPreOpReturn(PSTAGE_ATTACH_TRANSACTION Transaction);
static VOID StageCollectHandleReceiptRpcs(PLIST_ENTRY Rpcs);
static VOID StagePerformHandleReceiptRpcs(PLIST_ENTRY Rpcs);
static BOOLEAN StageAttachHasInstance(_In_ PFLT_INSTANCE Instance);
static VOID StageAttachRollbackBinding(_Inout_ PSTAGE_ATTACH_TRANSACTION Transaction,
    _Inout_ PSTAGE_STREAM Stream);
static VOID StageAttachQueueUnattachedAllocation(_Inout_ PSTAGE_STREAM Stream);
static VOID StageAttachComplete(_Inout_ PSTAGE_ATTACH_TRANSACTION Transaction,
    _In_ NTSTATUS Status);
static VOID StageAttachReference(_Inout_ PSTAGE_ATTACH_TRANSACTION Transaction);
static BOOLEAN StageAttachRetryAllowed(_In_ PSTAGE_ATTACH_TRANSACTION Transaction);
static NTSTATUS StageAttachExchangeRetry(_Inout_ PSTAGE_ATTACH_TRANSACTION Transaction,
    _In_ UINT32 Operation, _Inout_ PSAFEUPLOAD_REQUEST Request, _Out_ PUINT32 Result);
static NTSTATUS StageAttachRunLifecycle(_Inout_ PSTAGE_ATTACH_TRANSACTION Transaction,
    _Inout_ PSTAGE_STREAM Stream);
static NTSTATUS StageAttachSnapshotName(_In_ PFLT_FILE_NAME_INFORMATION Source,
    _Outptr_ PFLT_FILE_NAME_INFORMATION *Snapshot);
static BOOLEAN StageAttachRemoveLookup(_Inout_ PSTAGE_ATTACH_TRANSACTION Transaction);
static VOID StageAttachReleaseActive(VOID);
static VOID StageAttachDrainTransaction(_Inout_ PSTAGE_ATTACH_TRANSACTION Transaction);
static NTSTATUS StageAttachResumeOrRun(_Inout_ PSTAGE_ATTACH_TRANSACTION Transaction,
    _Out_ PBOOLEAN NewBinding);
static NTSTATUS StageAttachWorkerBody(_Inout_ PSTAGE_ATTACH_TRANSACTION Transaction);
static NTSTATUS StageAttachValidateCurrent(_Inout_ PSTAGE_ATTACH_TRANSACTION Transaction,
    _Inout_ PSTAGE_STREAM Stream);
static NTSTATUS StageAttachRetireUnexposed(_Inout_ PSTAGE_ATTACH_TRANSACTION Transaction,
    _Inout_ PSTAGE_STREAM Stream);
static BOOLEAN StageAttachIsInstanceTearingDown(_In_ PFLT_INSTANCE Instance);
#endif
_IRQL_requires_(DISPATCH_LEVEL)
static BOOLEAN StageQueueLocked(PSTAGE_STREAM Stream);
static VOID StageQueueStream(PSTAGE_STREAM Stream, volatile UINT64 *Reason);
static BOOLEAN StageSettleCurrent(PSTAGE_VIEW View);
static NTSTATUS StagePublicNameFree(PFLT_INSTANCE Instance, PUNICODE_STRING Name);
static VOID StageUpdateRetryTimer(VOID);
#if SAFEUPLOAD_STAGING_PROTOTYPE
static BOOLEAN StageParseTransferId(PCWCH Digits, USHORT Chars, GUID *Id);
static SAFEUPLOAD_VOLUME_KIND StageVolumeKind(PFLT_INSTANCE Instance);
static UCHAR StageWaitFor(NTSTATUS Status);
#endif

static PSTAGE_STREAM StageStreamForObject(PFILE_OBJECT FileObject)
{
    PLIST_ENTRY link;
    KIRQL irql;
    PSTAGE_STREAM found = NULL;
    if (FileObject == NULL || FileObject->FsContext == NULL) return NULL;
    StageStreamAcquireSpinLock(&StageListLock, &irql);
    for (link = StageStreams.Flink; link != &StageStreams; link = link->Flink) {
        PSTAGE_STREAM stream = CONTAINING_RECORD(link, STAGE_STREAM, Link);
        if (FileObject->FsContext == &stream->Header) { found = stream; break; }
    }
    StageStreamReleaseSpinLock(&StageListLock, irql);
    /* A stream found through a live file object stays allocated while that file object exists: the worker releases a stream
     * only after its last IRP_MJ_CLOSE (T4). */
    return found;
}

static VOID StageAcquire(PERESOURCE Resource)
{
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(Resource, TRUE);
}

static VOID StageRelease(PERESOURCE Resource)
{
    ExReleaseResourceLite(Resource);
    KeLeaveCriticalRegion();
}

static BOOLEAN StageCacheAcquire(PVOID Context, BOOLEAN Wait)
{
    PSTAGE_STREAM stream = Context;
    if (!ExAcquireRundownProtection(&StageOwnedCallbackBodies)) return FALSE;
    KeEnterCriticalRegion();
    if (!ExAcquireResourceSharedLite(&stream->PagingResource, Wait)) {
        KeLeaveCriticalRegion();
        ExReleaseRundownProtection(&StageOwnedCallbackBodies);
        return FALSE;
    }
    return TRUE;
}

static VOID StageCacheRelease(PVOID Context)
{
    PSTAGE_STREAM stream = Context;
    StageRelease(&stream->PagingResource);
    ExReleaseRundownProtection(&StageOwnedCallbackBodies);
}

static CACHE_MANAGER_CALLBACKS StageCacheCallbacks = {
    StageCacheAcquire, StageCacheRelease, StageCacheAcquire, StageCacheRelease
};

static VOID StageInitializeCache(PSTAGE_STREAM Stream, PFILE_OBJECT FileObject)
{
    CC_FILE_SIZES sizes;
    if (FileObject->PrivateCacheMap != NULL) return;
    sizes.AllocationSize = Stream->Header.AllocationSize;
    sizes.FileSize = Stream->Header.FileSize;
    sizes.ValidDataLength = Stream->Header.ValidDataLength;
    CcInitializeCacheMap(FileObject, &sizes, FALSE, &StageCacheCallbacks, Stream);
}

/* Drain dirty upper pages; their paging writes route to the backing. */
static NTSTATUS StageFlushUpper(PSTAGE_STREAM Stream)
{
    IO_STATUS_BLOCK io = {0};
    if (Stream->Sections.DataSectionObject != NULL) {
        CcFlushCache(&Stream->Sections, NULL, 0, &io);
        if (!NT_SUCCESS(io.Status)) return io.Status;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS StageFlush(PSTAGE_STREAM Stream)
{
    NTSTATUS status = StageFlushUpper(Stream);
    if (!NT_SUCCESS(status)) return status;
    return Stream->ReadOnly ? STATUS_SUCCESS : FltFlushBuffers(Stream->BackingInstance, Stream->BackingObject);
}

static VOID StageFreeStream(PSTAGE_STREAM Stream)
{
#if SAFEUPLOAD_STAGING_PROTOTYPE
    NT_ASSERT(Stream->AllocationWriterLease == NULL); /* Drained at PASSIVE outside namespace locks. */
    SafeUploadStagePublicReleaseWriter(Stream->PublicationWriterLease);
    Stream->PublicationWriterLease = NULL;
#endif
    if (Stream->ReservationLinked) {
        RemoveEntryList(&Stream->ReservationLink);
        Stream->ReservationLinked = FALSE;
    }
    if (Stream->BackingObject != NULL) ObDereferenceObject(Stream->BackingObject);
    if (Stream->BackingHandle != NULL) FltClose(Stream->BackingHandle);
    if (Stream->BackingInstance != NULL) FltObjectDereference(Stream->BackingInstance);
    if (Stream->OriginalInstance != NULL) FltObjectDereference(Stream->OriginalInstance);
    if (Stream->RenameExchange != NULL) ExFreePoolWithTag(Stream->RenameExchange, STAGE_TAG);
    if (Stream->ByteLocks != NULL) FltFreeFileLock(Stream->ByteLocks);
    if (Stream->PagingInitialized) ExDeleteResourceLite(&Stream->PagingResource);
    if (Stream->ResourceInitialized) ExDeleteResourceLite(&Stream->Resource);
    ExFreePoolWithTag(Stream, STAGE_TAG);
}

static NTSTATUS StageResize(PSTAGE_STREAM Stream, PFILE_OBJECT FileObject, LARGE_INTEGER Size);
static VOID StageCloseBacking(PSTAGE_STREAM Stream);
static VOID StageDrainAndSeal(PSTAGE_STREAM Stream);

#if SAFEUPLOAD_STAGING_PROTOTYPE
static BOOLEAN StageV19IdentityEqual(const SAFEUPLOAD_STAGE_IDENTITY_V19 *Left,
    const SAFEUPLOAD_STAGE_IDENTITY_V19 *Right)
{
    return Left->VolumeSerialNumber == Right->VolumeSerialNumber &&
        RtlEqualMemory(&Left->FileId, &Right->FileId, sizeof(FILE_ID_128));
}

/* Resolve the parent as an object with no reparse traversal at its final
 * component. The public name is revalidated after each service RPC, so a
 * junction swap must not silently change which directory the transaction
 * refers to. */
static NTSTATUS StageQueryNoReparseIdentity(PFLT_INSTANCE Instance,
    PUNICODE_STRING Name, BOOLEAN Directory, SAFEUPLOAD_STAGE_IDENTITY_V19 *Identity)
{
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io = {0};
    HANDLE handle = NULL;
    PFILE_OBJECT file = NULL;
    FILE_ATTRIBUTE_TAG_INFORMATION tag;
    FILE_ID_INFORMATION id;
    NTSTATUS status;

    PAGED_CODE();
    RtlZeroMemory(Identity, sizeof(*Identity));
    InitializeObjectAttributes(&attributes, Name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = FltCreateFileEx2(SafeUploadData.Filter, Instance, &handle, &file,
        FILE_READ_ATTRIBUTES, &attributes, &io, NULL, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
        (Directory ? FILE_DIRECTORY_FILE : FILE_NON_DIRECTORY_FILE) | FILE_OPEN_REPARSE_POINT,
        NULL, 0, IO_IGNORE_SHARE_ACCESS_CHECK | IO_STOP_ON_SYMLINK, NULL);
    if (status == STATUS_STOPPED_ON_SYMLINK && io.Information != 0)
        ExFreePool((PVOID)io.Information);
    if (!NT_SUCCESS(status)) return status;

    status = FltQueryInformationFile(Instance, file, &tag, sizeof(tag), FileAttributeTagInformation, NULL);
    if (NT_SUCCESS(status) && FlagOn(tag.FileAttributes, FILE_ATTRIBUTE_REPARSE_POINT))
        status = STATUS_REPARSE_POINT_ENCOUNTERED;
    if (NT_SUCCESS(status)) {
        status = FltQueryInformationFile(Instance, file, &id, sizeof(id), FileIdInformation, NULL);
        if (NT_SUCCESS(status)) {
            Identity->VolumeSerialNumber = id.VolumeSerialNumber;
            Identity->FileId = id.FileId;
        }
    }
    ObDereferenceObject(file);
    FltClose(handle);
    return status;
}

static NTSTATUS StageQueryParentIdentity(PFLT_INSTANCE Instance,
    PUNICODE_STRING Name, SAFEUPLOAD_STAGE_IDENTITY_V19 *Identity)
{
    UNICODE_STRING parent = *Name;
    USHORT index;
    for (index = parent.Length / sizeof(WCHAR); index > 0; --index)
        if (parent.Buffer[index - 1] == L'\\') break;
    if (index == 0) return STATUS_OBJECT_PATH_INVALID;
    parent.Length = (index - 1) * sizeof(WCHAR);
    parent.MaximumLength = parent.Length;
    return StageQueryNoReparseIdentity(Instance, &parent, TRUE, Identity);
}

static NTSTATUS StageQueryBackingIdentity(PSTAGE_STREAM Stream,
    SAFEUPLOAD_STAGE_IDENTITY_V19 *Identity)
{
    FILE_ID_INFORMATION information;
    ULONG returned = 0;
    NTSTATUS status = FltQueryInformationFile(Stream->BackingInstance, Stream->BackingObject,
        &information, sizeof(information), FileIdInformation, &returned);
    if (!NT_SUCCESS(status)) return status;
    if (returned != sizeof(information)) return STATUS_INFO_LENGTH_MISMATCH;
    Identity->VolumeSerialNumber = information.VolumeSerialNumber;
    Identity->FileId = information.FileId;
    return STATUS_SUCCESS;
}
#endif

static NTSTATUS StageOpenBacking(PSTAGE_STREAM Stream, BOOLEAN ReadOnly)
{
    UNICODE_STRING drive = RTL_CONSTANT_STRING(L"\\??\\C:");
    PFLT_VOLUME volume = NULL, sourceVolume = NULL;
    PDEVICE_OBJECT sourceDevice = NULL, backingDevice = NULL;
    FLT_VOLUME_PROPERTIES properties;
    ULONG needed;
    ULONG createOptions = FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_NO_INTERMEDIATE_BUFFERING;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io;
    FILE_STANDARD_INFORMATION standard;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    FILE_ATTRIBUTE_TAG_INFORMATION stageAttributes;
    SAFEUPLOAD_STAGE_IDENTITY_V19 identity;
#endif
    FLT_FILESYSTEM_TYPE fs;
    NTSTATUS status;
    if (Stream->BackingInstance == NULL) {
        status = FltGetVolumeFromName(SafeUploadData.Filter, &drive, &volume);
        if (!NT_SUCCESS(status)) goto Exit;
        status = FltGetVolumeProperties(volume, &properties, sizeof(properties), &needed);
        if (status != STATUS_BUFFER_OVERFLOW && !NT_SUCCESS(status)) goto Exit;
        Stream->SectorSize = properties.SectorSize;
        if (Stream->SectorSize < 512 || Stream->SectorSize > 65536 ||
            (Stream->SectorSize & (Stream->SectorSize - 1)) != 0) {
            status = STATUS_NOT_SUPPORTED; goto Exit;
        }
        status = FltGetVolumeInstanceFromName(SafeUploadData.Filter, volume, NULL, &Stream->BackingInstance);
        if (!NT_SUCCESS(status)) goto Exit;
        status = FltGetFileSystemType(Stream->BackingInstance, &fs);
        if (!NT_SUCCESS(status)) goto Exit;
        if (fs != FLT_FSTYPE_NTFS) { status = STATUS_NOT_SUPPORTED; goto Exit; }
        status = FltGetVolumeFromInstance(Stream->OriginalInstance, &sourceVolume);
        if (!NT_SUCCESS(status)) goto Exit;
        status = FltGetDeviceObject(sourceVolume, &sourceDevice);
        if (!NT_SUCCESS(status)) goto Exit;
        status = FltGetDeviceObject(volume, &backingDevice);
        if (!NT_SUCCESS(status)) goto Exit;
        if (backingDevice->StackSize < sourceDevice->StackSize) {
            status = STATUS_NOT_SUPPORTED; goto Exit;
        }
    }
#if SAFEUPLOAD_STAGING_PROTOTYPE
    createOptions |= FILE_OPEN_REPARSE_POINT;
#endif
    InitializeObjectAttributes(&attributes, &Stream->StageName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = FltCreateFileEx2(SafeUploadData.Filter, Stream->BackingInstance,
        &Stream->BackingHandle, &Stream->BackingObject,
        FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE |
            (ReadOnly ? 0 : FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES),
        &attributes, &io, NULL, FILE_ATTRIBUTE_NORMAL, ReadOnly ? (FILE_SHARE_READ | FILE_SHARE_DELETE) : 0, FILE_OPEN,
        createOptions,
        NULL, 0, IO_STOP_ON_SYMLINK, NULL);
    if (status == STATUS_STOPPED_ON_SYMLINK && io.Information != 0) ExFreePool((PVOID)io.Information);
    if (!NT_SUCCESS(status)) goto Exit;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    RtlZeroMemory(&stageAttributes, sizeof(stageAttributes));
    status = FltQueryInformationFile(Stream->BackingInstance, Stream->BackingObject,
        &stageAttributes, sizeof(stageAttributes), FileAttributeTagInformation, NULL);
    if (!NT_SUCCESS(status)) goto Exit;
    if (FlagOn(stageAttributes.FileAttributes, FILE_ATTRIBUTE_REPARSE_POINT)) {
        status = STATUS_REPARSE_POINT_ENCOUNTERED;
        goto Exit;
    }
    status = StageQueryBackingIdentity(Stream, &identity);
    if (!NT_SUCCESS(status)) goto Exit;
    if (Stream->ExpectedStageIdentityValid &&
        !StageV19IdentityEqual(&identity, &Stream->ExpectedStageIdentity)) {
        status = STATUS_OBJECT_NAME_COLLISION;
        goto Exit;
    }
    if (Stream->StageIdentityValid &&
        !StageV19IdentityEqual(&identity, &Stream->StageIdentity)) {
        status = STATUS_OBJECT_NAME_COLLISION;
        goto Exit;
    }
    Stream->StageIdentity = identity;
    Stream->StageIdentityValid = TRUE;
#endif
    if (!ReadOnly && Stream->BackingObject->SectionObjectPointer != NULL &&
        (Stream->BackingObject->SectionObjectPointer->SharedCacheMap != NULL ||
         Stream->BackingObject->SectionObjectPointer->DataSectionObject != NULL ||
         Stream->BackingObject->SectionObjectPointer->ImageSectionObject != NULL)) {
        /* Do not purge or alter NTFS's cache. The allocator must hand over an
         * uncached backing, and the exclusive writer prevents new readers. */
        status = STATUS_USER_MAPPED_FILE;
        goto Exit;
    }
    if (!ReadOnly) {
        PFLT_FILE_NAME_INFORMATION name = NULL;
        status = FltGetFileNameInformationUnsafe(Stream->BackingObject, Stream->BackingInstance,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY, &name);
        if (!NT_SUCCESS(status)) goto Exit;
        if (name->Name.Length >= sizeof(Stream->StageBuffer)) status = STATUS_NAME_TOO_LONG;
        else {
            Stream->StageName.MaximumLength = sizeof(Stream->StageBuffer);
            RtlCopyUnicodeString(&Stream->StageName, &name->Name);
        }
        FltReleaseFileNameInformation(name);
        if (!NT_SUCCESS(status)) goto Exit;
    }
    status = FltQueryInformationFile(Stream->BackingInstance, Stream->BackingObject,
        &standard, sizeof(standard), FileStandardInformation, NULL);
    if (!NT_SUCCESS(status)) goto Exit;
    if (standard.EndOfFile.QuadPart > STAGE_MAX_BYTES) { status = STATUS_FILE_TOO_LARGE; goto Exit; }
    Stream->Header.FileSize = standard.EndOfFile;
    Stream->Header.ValidDataLength = standard.EndOfFile; /* Allocator copied/flushed every byte. */
    Stream->Header.AllocationSize = standard.AllocationSize;
Exit:
    if (!NT_SUCCESS(status)) StageCloseBacking(Stream);
    if (sourceDevice != NULL) ObDereferenceObject(sourceDevice);
    if (backingDevice != NULL) ObDereferenceObject(backingDevice);
    if (sourceVolume != NULL) FltObjectDereference(sourceVolume);
    if (volume != NULL) FltObjectDereference(volume);
    return status;
}

static VOID StageCloseBacking(PSTAGE_STREAM Stream)
{
    if (Stream->BackingObject != NULL) ObDereferenceObject(Stream->BackingObject);
    if (Stream->BackingHandle != NULL) FltClose(Stream->BackingHandle);
    Stream->BackingObject = NULL;
    Stream->BackingHandle = NULL;
}

static PSTAGE_VIEW StageFindView(PEPROCESS Owner, PUNICODE_STRING Name)
{
    PLIST_ENTRY link;
    for (link = StageViews.Flink; link != &StageViews; link = link->Flink) {
        PSTAGE_VIEW view = CONTAINING_RECORD(link, STAGE_VIEW, Link);
        if (!view->Detached && view->Owner == Owner && RtlEqualUnicodeString(&view->Name, Name, TRUE)) return view;
    }
    return NULL;
}

#if SAFEUPLOAD_STAGING_PROTOTYPE
/* Caller owns NamespaceResource. A private-delete reservation is a
 * cross-owner barrier: until last private handle cleanup,
 * no other private view may race the same public name. */
static PSTAGE_STREAM StageFindPrivateDeleteReservation(PUNICODE_STRING Name)
{
    PLIST_ENTRY link;
    for (link = StageStreams.Flink; link != &StageStreams; link = link->Flink) {
        PSTAGE_STREAM stream = CONTAINING_RECORD(link, STAGE_STREAM, Link);
        if (stream->PrivateDeleteReserved && RtlEqualUnicodeString(&stream->Name, Name, TRUE)) return stream;
    }
    for (link = StageAllocationReservations.Flink; link != &StageAllocationReservations; link = link->Flink) {
        PSTAGE_STREAM stream = CONTAINING_RECORD(link, STAGE_STREAM, ReservationLink);
        if (stream->PrivateDeleteReserved && RtlEqualUnicodeString(&stream->Name, Name, TRUE)) return stream;
    }
    return NULL;
}

/* PASSIVE attach worker, NamespaceResource held. A name only selects the
 * reservation; the pinned process/view and recorded allocation/op15 tuple
 * authorize this one resume. No service send or callback wait under this lock. */
static BOOLEAN StageAttachOwnerCanResume(PSTAGE_STREAM Stream,
    PSTAGE_ATTACH_TRANSACTION Transaction, PEPROCESS Owner)
{
    PSTAGE_VIEW view = Stream->View;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (Transaction == NULL || Owner != Transaction->RequestorProcess ||
        view == NULL || view->Detached || view->Current != Stream ||
        view->Owner != Owner || view->OwnerProcessId != Transaction->RequestorProcessId ||
        view->Generation != Transaction->ExpectedGeneration || Stream->OwnerExited ||
        Stream->OriginalInstance != Transaction->InstanceIdentity ||
        !Stream->AttachCompletionPending || Stream->AttachLifecycleInFlight ||
        Stream->AttachCompletionFence || Stream->AttachTerminalPending || Stream->AttachRetirePending ||
        Stream->DiscardOnClose || Stream->Discarded || Stream->Sealed ||
        InterlockedCompareExchange(&Stream->FileObjects, 0, 0) != 0 ||
        !Stream->AllocationReceiptPending || !Stream->AllocationTupleKnown ||
        Stream->AllocationRpcInFlight || Stream->AllocationRecoveryPending || Stream->AllocationRecoveryInFlight ||
        !Stream->HasTransferId || !Stream->StageIdentityValid || !Stream->ExpectedStageIdentityValid ||
        Stream->DestinationGeneration == 0 ||
        Stream->AllocationRecoveryProcessId != Transaction->RequestorProcessId ||
        !RtlEqualMemory(&Stream->TransferId, &Stream->AllocationIntent.AllocationReservationId, sizeof(GUID)) ||
        !StageV19IdentityEqual(&Stream->StageIdentity, &Stream->ExpectedStageIdentity) ||
        !RtlEqualMemory(&Stream->DriverInstanceId, &Transaction->DriverInstanceId, sizeof(GUID)) ||
        !RtlEqualMemory(&Stream->DriverInstanceId, &StageDriverInstanceId, sizeof(GUID)) ||
        Stream->AllocationParentDirectoryIdentity.VolumeSerialNumber != view->ParentIdentity.VolumeSerialNumber ||
        !RtlEqualMemory(&Stream->AllocationParentDirectoryIdentity.FileId,
            &view->ParentIdentity.FileId, sizeof(FILE_ID_128))) return FALSE;
    if (!Stream->AttachCompletionMayExist || Stream->AttachCompletionRequest.RequestId == 0) return FALSE;
    if (!SafeUploadStageAttachmentRequestV20Matches(&Stream->AttachCompletionRequest,
            view->OwnerProcessId, &Stream->Name, Transaction->VolumeKind,
            SAFEUPLOAD_OPERATION_STAGE_ATTACH_COMPLETION_PERMITTED, &Stream->TransferId,
            Stream->DestinationGeneration, &Stream->StageIdentity, &Stream->DriverInstanceId,
            &Stream->AllocationParentDirectoryIdentity)) return FALSE;
    return TRUE;
}

/* Caller owns NamespaceResource. The transfer ID itself is a stable,
 * globally unique reservation token scoped to this never-reused version. */
static NTSTATUS StageReservePrivateDelete(PSTAGE_STREAM Stream)
{
    static const GUID EmptyId = {0};
    PLIST_ENTRY link;
    if (Stream->PrivateDeleteReserved) return STATUS_SUCCESS;
    if (!Stream->HasTransferId || RtlEqualMemory(&Stream->TransferId, &EmptyId, sizeof(GUID)))
        return STATUS_INVALID_PARAMETER;
    for (link = StageStreams.Flink; link != &StageStreams; link = link->Flink) {
        PSTAGE_STREAM other = CONTAINING_RECORD(link, STAGE_STREAM, Link);
        if (other != Stream && other->PrivateDeleteReserved &&
            RtlEqualUnicodeString(&other->Name, &Stream->Name, TRUE)) return STATUS_DELETE_PENDING;
    }
    for (link = StageAllocationReservations.Flink; link != &StageAllocationReservations; link = link->Flink) {
        PSTAGE_STREAM other = CONTAINING_RECORD(link, STAGE_STREAM, ReservationLink);
        if (other != Stream && RtlEqualUnicodeString(&other->Name, &Stream->Name, TRUE))
            return STATUS_DELETE_PENDING;
    }
    for (link = StageViews.Flink; link != &StageViews; link = link->Flink) {
        PSTAGE_VIEW otherView = CONTAINING_RECORD(link, STAGE_VIEW, Link);
        if (otherView != Stream->View && !otherView->Detached &&
            RtlEqualUnicodeString(&otherView->Name, &Stream->Name, TRUE))
            return STATUS_SHARING_VIOLATION;
    }
    Stream->DeleteReservationId = Stream->TransferId;
    Stream->PrivateDeleteReserved = TRUE;
    return STATUS_SUCCESS;
}

/* Caller owns NamespaceResource. */
static VOID StageClearPrivateDelete(PSTAGE_STREAM Stream)
{
    if (Stream->AllocationRpcInFlight || Stream->AllocationReceiptPending ||
        Stream->DiscardRpcInFlight) return;
    Stream->PrivateDeleteReserved = FALSE;
    RtlZeroMemory(&Stream->DeleteReservationId, sizeof(Stream->DeleteReservationId));
}

/* Caller owns NamespaceResource. Reserve the logical name before an unlocked
 * allocation RPC. Other owners see DELETE_PENDING until the exact allocation
 * is attached or its durable unattached receipt is ACKed. */
static NTSTATUS StageReserveAllocationName(PSTAGE_STREAM Stream)
{
    PLIST_ENTRY link;
    if (Stream->ReservationLinked || Stream->PrivateDeleteReserved) return STATUS_INVALID_PARAMETER;
    for (link = StageStreams.Flink; link != &StageStreams; link = link->Flink) {
        PSTAGE_STREAM other = CONTAINING_RECORD(link, STAGE_STREAM, Link);
        if (other->PrivateDeleteReserved &&
            RtlEqualUnicodeString(&other->Name, &Stream->Name, TRUE))
            return STATUS_DELETE_PENDING;
    }
    for (link = StageAllocationReservations.Flink; link != &StageAllocationReservations; link = link->Flink) {
        PSTAGE_STREAM other = CONTAINING_RECORD(link, STAGE_STREAM, ReservationLink);
        if (other != Stream && RtlEqualUnicodeString(&other->Name, &Stream->Name, TRUE))
            return STATUS_DELETE_PENDING;
    }
    for (link = StageViews.Flink; link != &StageViews; link = link->Flink) {
        PSTAGE_VIEW other = CONTAINING_RECORD(link, STAGE_VIEW, Link);
        if (other != Stream->View && !other->Detached &&
            RtlEqualUnicodeString(&other->Name, &Stream->Name, TRUE))
            return STATUS_SHARING_VIOLATION;
    }
    Stream->PrivateDeleteReserved = TRUE;
    Stream->AllocationRpcInFlight = TRUE;
    InsertTailList(&StageAllocationReservations, &Stream->ReservationLink);
    Stream->ReservationLinked = TRUE;
    return STATUS_SUCCESS;
}

static VOID StageRemoveAllocationNameReservation(PSTAGE_STREAM Stream)
{
    if (!Stream->ReservationLinked) return;
    RemoveEntryList(&Stream->ReservationLink);
    InitializeListHead(&Stream->ReservationLink);
    Stream->ReservationLinked = FALSE;
}

/* Build an unlisted version shell before dropping NamespaceResource for a
 * service exchange. The caller owns the reserved slot and either attaches
 * this object or frees it after the exchange. */
static NTSTATUS StageCreateStreamShell(PFLT_INSTANCE OriginalInstance,
    USHORT VolumeLength, PUNICODE_STRING Name, PSTAGE_VIEW View,
    _Outptr_ PSTAGE_STREAM *OutStream)
{
    PSTAGE_STREAM stream;
    NTSTATUS status;
    *OutStream = NULL;
    stream = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*stream), STAGE_TAG);
    if (stream == NULL) return STATUS_INSUFFICIENT_RESOURCES;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    InitializeListHead(&stream->RpcLink);
#endif
    InitializeListHead(&stream->ReservationLink);
#if SAFEUPLOAD_STAGING_PROTOTYPE
    InitializeListHead(&stream->RecoveryLink);
#endif
    stream->View = View;
    stream->VolumeLength = VolumeLength;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    stream->DriverInstanceId = StageDriverInstanceId;
#endif
    stream->Name.Buffer = stream->NameBuffer;
    stream->Name.MaximumLength = sizeof(stream->NameBuffer);
    if (Name->Length > sizeof(stream->NameBuffer)) { status = STATUS_NAME_TOO_LONG; goto Exit; }
    RtlCopyUnicodeString(&stream->Name, Name);
    stream->ByteLocks = FltAllocateFileLock(NULL, NULL);
    if (stream->ByteLocks == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    status = ExInitializeResourceLite(&stream->Resource);
    if (!NT_SUCCESS(status)) goto Exit;
    stream->ResourceInitialized = TRUE;
    status = ExInitializeResourceLite(&stream->PagingResource);
    if (!NT_SUCCESS(status)) goto Exit;
    stream->PagingInitialized = TRUE;
    ExInitializeRundownProtection(&stream->PagingRundown);
    ExInitializeFastMutex(&stream->HeaderMutex);
    FsRtlSetupAdvancedHeader(&stream->Header, &stream->HeaderMutex);
    stream->Header.NodeTypeCode = 0x5349;
    stream->Header.NodeByteSize = sizeof(*stream);
    stream->Header.Resource = &stream->Resource;
    stream->Header.PagingIoResource = &stream->PagingResource;
    stream->Header.IsFastIoPossible = FastIoIsNotPossible;
    status = FltObjectReference(OriginalInstance);
    if (!NT_SUCCESS(status)) goto Exit;
    stream->OriginalInstance = OriginalInstance;
    *OutStream = stream;
    return STATUS_SUCCESS;
Exit:
    StageFreeStream(stream);
    return status;
}

static NTSTATUS StageSetStreamStageName(PSTAGE_STREAM Stream,
    PCWCH Basename, USHORT BasenameLength)
{
    WCHAR name[SAFEUPLOAD_MAX_STAGE_NAME_CHARS];
    GUID parsedId;
    BOOLEAN expectedIdValid = Stream->HasTransferId;
    USHORT chars;
    NTSTATUS status;
    if (BasenameLength < 32 * sizeof(WCHAR) ||
        BasenameLength >= SAFEUPLOAD_MAX_STAGE_NAME_CHARS * sizeof(WCHAR) ||
        (BasenameLength & 1)) return STATUS_INVALID_PARAMETER;
    chars = (USHORT)(BasenameLength / sizeof(WCHAR));
    RtlCopyMemory(name, Basename, BasenameLength);
    name[chars] = L'\0';
    status = RtlStringCchPrintfW(Stream->StageBuffer, SAFEUPLOAD_MAX_PATH_CHARS,
        L"\\??\\C:\\ProgramData\\SafeUpload\\staging\\%ws", name);
    if (!NT_SUCCESS(status)) return status;
    if (!StageParseTransferId(Basename, BasenameLength / sizeof(WCHAR), &parsedId))
        return STATUS_INVALID_PARAMETER;
    if (expectedIdValid && !RtlEqualMemory(&Stream->TransferId, &parsedId, sizeof(GUID)))
        return STATUS_OBJECT_NAME_COLLISION;
    RtlInitUnicodeString(&Stream->StageName, Stream->StageBuffer);
    Stream->TransferId = parsedId;
    Stream->HasTransferId = TRUE;
    return STATUS_SUCCESS;
}

/* Scheduling hint only. An unrelated arm may be about to expire; each failed
 * allocation still owes its own complete backoff interval from this attempt. */
static ULONGLONG StageAllocationRetryDeadline(VOID)
{
    ULONG delay = StageRetryMs < STAGE_RETRY_FIRST_MS ? STAGE_RETRY_FIRST_MS : StageRetryMs;
    ULONGLONG deadline = KeQueryInterruptTime() + (ULONGLONG)delay * 10000ULL;
    return StageRetryDueTime > deadline ? StageRetryDueTime : deadline;
}

/* Caller owns NamespaceResource. An allocation that may have reached the
 * service but did not attach to an upper file object remains a listed exact
 * receipt. The worker replays the stable request when its tuple is unknown,
 * then issues kind-5 identity-qualified cleanup. */
static VOID StageRetainAllocationReceipt(PSTAGE_STREAM Stream, PSTAGE_VIEW View,
    BOOLEAN NewView, BOOLEAN ReservedSlot, PSTAGE_STREAM Parent, NTSTATUS LastStatus)
{
    KIRQL irql;
    Stream->AllocationRpcInFlight = FALSE;
    Stream->AllocationReceiptPending = TRUE;
    Stream->AttachCompletionPending = FALSE; /* no upper-file-object attach committed */
    Stream->AllocationRecoveryPending = !Stream->AllocationTupleKnown;
    Stream->PrivateDeleteReserved = TRUE;
    Stream->DeleteReservationId = Stream->TransferId;
    Stream->DiscardOnClose = TRUE;
    Stream->DiscardDisposition = TRUE;
    Stream->DiscardRpcKind = SAFEUPLOAD_STAGE_DISCARD_KIND_UNATTACHED_ALLOCATION;
    Stream->DiscardRpcPending = Stream->AllocationTupleKnown;
    Stream->Wait = StageWaitFor(LastStatus);
    Stream->AllocationRecoveryWait = Stream->Wait;
    Stream->AllocationRecoveryRetryAfter = 0;
    StageCloseBacking(Stream); /* the service must be able to delete this exact private file */
    Stream->View = View;
    if (Parent != NULL && Stream->AllocationReceiptParent == NULL) {
        Stream->AllocationReceiptParent = Parent;
        ++Parent->AllocationReceiptReferences;
        /* The receipt stream now owns the same-name barrier. Keeping it on the
         * predecessor would let a later CREATE replay a child whose attach
         * failed while this exact cleanup is pending. */
        StageClearPrivateDelete(Parent);
    }
    StageStreamAcquireSpinLock(&StageListLock, &irql);
    if (!Stream->Listed) {
        InsertTailList(&StageStreams, &Stream->Link);
        Stream->Listed = TRUE;
        ++StageStreamCount;
        ++View->Streams;
    }
    StageStreamReleaseSpinLock(&StageListLock, irql);
    if (NewView) {
        View->Generation = ++StageNamespaceSequence;
        View->Current = Stream;
        View->Detached = TRUE; /* failed CREATE has no visible private view */
        InsertTailList(&StageViews, &View->Link);
        ++StageViewCount;
    }
    if (ReservedSlot && StageReservedStreamCount != 0) --StageReservedStreamCount;
    StageUpdateRetryTimer();
    if (Stream->AllocationRecoveryPending && Stream->AllocationRecoveryWait == STAGE_WAIT_EXCHANGE)
        Stream->AllocationRecoveryRetryAfter = StageAllocationRetryDeadline();
    if (Stream->AllocationTupleKnown) StageQueueStream(Stream, &StageCounters.WakeInline);
}
#endif

/* Caller holds NamespaceResource. Only the private logical ID is routed here;
 * physical aliases need separate object admission and mutation fencing. */
static PSTAGE_VIEW StageFindId(PEPROCESS Owner, PFLT_INSTANCE Instance, PUNICODE_STRING Id)
{
    PLIST_ENTRY link;
    for (link = StageViews.Flink; link != &StageViews; link = link->Flink) {
        PSTAGE_VIEW view = CONTAINING_RECORD(link, STAGE_VIEW, Link);
        if (view->Detached || view->Owner != Owner || view->Current->OriginalInstance != Instance) continue;
        if (Id->Length == sizeof(FILE_ID_128) &&
            RtlEqualMemory(Id->Buffer, &view->Identity.FileId, sizeof(FILE_ID_128))) return view;
    }
    return NULL;
}

static NTSTATUS StageSetIdentity(PSTAGE_VIEW View, PCWSTR Basename)
{
    ULONG index;
    PLIST_ENTRY link;
    for (index = 0; index < sizeof(View->Identity.FileId.Identifier); ++index) {
        ULONG nibble, byte = 0;
        for (nibble = 0; nibble < 2; ++nibble) {
            WCHAR ch = Basename[index * 2 + nibble];
            ULONG value = ch >= L'0' && ch <= L'9' ? ch - L'0' :
                ch >= L'a' && ch <= L'f' ? ch - L'a' + 10 :
                ch >= L'A' && ch <= L'F' ? ch - L'A' + 10 : 16;
            if (value > 15) return STATUS_INVALID_PARAMETER;
            byte = byte * 16 + value;
        }
        View->Identity.FileId.Identifier[index] = (UCHAR)byte;
    }
    /* Distinguish private IDs from NTFS's physical 64-bit reference numbers. */
    View->Identity.FileId.Identifier[15] |= 0x80;
    View->Identity.VolumeSerialNumber = View->ParentIdentity.VolumeSerialNumber;
    for (link = StageViews.Flink; link != &StageViews; link = link->Flink) {
        PSTAGE_VIEW other = CONTAINING_RECORD(link, STAGE_VIEW, Link);
        if (other->Identity.VolumeSerialNumber == View->Identity.VolumeSerialNumber &&
            RtlEqualMemory(&other->Identity.FileId, &View->Identity.FileId, sizeof(FILE_ID_128)))
            return STATUS_OBJECT_NAME_COLLISION;
    }
    return STATUS_SUCCESS;
}

/* Caller holds NamespaceResource. */
static PSTAGE_TOMBSTONE StageHiddenTombstone(PEPROCESS Owner, PUNICODE_STRING Name)
{
    PLIST_ENTRY link;
    for (link = StageTombstones.Flink; link != &StageTombstones; link = link->Flink) {
        PSTAGE_TOMBSTONE tombstone = CONTAINING_RECORD(link, STAGE_TOMBSTONE, Link);
        if (tombstone->Owner == Owner && RtlEqualUnicodeString(&tombstone->Name, Name, TRUE)) return tombstone;
    }
    return NULL;
}

static BOOLEAN StageHiddenName(PEPROCESS Owner, PUNICODE_STRING Name)
{
    return StageHiddenTombstone(Owner, Name) != NULL;
}

/* Caller holds NamespaceResource. */
static VOID StageFreeTombstone(PSTAGE_TOMBSTONE Tombstone)
{
    RemoveEntryList(&Tombstone->Link);
    StageTombstoneCount--;
    ObDereferenceObject(Tombstone->Owner);
    ExFreePoolWithTag(Tombstone, STAGE_TAG);
}

/* A view takes Name for Owner, so the name is no longer logically absent. Before T4 an attached view shadowed the tombstone
 * forever; a view can now be detached, and a stale tombstone would then hide the owner's own published file. */
static VOID StageDropTombstone(PEPROCESS Owner, PUNICODE_STRING Name)
{
    PSTAGE_TOMBSTONE tombstone = StageHiddenTombstone(Owner, Name);
    if (tombstone != NULL) StageFreeTombstone(tombstone);
}

/* The stage basename starts with the service's transfer GUID in "N" form (32 hex digits). */
static PWCH StageTransferDigits(PSTAGE_STREAM Stream)
{
    USHORT basename = Stream->StageName.Length / sizeof(WCHAR);
    while (basename > 0 && Stream->StageName.Buffer[basename - 1] != L'\\') --basename;
    return Stream->StageName.Buffer + basename;
}

static BOOLEAN StageParseTransferId(PCWCH Digits, USHORT Chars, GUID *Id)
{
    UCHAR bytes[16];
    USHORT index;
    if (Chars < 32) return FALSE;
    for (index = 0; index < 32; ++index) {
        WCHAR c = Digits[index];
        UCHAR nibble;
        if (c >= L'0' && c <= L'9') nibble = (UCHAR)(c - L'0');
        else if (c >= L'a' && c <= L'f') nibble = (UCHAR)(c - L'a' + 10);
        else if (c >= L'A' && c <= L'F') nibble = (UCHAR)(c - L'A' + 10);
        else return FALSE;
        if ((index & 1) == 0) bytes[index / 2] = (UCHAR)(nibble << 4);
        else bytes[index / 2] |= nibble;
    }
    /* "N" form prints Data1, Data2 and Data3 as big-endian numbers, then Data4 byte by byte. */
    Id->Data1 = ((ULONG)bytes[0] << 24) | ((ULONG)bytes[1] << 16) | ((ULONG)bytes[2] << 8) | bytes[3];
    Id->Data2 = (USHORT)(((USHORT)bytes[4] << 8) | bytes[5]);
    Id->Data3 = (USHORT)(((USHORT)bytes[6] << 8) | bytes[7]);
    RtlCopyMemory(Id->Data4, bytes + 8, 8);
    return TRUE;
}

#if SAFEUPLOAD_STAGING_PROTOTYPE
/* Fast same-name CREATE_ALWAYS path. This must run before StageSettleCurrent:
 * it bypasses the old V2 discard RPC/ACK and asks the service to persist V2
 * DiscardPending plus a deterministic V3 Allocated child. Caller owns
 * NamespaceResource on entry and return. */

#endif

static VOID StageFreeView(PSTAGE_VIEW View)
{
    if (View->Owner != NULL) ObDereferenceObject(View->Owner);
    SafeUploadStageFreeSecurity(View->Security, View->AssignedSecurity);
    ExFreePoolWithTag(View, STAGE_TAG);
}

#if SAFEUPLOAD_STAGING_PROTOTYPE
/* Pure local tuple check; callers own the stream/namespace lifetime. */
static BOOLEAN StageBoundSeedReady(_In_ PSTAGE_STREAM Stream)
{
    const SAFEUPLOAD_STAGE_SEED_COMPLETION *seed = &Stream->SeedCompletion;
    return !Stream->BoundAllocation || (Stream->BoundSeedDurable && seed->Complete &&
        seed->Generation == Stream->DestinationGeneration &&
        RtlEqualMemory(&seed->TransferId, &Stream->TransferId, sizeof(GUID)) &&
        RtlEqualMemory(&seed->DriverInstanceId, &StageDriverInstanceId, sizeof(GUID)) &&
        StageV19IdentityEqual(&seed->StageIdentity, &Stream->StageIdentity));
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageAllocateBound(_Inout_ PSTAGE_ATTACH_TRANSACTION Transaction,
    _In_opt_ PSTAGE_STREAM Previous, _In_opt_ PCUNICODE_STRING Tombstone,
    _Out_writes_(SAFEUPLOAD_MAX_STAGE_NAME_CHARS) PWCH Basename, _Out_ PUSHORT BasenameLength,
    _Out_ PUINT64 Generation, _Out_ PSAFEUPLOAD_STAGE_IDENTITY_V19 Identity,
    _Out_ PSAFEUPLOAD_STAGE_ALLOCATE_V19 Intent, _Out_ PSAFEUPLOAD_REQUEST Request,
    _Out_ PBOOLEAN MayExist);
#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, StageAllocateBound)
#endif
_Use_decl_annotations_
static NTSTATUS StageAllocateBound(PSTAGE_ATTACH_TRANSACTION Transaction,
    PSTAGE_STREAM Previous, PCUNICODE_STRING Tombstone, PWCH Basename, PUSHORT BasenameLength,
    PUINT64 Generation, PSAFEUPLOAD_STAGE_IDENTITY_V19 Identity,
    PSAFEUPLOAD_STAGE_ALLOCATE_V19 Intent, PSAFEUPLOAD_REQUEST Request, PBOOLEAN MayExist)
{
    SAFEUPLOAD_STAGE_PUBLIC_BINDING captured;
    SAFEUPLOAD_STAGE_ALLOCATE_V23 binding = {0};
    NTSTATUS status;
    PAGED_CODE();
    RtlZeroMemory(Basename, SAFEUPLOAD_MAX_STAGE_NAME_CHARS * sizeof(WCHAR));
    *BasenameLength = 0; *Generation = 0; *MayExist = FALSE;
    RtlZeroMemory(Identity, sizeof(*Identity)); RtlZeroMemory(Intent, sizeof(*Intent));
    RtlZeroMemory(Request, sizeof(*Request));
    if (!SafeUploadStageProtocolBoundAllocationReady() || Transaction->WriterLease == NULL)
        return STATUS_DEVICE_NOT_READY;
    SafeUploadStagePublicGetWriterBinding(Transaction->WriterLease, &captured);
    binding.Version = SAFEUPLOAD_STAGE_BOUND_ALLOCATION_VERSION;
    binding.StructSize = sizeof(binding);
    status = ExUuidCreate(&binding.AllocationReservationId);
    if (!NT_SUCCESS(status)) return status;
    binding.Disposition = Transaction->CreateInput.Options >> 24;
    if (Previous != NULL) {
        /* A legacy predecessor has no immutable source lineage/metadata. */
        if (!Previous->BoundAllocation || !StageBoundSeedReady(Previous)) return STATUS_DEVICE_NOT_READY;
        binding.ReferenceKind = SAFEUPLOAD_STAGE_ALLOC_REFERENCE_FOLLOWUP;
        binding.ParentTransferId = Previous->TransferId;
    } else if (Tombstone != NULL) {
        binding.ReferenceKind = SAFEUPLOAD_STAGE_ALLOC_REFERENCE_TOMBSTONE;
        if (!StageParseTransferId(Tombstone->Buffer, Tombstone->Length / sizeof(WCHAR), &binding.ParentTransferId))
            return STATUS_INVALID_PARAMETER;
    }
    binding.PublicTargetId = captured.PublicIdentity.FileId;
    binding.MountManagerVolumeId = captured.MountManagerVolumeId;
    binding.VolumeRootId = captured.VolumeRootIdentity.FileId;
    binding.ParentIdentity.VolumeSerialNumber = captured.ParentIdentity.VolumeSerialNumber;
    binding.ParentIdentity.FileId = captured.ParentIdentity.FileId;
    binding.ParentCaseSensitive = captured.ParentCaseSensitive ? 1 : 0;
    binding.CanonicalLeafBytes = captured.CanonicalLeafBytes;
    /* V23 itself requires complete, current increment-3 metadata and the
     * increment-2 security check before sending. A refused bound request never
     * falls back to V19. V18/V23/V26/V27 layouts and interfaces stay unchanged. */
    return SafeUploadStageAllocateBoundV23(Transaction->CallbackData, Transaction->WriterLease,
        &Transaction->NameInfo->Name, &binding, &StageDriverInstanceId, Basename, BasenameLength,
        Generation, Identity, Intent, Request, MayExist);
}
#endif

/* NamespaceResource serializes CREATE, rotation, retarget and retirement.
 * An upper FILE_OBJECT references a version, never a mutable current pointer. */
static NTSTATUS StageCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS Objects,
    PFLT_FILE_NAME_INFORMATION Name, SAFEUPLOAD_VOLUME_KIND Kind, BOOLEAN Writer,
    LONG64 ExpectedGeneration, BOOLEAN ById, BOOLEAN PrivateNamespace,
    BOOLEAN AllowAttachResume, PVOID AttachContext, PBOOLEAN Handled)
{
    PSTAGE_VIEW view = NULL;
    PSTAGE_TOMBSTONE hidden = NULL;
    PSTAGE_STREAM previous = NULL;
    PSTAGE_STREAM stream = NULL;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    PSTAGE_STREAM privateDelete = NULL;
#endif
    PSTAGE_HANDLE handle = NULL;
    PFILE_OBJECT file = Data->Iopb->TargetFileObject;
    ACCESS_MASK desired = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    ACCESS_MASK granted = 0;
    ULONG disposition = Data->Iopb->Parameters.Create.Options >> 24;
    ULONG information = FILE_OPENED;
    PEPROCESS owner = FltGetRequestorProcess(Data);
    BOOLEAN newView = FALSE, newStream = FALSE, exists = FALSE;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    PSTAGE_ATTACH_TRANSACTION transaction = (PSTAGE_ATTACH_TRANSACTION)AttachContext;
    SAFEUPLOAD_STAGE_WRITER_REFUSAL writerReason = StageWriterNoRefusal;
    BOOLEAN bound = transaction != NULL && transaction->WriterLease != NULL;
    BOOLEAN reservedForCreate = FALSE;
    BOOLEAN reservedStreamSlot = FALSE;
    BOOLEAN allocationMayExist = FALSE;
    BOOLEAN allocationReplyKnown = FALSE;
    PSAFEUPLOAD_REQUEST allocationRequest = NULL;
    UINT64 allocationRequestId = 0;
    BOOLEAN previousPinned = FALSE;
    LONG64 namespaceSequence = 0;
    BOOLEAN viewWasDetached = FALSE;
    UINT64 allocatedGeneration = 0;
    SAFEUPLOAD_STAGE_IDENTITY_V19 allocatedIdentity;
    SAFEUPLOAD_STAGE_ALLOCATE_V19 allocationIntent;
    SAFEUPLOAD_STAGE_IDENTITY_V19 previousIdentity = {0};
    UINT64 previousGeneration = 0;
    GUID previousTransferId;
    LONG64 allocationViewGeneration = 0;
    LONG allocationServiceGeneration = 0;
    WCHAR tombstoneTransferBuffer[32];
    UNICODE_STRING tombstoneTransferName;
    BOOLEAN tombstoneSnapshotValid = FALSE;
#endif
    FLT_FILESYSTEM_TYPE fs;
    WCHAR basename[SAFEUPLOAD_MAX_STAGE_NAME_CHARS];
    USHORT basenameLength;
    KIRQL irql;
    NTSTATUS status = STATUS_SUCCESS;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    UINT32 sharingGate = 0;
#endif
    *Handled = TRUE;
#if !SAFEUPLOAD_STAGING_PROTOTYPE
    UNREFERENCED_PARAMETER(AllowAttachResume);
    UNREFERENCED_PARAMETER(AttachContext);
#endif
    if (owner == NULL) return STATUS_ACCESS_DENIED;
    StageAcquire(&StageNamespaceResource);
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (InterlockedCompareExchange(&StageDirectoryMutationActive, 0, 0) != 0) {
        sharingGate = 1;
        status = STATUS_SHARING_VIOLATION; goto Exit;
    }
    namespaceSequence = StageDirectorySequence;
#endif
    if (StageStopping
#if SAFEUPLOAD_STAGING_PROTOTYPE
        || InterlockedCompareExchange(&StageUnloadAdmissionClosed, 0, 0) != 0
#endif
        ) { status = STATUS_DEVICE_NOT_READY; goto Exit; }
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (InterlockedCompareExchange(&StageDirectoryMutationActive, 0, 0) != 0 ||
        (transaction != NULL && transaction->DirectorySequence !=
            InterlockedCompareExchange64(&StageDirectorySequence, 0, 0))) {
        sharingGate = 2;
        status = STATUS_SHARING_VIOLATION;
        goto Exit;
    }
    if (InterlockedCompareExchange(&StageReconcileNeeded, 0, 0) ||
        !SafeUploadStageProtocolIsReady()) {
        status = STATUS_DEVICE_NOT_READY;
        goto Exit;
    }
#endif
#if SAFEUPLOAD_STAGING_PROTOTYPE
    privateDelete = StageFindPrivateDeleteReservation(&Name->Name);
    if (privateDelete != NULL && (!AllowAttachResume ||
        !StageAttachOwnerCanResume(privateDelete, transaction, owner))) {
        /* Before last cleanup keep the existing private delete-pending
         * admission contract. Afterwards cleanup detaches the old version,
         * and CREATE uses the ordinary allocator's next generation. Only the
         * exact allocation owner's attach worker may resume an unresolved
         * attachment. Unattached cleanup reports a retryable sharing conflict;
         * actual delete and completion-permission ambiguity stay held. */
        status = STATUS_DELETE_PENDING;
        if (privateDelete->AllocationReceiptPending &&
            !privateDelete->AttachCompletionMayExist && !privateDelete->AttachCompletionKnown)
            { sharingGate = 3; status = STATUS_SHARING_VIOLATION; }
        goto Exit;
    }
#endif
    for (;;) {
        view = StageFindView(owner, &Name->Name);
        /* T4: what the worker would do at its next event for this version is done here first; a version the service disposed
         * of, or whose stage it deleted, leaves the namespace once nothing holds it, and the name resolves without it. */
        if (view == NULL || !StageSettleCurrent(view)) break;
    }
    /* A name snapshot for a file-ID open must still name that same live view.
     * Rename/replacement between lookup and admission must never create a new
     * view or return the newly occupying file. The generation identifies the
     * view: a detached, unreferenced view is released (T4), so its address can
     * be reused. */
    if (ById && (view == NULL || view->Generation != ExpectedGeneration)) {
        status = STATUS_SHARING_VIOLATION;
#if SAFEUPLOAD_STAGING_PROTOTYPE
        sharingGate = 4;
#endif
        goto Exit;
    }
    if (view == NULL) hidden = StageHiddenTombstone(owner, &Name->Name);
    /* A name open was admitted against a snapshot of the owner's private
     * namespace. If what it saw changed since (a detach after the service's
     * disposal, a rename, a new view), the admission gates run again. */
    if (!ById && ((view != NULL ? view->Generation : 0) != ExpectedGeneration ||
        (view != NULL || hidden != NULL) != PrivateNamespace)) {
        status = STAGE_STATUS_READMIT; goto Exit;
    }
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (view != NULL && view->Current->PrivateCancellationBusy) {
        status = STATUS_DELETE_PENDING; goto Exit;
    }
#endif
    if (view != NULL && view->Current->OriginalInstance != Objects->Instance) {
#if SAFEUPLOAD_STAGING_PROTOTYPE
        sharingGate = 5;
#endif
        status = STATUS_SHARING_VIOLATION; goto Exit;
    }
    if (hidden != NULL) {
        if (!Writer || disposition == FILE_OPEN || disposition == FILE_OVERWRITE) {
            status = STATUS_OBJECT_NAME_NOT_FOUND; goto Exit;
        }
        /* Logical absence is distinct from an occupied public name. The
         * service must consume this writer's CURRENT committed tombstone. */
    }
    if (view == NULL && !Writer) {
        if (PrivateNamespace) status = STATUS_OBJECT_NAME_NOT_FOUND;
        else *Handled = FALSE;
        goto Exit;
    }
    if (Name->Name.Length > sizeof(stream->NameBuffer) || Name->Stream.Length != 0 ||
        (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_OPEN_BY_FILE_ID) && !ById) ||
        FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE | FILE_NO_INTERMEDIATE_BUFFERING) ||
        file->FsContext != NULL || file->FsContext2 != NULL) {
        if (Name->Stream.Length != 0)
            SafeUploadDenyDetail(Data, SAFEUPLOAD_DENY_REASON_STREAM_UNSUPPORTED, STATUS_NOT_SUPPORTED, &Name->Name);
        status = STATUS_NOT_SUPPORTED; goto Exit;
    }
    if (Writer && (Data->Iopb->Parameters.Create.EaLength != 0 ||
        FlagOn(Data->Iopb->Parameters.Create.FileAttributes, ~STAGE_BASIC_ATTRIBUTES))) {
        SafeUploadDenyDetail(Data, SAFEUPLOAD_DENY_REASON_METADATA_UNSUPPORTED, STATUS_NOT_SUPPORTED, &Name->Name);
        status = STATUS_NOT_SUPPORTED; goto Exit;
    }
    /* T5: delete-on-close discards only a private-only name; a name that exists publicly cannot be deleted through staging yet. */
    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE)) {
        status = StagePublicNameFree(Objects->Instance, &Name->Name);
        if (!NT_SUCCESS(status)) goto Exit;
    }
    status = FltGetFileSystemType(Objects->Instance, &fs);
    if (!NT_SUCCESS(status)) goto Exit;
    if (fs != FLT_FSTYPE_NTFS || Kind == SafeUploadVolumeNetwork) {
        status = STATUS_NOT_SUPPORTED; goto Exit;
    }
    if (view == NULL) {
        view = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*view), STAGE_TAG);
        if (view == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
        newView = TRUE;
        status = SafeUploadStageCaptureSecurity(Data, Objects->Instance, &Name->Name, hidden != NULL,
            &view->Security, &view->AssignedSecurity, &exists, &granted);
        if (!NT_SUCCESS(status)) goto Exit;
        {
            UNICODE_STRING parent = Name->Name;
            USHORT index;
            for (index = parent.Length / sizeof(WCHAR); index > 0; --index)
                if (parent.Buffer[index - 1] == L'\\') break;
            if (index == 0) { status = STATUS_OBJECT_PATH_INVALID; goto Exit; }
            parent.Length = (index - 1) * sizeof(WCHAR);
            parent.MaximumLength = parent.Length;
            status = SafeUploadStageQueryIdentity(Objects->Instance, &parent, TRUE, &view->ParentIdentity);
            if (!NT_SUCCESS(status)) goto Exit;
            view->PhysicalExists = exists;
            if (exists || hidden != NULL) {
                status = SafeUploadStageQueryIdentity(Objects->Instance, &Name->Name, FALSE, &view->PhysicalIdentity);
                if (!exists && status == STATUS_OBJECT_NAME_NOT_FOUND) status = STATUS_SUCCESS;
                else if (!NT_SUCCESS(status)) goto Exit;
                else view->PhysicalExists = TRUE;
                if (view->PhysicalExists && view->PhysicalIdentity.VolumeSerialNumber != view->ParentIdentity.VolumeSerialNumber) {
                    status = STATUS_NOT_SAME_DEVICE; goto Exit;
                }
            }
        }
        view->Owner = owner; ObReferenceObject(owner);
        view->OwnerProcessId = FltGetRequestorProcessId(Data);
        view->Name.Buffer = view->NameBuffer;
        view->Name.MaximumLength = sizeof(view->NameBuffer);
        RtlCopyUnicodeString(&view->Name, &Name->Name);
    } else if (!reservedStreamSlot) {
        exists = TRUE;
        if (disposition == FILE_CREATE) { status = STATUS_OBJECT_NAME_COLLISION; goto Exit; }
        status = SafeUploadStageCheckAccess(Data, view->Security, desired, &granted);
        if (!NT_SUCCESS(status)) goto Exit;
        stream = view->Current;
        if (Writer && (FlagOn(desired, FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE | GENERIC_ALL | MAXIMUM_ALLOWED) ||
            disposition == FILE_SUPERSEDE || disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF)) {
            BOOLEAN readOnlyAttribute;
            StageAcquire(&stream->Resource);
            readOnlyAttribute = StageBasicReadonly(stream);
            StageRelease(&stream->Resource);
            if (readOnlyAttribute) { status = STATUS_ACCESS_DENIED; goto Exit; }
        }
#if SAFEUPLOAD_STAGING_PROTOTYPE
        if (stream->AttachLifecycleInFlight || stream->AttachCompletionFence || stream->AttachTerminalPending ||
            stream->AttachRetirePending ||
            (stream->AttachCompletionPending && (!AllowAttachResume ||
             InterlockedCompareExchange(&stream->FileObjects, 0, 0) != 0))) {
            status = STATUS_DEVICE_BUSY; goto Exit;
        }
#endif
        /* T5: the owner deleted this version and handles remain: the name is delete-pending, as on NTFS. */
        if (stream->DiscardOnClose && !stream->Sealed) { status = STATUS_DELETE_PENDING; goto Exit; }
        if (stream->RenameExchange != NULL || (stream->ReadOnly && !stream->Sealed)) {
            /* StageSettleCurrent just retried it inline; let the worker arm the retry timer for what still waits. */
            KeSetEvent(&StageWorkEvent, IO_NO_INCREMENT, FALSE);
            status = STATUS_SHARING_VIOLATION;
#if SAFEUPLOAD_STAGING_PROTOTYPE
            sharingGate = 6;
            if (!Writer && !stream->BoundAllocation && stream->RenameExchange == NULL && stream->ReadOnly && !stream->Sealed)
                status = STAGE_STATUS_READMIT; /* seal began after the unlocked namespace-reopen wait */
#endif
            goto Exit;
        }
        if (stream->Sealed && stream->BackingObject != NULL) {
            /* The service deleted this sealed version's stage file (BLOCK cleanup): the worker retires the stream at its next pass, but an
             * open must not be served from a delete-pending backing in between. Fail closed; the delete-pending state is permanent. */
            FILE_STANDARD_INFORMATION pending;
            /* T11: a create nested inside another file-system call (a top-level IRP is set) must not send the backing a new
             * request while the namespace lock is held. The backing cannot be verified there, so the open fails as a retryable
             * sharing conflict instead of being served from a possibly delete-pending stage. */
            if (IoGetTopLevelIrp() != NULL) {
#if SAFEUPLOAD_STAGING_PROTOTYPE
                sharingGate = 7;
#endif
                status = STATUS_SHARING_VIOLATION; goto Exit;
            }
            RtlZeroMemory(&pending, sizeof(pending));
            status = FltQueryInformationFile(stream->BackingInstance, stream->BackingObject,
                &pending, sizeof(pending), FileStandardInformation, NULL);
            if (!NT_SUCCESS(status)) goto Exit;
            if (pending.DeletePending) {
#if SAFEUPLOAD_STAGING_PROTOTYPE
                sharingGate = 8;
#endif
                status = STATUS_SHARING_VIOLATION; goto Exit;
            }
        }
    }
    if (stream == NULL || (Writer && stream->Sealed)) {
        previous = stream;
        if (StageStreamCount + StageReservedStreamCount >= STAGE_LIMIT) {
            InterlockedIncrement64((volatile LONG64 *)&StageCounters.CapRefusals);
            status = STATUS_INSUFFICIENT_RESOURCES; goto Exit;
        }
#if SAFEUPLOAD_STAGING_PROTOTYPE
        ++StageReservedStreamCount;
        reservedStreamSlot = TRUE;
        status = StageCreateStreamShell(Objects->Instance, Name->Volume.Length,
            &Name->Name, view, &stream);
        if (!NT_SUCCESS(status)) goto Exit;
        newStream = TRUE;
        if (previous != NULL) {
            previousTransferId = previous->TransferId;
            previousGeneration = previous->DestinationGeneration;
            previousIdentity = previous->StageIdentity;
            allocationViewGeneration = view->Generation;
            viewWasDetached = view->Detached;
            InterlockedIncrement(&previous->RpcReferences);
            previousPinned = TRUE;
        } else {
            allocationViewGeneration = view->Generation;
            viewWasDetached = view->Detached;
        }
        if (hidden != NULL) {
            tombstoneTransferName.Buffer = tombstoneTransferBuffer;
            tombstoneTransferName.Length = sizeof(tombstoneTransferBuffer);
            tombstoneTransferName.MaximumLength = sizeof(tombstoneTransferBuffer);
            RtlCopyMemory(tombstoneTransferBuffer, hidden->TransferId, sizeof(tombstoneTransferBuffer));
            tombstoneSnapshotValid = TRUE;
        }
        status = StageReserveAllocationName(stream);
        if (!NT_SUCCESS(status)) goto Exit;
        /* The v19 retry snapshot is larger than a kernel callback stack
         * allowance. Keep one bounded request scratch off-stack, then copy
         * its exact bytes into the retained stream receipt before freeing. */
        allocationRequest = ExAllocatePool2(POOL_FLAG_NON_PAGED,
            sizeof(*allocationRequest), STAGE_TAG);
        if (allocationRequest == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }
        RtlZeroMemory(allocationRequest, sizeof(*allocationRequest));
        allocationServiceGeneration = InterlockedCompareExchange(&StageServiceGeneration, 0, 0);
        StageRelease(&StageNamespaceResource);
        stream->BoundAllocation = bound;
        if (bound)
            status = StageAllocateBound(transaction, previous,
                tombstoneSnapshotValid ? &tombstoneTransferName : NULL,
                basename, &basenameLength, &allocatedGeneration, &allocatedIdentity,
                &allocationIntent, allocationRequest, &allocationMayExist);
        else status = SafeUploadStageAllocateV19(Data, &Name->Name, Kind,
            previous != NULL ? &previous->StageName : NULL,
            tombstoneSnapshotValid ? &tombstoneTransferName : NULL,
            basename, &basenameLength, &StageDriverInstanceId,
            &allocatedGeneration, &allocatedIdentity, &allocationIntent,
            allocationRequest, &allocationMayExist);
        allocationReplyKnown = NT_SUCCESS(status);
        stream->AllocationIntent = allocationIntent;
        stream->AllocationRequest = *allocationRequest;
        allocationRequestId = allocationRequest->RequestId;
        ExFreePoolWithTag(allocationRequest, STAGE_TAG);
        allocationRequest = NULL;
        stream->AllocationRecoveryProcessId = FltGetRequestorProcessId(Data);
        if (allocationIntent.Version == SAFEUPLOAD_STAGE_EXTENSION_VERSION &&
            allocationRequestId != 0) {
            stream->TransferId = allocationIntent.AllocationReservationId;
            stream->HasTransferId = TRUE;
        }
        stream->AllocationParentDirectoryIdentity.VolumeSerialNumber = view->ParentIdentity.VolumeSerialNumber;
        RtlCopyMemory(&stream->AllocationParentDirectoryIdentity.FileId,
            &view->ParentIdentity.FileId, sizeof(FILE_ID_128));
        if (allocationReplyKnown) {
            NTSTATUS nameStatus = StageSetStreamStageName(stream, basename, basenameLength);
            if (NT_SUCCESS(nameStatus)) {
                stream->DestinationGeneration = allocatedGeneration;
                stream->StageIdentity = allocatedIdentity;
                stream->StageIdentityValid = TRUE;
                stream->ExpectedStageIdentity = allocatedIdentity;
                stream->ExpectedStageIdentityValid = TRUE;
                stream->AllocationTupleKnown = TRUE;
            } else status = nameStatus;
        }
        if (bound && NT_SUCCESS(status)) {
            /* The new stream is still exclusively attach-owned and reserved.
             * Disk/query waits occur outside namespace/stream/spin locks. */
            status = SafeUploadStagePublicRevalidateWriter(transaction->WriterLease, &writerReason);
            if (status == STATUS_SUCCESS)
                status = SafeUploadStagePublicWriterMetadataCurrent(transaction->WriterLease, &writerReason);
            if (status == STATUS_SUCCESS) status = StageOpenBacking(stream, FALSE);
            if (status == STATUS_SUCCESS)
                status = SafeUploadStagePublicSeedWriter(transaction->WriterLease,
                    stream->BackingInstance, stream->BackingObject, stream->SectorSize,
                    &stream->StageIdentity, stream->DestinationGeneration, Data,
                    &stream->SeedCompletion, &writerReason);
            if (status == STATUS_SUCCESS) {
                if (previous != NULL) {
                    stream->SeedCompletion.PredecessorIdentity = previousIdentity;
                    stream->SeedCompletion.PredecessorGeneration = previousGeneration;
                }
                stream->Header.FileSize.QuadPart = stream->SeedCompletion.Length;
                stream->Header.ValidDataLength = stream->Header.FileSize;
            }
        }
        StageAcquire(&StageNamespaceResource);
        stream->AllocationRpcInFlight = FALSE;
        if (previousPinned && !bound) {
            InterlockedDecrement(&previous->RpcReferences);
            previousPinned = FALSE;
        }
        if (allocationMayExist && allocationRequestId != 0) {
            stream->AllocationReceiptPending = TRUE;
            stream->AllocationRecoveryPending = !stream->AllocationTupleKnown;
        } else {
            StageRemoveAllocationNameReservation(stream);
        }
        if (NT_SUCCESS(status) && (InterlockedCompareExchange(&StageDirectoryMutationActive, 0, 0) != 0 ||
            namespaceSequence != StageDirectorySequence)) { sharingGate = 9; status = STATUS_SHARING_VIOLATION; }
        if (NT_SUCCESS(status) && (StageStopping || SafeUploadStageMandatoryTeardownActive()))
            status = STATUS_DEVICE_NOT_READY;
        if (NT_SUCCESS(status) && allocationServiceGeneration !=
            InterlockedCompareExchange(&StageServiceGeneration, 0, 0))
            status = STATUS_PORT_DISCONNECTED;
        if (NT_SUCCESS(status) && ((!newView && StageFindView(owner, &Name->Name) != view) ||
            view->Detached != viewWasDetached || view->Generation != allocationViewGeneration ||
            (previous != NULL && (view->Current != previous ||
                !RtlEqualMemory(&previous->TransferId, &previousTransferId, sizeof(GUID)) ||
                previous->DestinationGeneration != previousGeneration ||
                !StageV19IdentityEqual(&previous->StageIdentity, &previousIdentity))) ||
            (previous == NULL && !newView)))
            status = STATUS_DELETE_PENDING;
        if (NT_SUCCESS(status) && tombstoneSnapshotValid) {
            PSTAGE_TOMBSTONE currentTombstone = StageHiddenTombstone(owner, &Name->Name);
            if (currentTombstone == NULL ||
                !RtlEqualMemory(currentTombstone->TransferId, tombstoneTransferBuffer,
                    sizeof(tombstoneTransferBuffer))) status = STATUS_DELETE_PENDING;
        }
        if (!allocationMayExist && !NT_SUCCESS(status)) goto Exit;
        if (!NT_SUCCESS(status)) goto Exit; /* receipt handling at Exit retains any possible commit */
        if (newView) {
            status = StageSetIdentity(view, basename);
            if (!NT_SUCCESS(status)) goto Exit;
        }
        if (!bound) status = StageOpenBacking(stream, FALSE);
        if (!NT_SUCCESS(status)) goto Exit;
#else
        stream = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*stream), STAGE_TAG);
        if (stream == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
        newStream = TRUE;
#if SAFEUPLOAD_STAGING_PROTOTYPE
        InitializeListHead(&stream->RpcLink);
#endif
        InitializeListHead(&stream->ReservationLink);
        stream->View = view;
        stream->ByteLocks = FltAllocateFileLock(NULL, NULL);
        if (stream->ByteLocks == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
        status = ExInitializeResourceLite(&stream->Resource);
        if (!NT_SUCCESS(status)) goto Exit;
        stream->ResourceInitialized = TRUE;
        status = ExInitializeResourceLite(&stream->PagingResource);
        if (!NT_SUCCESS(status)) goto Exit;
        stream->PagingInitialized = TRUE;
        ExInitializeRundownProtection(&stream->PagingRundown);
        ExInitializeFastMutex(&stream->HeaderMutex);
        FsRtlSetupAdvancedHeader(&stream->Header, &stream->HeaderMutex);
        stream->Header.NodeTypeCode = 0x5349;
        stream->Header.NodeByteSize = sizeof(*stream);
        stream->Header.Resource = &stream->Resource;
        stream->Header.PagingIoResource = &stream->PagingResource;
        stream->Header.IsFastIoPossible = FastIoIsNotPossible;
        status = FltObjectReference(Objects->Instance);
        if (!NT_SUCCESS(status)) goto Exit;
        stream->OriginalInstance = Objects->Instance;
        stream->VolumeLength = Name->Volume.Length;
        stream->Name.Buffer = stream->NameBuffer;
        stream->Name.MaximumLength = sizeof(stream->NameBuffer);
        RtlCopyUnicodeString(&stream->Name, &Name->Name);
        status = SafeUploadStageAllocate(Data, &Name->Name, Kind,
            previous != NULL ? &previous->StageName : NULL,
            hidden != NULL ? &hidden->TransferName : NULL, basename, &basenameLength);
        if (!NT_SUCCESS(status)) goto Exit;
        if (newView) {
            status = StageSetIdentity(view, basename);
            if (!NT_SUCCESS(status)) goto Exit;
        }
        status = RtlStringCchPrintfW(stream->StageBuffer, SAFEUPLOAD_MAX_PATH_CHARS,
            L"\\??\\C:\\ProgramData\\SafeUpload\\staging\\%ws", basename);
        if (!NT_SUCCESS(status)) goto Exit;
        RtlInitUnicodeString(&stream->StageName, stream->StageBuffer);
        stream->HasTransferId = StageParseTransferId(basename, basenameLength / sizeof(WCHAR), &stream->TransferId);
        status = StageOpenBacking(stream, FALSE);
        if (!NT_SUCCESS(status)) goto Exit;
#endif
    }
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (stream->BoundAllocation && (!bound || !StageBoundSeedReady(stream))) {
        /* A local EOF/flush receipt alone is not durable service confirmation.
         * Missing transport remains a named gate, including for empty stages. */
        SafeUploadStagePublicRecordWriterRefusal(StageWriterSeedCompletionUnproved);
        status = STATUS_DEVICE_NOT_READY;
        goto Exit;
    }
    if (bound && !stream->BoundAllocation) { status = STATUS_DEVICE_NOT_READY; goto Exit; }
    if (bound) granted = transaction->WriterGrantedAccess;
#endif
    if (newStream && NT_SUCCESS(status)) {
        StageInitializeBasic(stream, previous, exists, disposition, Data->Iopb->Parameters.Create.FileAttributes);
        /* The file object may be bound locally, but the upper create stays
         * pending until the exact v20 attach transaction permits completion. */
        stream->AttachCompletionPending = TRUE;
    }
    if (FLT_IS_IRP_OPERATION(Data) && FltIsIoCanceled(Data)) {
        status = STATUS_CANCELLED; goto Exit;
    }
    handle = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*handle), STAGE_TAG);
    if (handle == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (BooleanFlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE)) {
        reservedForCreate = !stream->PrivateDeleteReserved;
        stream->DeleteReservationId = stream->TransferId;
        status = StageReservePrivateDelete(stream);
        if (!NT_SUCCESS(status)) goto Exit;
    }
#endif
    StageAcquire(&stream->Resource);
    status = IoCheckShareAccess(granted, Data->Iopb->Parameters.Create.ShareAccess,
        file, &stream->ShareAccess, FALSE);
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (status == STATUS_SHARING_VIOLATION) sharingGate = 10;
#endif
    if (NT_SUCCESS(status) && !newStream && Writer &&
        (disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF || disposition == FILE_SUPERSEDE)) {
        LARGE_INTEGER zero = {0};
        /* CcSetFileSizes needs a file object bound to this stream. */
        file->FsContext = &stream->Header;
        file->SectionObjectPointer = &stream->Sections;
        __try { status = StageResize(stream, file, zero); }
        __except(EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
        if (!NT_SUCCESS(status)) {
            (VOID)CcUninitializeCacheMap(file, NULL, NULL);
            file->FsContext = NULL; file->SectionObjectPointer = NULL;
        }
    }
    if (NT_SUCCESS(status)) {
        IoUpdateShareAccess(file, &stream->ShareAccess);
        handle->Stream = stream; handle->GrantedAccess = granted;
#if SAFEUPLOAD_STAGING_PROTOTYPE
        if (bound) {
            handle->WriterLease = transaction->WriterLease;
            transaction->WriterLease = NULL;
        }
#endif
        /* T5: delete-on-close of the owner's private version discards it at the last cleanup (driver/T5-DELETES.md R3). */
        handle->DeleteOnClose = BooleanFlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE);
        if (handle->DeleteOnClose) {
            ++stream->DeleteOnCloseCount;
            stream->DiscardOnClose = TRUE; /* visible before NamespaceResource admits another create or rename */
        }
        file->FsContext = &stream->Header;
        file->FsContext2 = handle;
        file->SectionObjectPointer = &stream->Sections;
#if SAFEUPLOAD_STAGING_PROTOTYPE
        /* The durable allocation receipt and same-name reservation are
         * consumed only after the service's exact CompletionPermitted ACK. */
#endif
        SetFlag(file->Flags, FO_CACHE_SUPPORTED);
        InterlockedIncrement(&stream->FileObjects);
        InterlockedIncrement(&StageFileObjects);
        Data->Iopb->Parameters.Create.SecurityContext->AccessState->PreviouslyGrantedAccess |= granted;
        Data->Iopb->Parameters.Create.SecurityContext->AccessState->RemainingDesiredAccess &= ~(granted | MAXIMUM_ALLOWED);
        information = !exists ? FILE_CREATED : disposition == FILE_SUPERSEDE ? FILE_SUPERSEDED :
            (disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF) ? FILE_OVERWRITTEN : FILE_OPENED;
        Data->IoStatus.Information = information;
    }
    StageRelease(&stream->Resource);
    if (!NT_SUCCESS(status)) goto Exit;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    /* NamespaceResource precedes Resource/StageListLock. Claim before dropping
     * it; rollback can remove FileObjects before this transaction completes. */
    if (stream->AttachCompletionPending) stream->AttachLifecycleInFlight = TRUE;
#endif
    if (newStream) {
        StageStreamAcquireSpinLock(&StageListLock, &irql);
        InsertTailList(&StageStreams, &stream->Link);
        /* Listed means "on StageStreams" for every version. Exact-reply
         * revalidation (op19 receipt, allocation recovery) requires it; left
         * clear, each attached version discarded its HANDLE_OBSERVED ACK and
         * parked for a service reconnect before seal (m2t5boot9). */
        stream->Listed = TRUE;
        StageStreamReleaseSpinLock(&StageListLock, irql);
        StageStreamCount++;
        if (reservedStreamSlot) {
            if (StageReservedStreamCount != 0) --StageReservedStreamCount;
            reservedStreamSlot = FALSE;
            view->Detached = FALSE;
        }
        InterlockedIncrement64((volatile LONG64 *)&StageCounters.VersionsCreated);
        view->Current = stream;
        view->Streams++;
#if SAFEUPLOAD_STAGING_PROTOTYPE
        if (previous != NULL && stream->AllocationReceiptParent == NULL) {
            stream->AllocationReceiptParent = previous;
            ++previous->AllocationReceiptReferences;
        }
        /* Keep AllocationReservation until v20 attachment is durably allowed. */
#endif
        /* The superseded version is unreachable by name now; it is released once nothing holds it. */
        if (previous != NULL) StageQueueStream(previous, &StageCounters.WakeInline);
    }
    if (newView) {
        view->Generation = ++StageNamespaceSequence;
        InsertTailList(&StageViews, &view->Link);
        StageViewCount++;
        StageDropTombstone(owner, &view->Name);
    }
Exit:
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (status == STATUS_SHARING_VIOLATION) {
        UINT32 detail = sharingGate;
        if (stream != NULL) {
            detail |= (stream->ReadOnly ? 0x100u : 0) | (stream->Sealed ? 0x200u : 0) |
                (stream->RenameExchange != NULL ? 0x400u : 0);
            detail |= ((UINT32)InterlockedCompareExchange(&stream->FileObjects, 0, 0) & 0xffffu) << 16;
        }
        SafeUploadDenyDetail(Data, SAFEUPLOAD_DENY_REASON_STAGE_CREATE_CONFLICT,
            (NTSTATUS)detail, &Name->Name);
    }
#endif
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (allocationRequest != NULL) ExFreePoolWithTag(allocationRequest, STAGE_TAG);
    if (!NT_SUCCESS(status) && newStream && stream != NULL && stream->BoundAllocation &&
        stream->BackingObject != NULL) {
        /* Still attach-owned, with the predecessor pin retained through this
         * local close. No new I/O wait under the namespace resource. */
        StageRelease(&StageNamespaceResource);
        StageCloseBacking(stream);
        StageAcquire(&StageNamespaceResource);
    }
    /* The legacy RPC completion path drops this pin and clears the flag before it
     * reaches Exit. Any earlier failure (including name-reservation or
     * request-scratch allocation failure) still owns it; release it here
     * while NamespaceResource keeps the predecessor stable, then wake the
     * worker in case it was waiting only for this reference to drain. */
    if (previousPinned) {
        InterlockedDecrement(&previous->RpcReferences);
        previousPinned = FALSE;
        StageQueueStream(previous, &StageCounters.WakeInline);
    }
#endif
    if (!NT_SUCCESS(status)) {
#if SAFEUPLOAD_STAGING_PROTOTYPE
        if (reservedForCreate && stream != NULL) StageClearPrivateDelete(stream);
        if (newStream && stream != NULL && stream->AllocationReceiptPending) {
            if (bound && !stream->AllocationTupleKnown) {
                stream->AllocationWriterLease = transaction->WriterLease;
                transaction->WriterLease = NULL;
            }
            StageRetainAllocationReceipt(stream, view, newView, reservedStreamSlot,
                previous, status);
            reservedStreamSlot = FALSE;
            newStream = FALSE;
            newView = FALSE;
        } else if (reservedStreamSlot && StageReservedStreamCount != 0) {
            --StageReservedStreamCount;
            reservedStreamSlot = FALSE;
        }
#endif
        if (handle != NULL) ExFreePoolWithTag(handle, STAGE_TAG);
        if (newStream) StageFreeStream(stream);
        if (newView) StageFreeView(view);
        /* A durable allocation whose CREATE failed remains unsealed for recovery. */
    }
    StageRelease(&StageNamespaceResource);
    return status;
}

#if SAFEUPLOAD_STAGING_PROTOTYPE
static NTSTATUS StageAttachSnapshotName(_In_ PFLT_FILE_NAME_INFORMATION Source,
    _Outptr_ PFLT_FILE_NAME_INFORMATION *Snapshot)
{
    PFLT_FILE_NAME_INFORMATION copy;
    PUCHAR cursor;
    SIZE_T bytes = sizeof(*copy);
#define STAGE_NAME_BYTES(_field) do { if (Source->_field.Length != 0) bytes += Source->_field.Length; } while (0)
    if (Snapshot == NULL) return STATUS_INVALID_PARAMETER;
    *Snapshot = NULL;
    if (Source == NULL || Source->Name.Buffer == NULL || Source->Name.Length == 0 ||
        Source->Name.Length > SAFEUPLOAD_MAX_PATH_BYTES || (Source->Name.Length & 1) != 0 ||
        Source->Volume.Length > SAFEUPLOAD_MAX_PATH_BYTES || (Source->Volume.Length & 1) != 0 ||
        Source->Stream.Length > SAFEUPLOAD_MAX_PATH_BYTES || (Source->Stream.Length & 1) != 0)
        return STATUS_INVALID_PARAMETER;
    STAGE_NAME_BYTES(Name); STAGE_NAME_BYTES(Volume); STAGE_NAME_BYTES(Share);
    STAGE_NAME_BYTES(Extension); STAGE_NAME_BYTES(Stream); STAGE_NAME_BYTES(FinalComponent);
    STAGE_NAME_BYTES(ParentDir);
#undef STAGE_NAME_BYTES
    if (bytes > MAXUSHORT) return STATUS_NAME_TOO_LONG;
    copy = ExAllocatePool2(POOL_FLAG_NON_PAGED, bytes, STAGE_TAG);
    if (copy == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(copy, bytes);
    copy->Size = (USHORT)bytes;
    copy->NamesParsed = Source->NamesParsed;
    cursor = (PUCHAR)(copy + 1);
#define STAGE_COPY_NAME(_field) do { \
        copy->_field.Length = Source->_field.Length; \
        copy->_field.MaximumLength = Source->_field.Length; \
        if (Source->_field.Length != 0) { \
            copy->_field.Buffer = (PWCH)cursor; \
            RtlCopyMemory(cursor, Source->_field.Buffer, Source->_field.Length); \
            cursor += Source->_field.Length; \
        } \
    } while (0)
    STAGE_COPY_NAME(Name); STAGE_COPY_NAME(Volume); STAGE_COPY_NAME(Share);
    STAGE_COPY_NAME(Extension); STAGE_COPY_NAME(Stream); STAGE_COPY_NAME(FinalComponent);
    STAGE_COPY_NAME(ParentDir);
#undef STAGE_COPY_NAME
    *Snapshot = copy;
    return STATUS_SUCCESS;
}

static VOID StageAttachReference(_Inout_ PSTAGE_ATTACH_TRANSACTION Transaction)
{
    NT_ASSERT(Transaction != NULL);
    InterlockedIncrement(&Transaction->References);
}

static VOID StageAttachReleaseCreateInput(PSAFEUPLOAD_STAGE_CREATE_INPUT Input)
{
    SafeUploadStagePublicFreeCreateLookup(Input);
    if (Input->EaBuffer != NULL) {
        ExFreePoolWithTag(Input->EaBuffer, STAGE_TAG);
        Input->EaBuffer = NULL;
    }
    if (Input->Security != NULL) {
        ExFreePoolWithTag(Input->Security, STAGE_TAG);
        Input->Security = NULL;
    }
}

/* Runs before queue publication, in the original callback's process context.
 * A failed capture leaves partial owned buffers for transaction destruction.
 * Do not assign a descriptor, widen access or mutate the original CREATE here. */
static NTSTATUS StageAttachCaptureCreateInput(PFLT_CALLBACK_DATA Data, PSAFEUPLOAD_STAGE_CREATE_INPUT Input)
{
    PIO_SECURITY_CONTEXT security = Data->Iopb->Parameters.Create.SecurityContext;
    PSECURITY_DESCRIPTOR supplied;
    SECURITY_DESCRIPTOR_CONTROL control;
    ULONG bytes, returned;
    NTSTATUS status = STATUS_SUCCESS;
    if (security == NULL || security->AccessState == NULL) return STATUS_ACCESS_DENIED;
    Input->DesiredAccess = security->DesiredAccess;
    Input->OriginalDesiredAccess = security->AccessState->OriginalDesiredAccess;
    Input->RemainingDesiredAccess = security->AccessState->RemainingDesiredAccess;
    Input->PreviouslyGrantedAccess = security->AccessState->PreviouslyGrantedAccess;
    Input->Options = Data->Iopb->Parameters.Create.Options;
    Input->FileAttributes = Data->Iopb->Parameters.Create.FileAttributes;
    Input->ShareAccess = Data->Iopb->Parameters.Create.ShareAccess;
    Input->AllocationSize = Data->Iopb->Parameters.Create.AllocationSize;
    Input->OperationFlags = Data->Iopb->OperationFlags; /* Includes SL_CASE_SENSITIVE. */
    Input->RequestorMode = Data->RequestorMode;
    Input->NativeEligible = StageAttachNativeEligible(Data);
    Input->EaLength = Data->Iopb->Parameters.Create.EaLength;
    supplied = security->AccessState->SecurityDescriptor;
    Input->SuppliedSecurity = supplied != NULL;
    __try {
        if (Input->EaLength != 0) {
            if (Input->EaLength > SAFEUPLOAD_STAGE_CREATE_EA_LIMIT) {
                SafeUploadStagePublicRecordWriterRefusal(StageWriterCaptureLimit);
                return STATUS_QUOTA_EXCEEDED;
            }
            if (Data->Iopb->Parameters.Create.EaBuffer == NULL) return STATUS_INVALID_PARAMETER;
            Input->EaBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, Input->EaLength, STAGE_TAG);
            if (Input->EaBuffer == NULL) return STATUS_INSUFFICIENT_RESOURCES;
            RtlCopyMemory(Input->EaBuffer, Data->Iopb->Parameters.Create.EaBuffer, Input->EaLength);
            /* Retain the exact bytes. Native disposition semantics decide
             * whether to apply or validate EAs; capture is not that decision. */
        }
        if (supplied != NULL) {
            if (!RtlValidSecurityDescriptor(supplied)) return STATUS_INVALID_SECURITY_DESCR;
            /* Absolute and self-relative descriptors share this documented
             * header; the descriptor was validated above. No private DDI. */
            control = ((SECURITY_DESCRIPTOR_RELATIVE *)supplied)->Control;
            bytes = RtlLengthSecurityDescriptor(supplied);
            if (bytes < sizeof(SECURITY_DESCRIPTOR_RELATIVE)) return STATUS_INVALID_SECURITY_DESCR;
            if (bytes > SAFEUPLOAD_STAGE_CREATE_SECURITY_LIMIT) {
                SafeUploadStagePublicRecordWriterRefusal(StageWriterCaptureLimit);
                return STATUS_QUOTA_EXCEEDED;
            }
            Input->Security = ExAllocatePool2(POOL_FLAG_NON_PAGED, bytes, STAGE_TAG);
            if (Input->Security == NULL) return STATUS_INSUFFICIENT_RESOURCES;
            if (FlagOn(control, SE_SELF_RELATIVE)) {
                RtlCopyMemory(Input->Security, supplied, bytes);
                returned = bytes;
            } else {
                returned = bytes;
                status = RtlAbsoluteToSelfRelativeSD(supplied, Input->Security, &returned);
                if (!NT_SUCCESS(status)) return status;
            }
            if (returned > bytes || !RtlValidRelativeSecurityDescriptor(Input->Security, returned, 0))
                return STATUS_INVALID_SECURITY_DESCR;
            Input->SecurityBytes = returned;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    return status;
}

/* Windows 10 19041/19045 does not export SeDeleteClientSecurity: the current
 * WDK declares it as a function for this project's NTDDI_VERSION, so a driver
 * importing it cannot load on the qualified target (m2t5rv1: fltmc 0x8007007F;
 * as a boot-start driver, every boot fell into WinRE). The pre-Windows 11 macro
 * released the one token reference SeCreateClientSecurityFromSubjectContext took
 * (PsDereferencePrimaryToken/PsDereferenceImpersonationToken, both
 * ObDereferenceObject). Token release stays at PASSIVE, as those routines are
 * annotated; the final transaction release, which can run at DISPATCH_LEVEL,
 * only asserts that the PASSIVE cleanup already released the subject. */
_IRQL_requires_(PASSIVE_LEVEL)
static VOID StageDeleteClientSecurity(_Inout_ PSECURITY_CLIENT_CONTEXT Context)
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (Context->ClientToken != NULL) ObDereferenceObject(Context->ClientToken);
    Context->ClientToken = NULL;
}

static VOID StageAttachTransactionDereference(PSTAGE_ATTACH_TRANSACTION Transaction)
{
    if (Transaction == NULL || InterlockedDecrement(&Transaction->References) != 0) return;
    NT_ASSERT(!Transaction->LookupLinked);
    NT_ASSERT(!Transaction->WorkItemQueued);
    /* Final cancellation release can be DISPATCH_LEVEL. PASSIVE failure or
     * active rundown must already have closed every new owned handle. */
    NT_ASSERT(Transaction->WriterLease == NULL);
    NT_ASSERT(Transaction->CreateInput.LookupRootHandle == NULL);
    if (Transaction->AdmissionToken != NULL)
        SafeUploadPolicyAdmissionRelease(Transaction->AdmissionToken);
    if (Transaction->NameInfo != NULL && Transaction->NameInfoIsSynthetic)
        ExFreePoolWithTag(Transaction->NameInfo, STAGE_TAG);
    if (Transaction->RequestorProcess != NULL) ObDereferenceObject(Transaction->RequestorProcess);
    /* Failure cleanup and worker completion release the subject at PASSIVE in
     * StageAttachReleaseRelatedObjects before the last reference can drop; a
     * failed capture leaves it zeroed. Never release a token here (DISPATCH). */
    NT_ASSERT(!Transaction->OriginalSubjectValid && Transaction->OriginalSubject.ClientToken == NULL);
    StageAttachReleaseCreateInput(&Transaction->CreateInput);
    if (Transaction->ReferencedFileObject != NULL)
        ObDereferenceObject(Transaction->ReferencedFileObject);
    if (Transaction->ReferencedVolume != NULL)
        FltObjectDereference(Transaction->ReferencedVolume);
    if (Transaction->ReferencedInstance != NULL)
        FltObjectDereference(Transaction->ReferencedInstance);
    if (Transaction->ReferencedFilter != NULL)
        FltObjectDereference(Transaction->ReferencedFilter);
    ExFreePoolWithTag(Transaction, STAGE_TAG);
}

/* The active lookup is also the instance-teardown rundown list. Drop every
 * object/process/name reference before unlinking it, so teardown-complete
 * cannot race a worker still holding Filter Manager objects. InstanceIdentity
 * is only compared as an opaque address after this point. */
static VOID StageAttachReleaseRelatedObjects(PSTAGE_ATTACH_TRANSACTION Transaction)
{
    if (Transaction == NULL) return;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    SafeUploadStagePublicReleaseWriter(Transaction->WriterLease);
    Transaction->WriterLease = NULL;
    SafeUploadStagePublicCloseCreateLookup(&Transaction->CreateInput);
    if (Transaction->OriginalSubjectValid) {
        StageDeleteClientSecurity(&Transaction->OriginalSubject);
        Transaction->OriginalSubjectValid = FALSE;
    }
    StageAttachReleaseCreateInput(&Transaction->CreateInput);
    if (Transaction->NameInfo != NULL && Transaction->NameInfoIsSynthetic) {
        ExFreePoolWithTag(Transaction->NameInfo, STAGE_TAG);
        Transaction->NameInfo = NULL;
        Transaction->NameInfoIsSynthetic = FALSE;
        Transaction->OwnNameInfo = FALSE;
    }
    if (Transaction->RequestorProcess != NULL) {
        ObDereferenceObject(Transaction->RequestorProcess);
        Transaction->RequestorProcess = NULL;
    }
    if (Transaction->ReferencedFileObject != NULL) {
        ObDereferenceObject(Transaction->ReferencedFileObject);
        Transaction->ReferencedFileObject = NULL;
    }
    if (Transaction->ReferencedVolume != NULL) {
        FltObjectDereference(Transaction->ReferencedVolume);
        Transaction->ReferencedVolume = NULL;
    }
    if (Transaction->ReferencedInstance != NULL) {
        FltObjectDereference(Transaction->ReferencedInstance);
        Transaction->ReferencedInstance = NULL;
    }
    if (Transaction->ReferencedFilter != NULL) {
        FltObjectDereference(Transaction->ReferencedFilter);
        Transaction->ReferencedFilter = NULL;
    }
}

static BOOLEAN StageAttachRemoveLookup(_Inout_ PSTAGE_ATTACH_TRANSACTION Transaction)
{
    KIRQL irql;
    BOOLEAN removed = FALSE;
    StageStreamAcquireSpinLock(&StageAttachLock, &irql);
    if (Transaction->LookupLinked) {
        RemoveEntryList(&Transaction->LookupLink);
        InitializeListHead(&Transaction->LookupLink);
        Transaction->LookupLinked = FALSE;
        removed = TRUE;
    }
    StageStreamReleaseSpinLock(&StageAttachLock, irql);
    if (removed) {
        KeSetEvent(&StageAttachChanged, IO_NO_INCREMENT, FALSE);
        StageAttachTransactionDereference(Transaction); /* lookup reference */
    }
    return removed;
}

static VOID StageAttachReleaseActive(VOID)
{
    KIRQL irql;
    StageStreamAcquireSpinLock(&StageAttachLock, &irql);
    if (InterlockedDecrement(&StageAttachActiveCount) == 0 && StageAttachCaptureCount == 0)
        KeSetEvent(&StageAttachDrained, IO_NO_INCREMENT, FALSE);
    StageStreamReleaseSpinLock(&StageAttachLock, irql);
    KeSetEvent(&StageAttachChanged, IO_NO_INCREMENT, FALSE);
}

static VOID StageAttachCancelCallback(PFLT_CALLBACK_DATA Data)
{
    PLIST_ENTRY link;
    PSTAGE_ATTACH_TRANSACTION transaction = NULL;
    KIRQL irql;
    /* The callback receives no driver context from Filter Manager. The
     * prepublished lookup table is the only route back to its transaction. */
    StageStreamAcquireSpinLock(&StageAttachLock, &irql);
    for (link = StageAttachLookup.Flink; link != &StageAttachLookup; link = link->Flink) {
        PSTAGE_ATTACH_TRANSACTION candidate = CONTAINING_RECORD(link,
            STAGE_ATTACH_TRANSACTION, LookupLink);
        if (candidate->CallbackData == Data) {
            transaction = candidate;
            StageAttachReference(transaction);
            InterlockedExchange(&transaction->CancelCallbackState, 1);
            InterlockedExchange(&transaction->CancelRequested, 1);
            break;
        }
    }
    StageStreamReleaseSpinLock(&StageAttachLock, irql);
    if (transaction != NULL) {
        KeSetEvent(&StageAttachQueueEvent, IO_NO_INCREMENT, FALSE);
        KeSetEvent(&StageAttachChanged, IO_NO_INCREMENT, FALSE);
        /* Set the exit event after all table accesses. FltClearCancelCompletion
         * returning STATUS_CANCELLED waits on this exact callback, not merely
         * on the IRP's cancellation bit. */
        InterlockedExchange(&transaction->CancelCallbackState, 2);
        KeSetEvent(&transaction->CancelCallbackExited, IO_NO_INCREMENT, FALSE);
        StageAttachTransactionDereference(transaction); /* callback reference */
    }
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageAttachReserveCapture(_In_ PFLT_INSTANCE Instance, _Out_ PULONG Slot)
{
    PLIST_ENTRY link;
    ULONG index, instanceCount = 0, freeSlot = STAGE_ATTACH_LIMIT_GLOBAL;
    KIRQL irql;
    NTSTATUS status = STATUS_SUCCESS;
    *Slot = STAGE_ATTACH_LIMIT_GLOBAL;
    StageStreamAcquireSpinLock(&StageAttachLock, &irql);
    if (!StageAttachAccepting || StageAttachStopping || !StageAttachThreadRunning ||
        InterlockedCompareExchange(&StageUnloadAdmissionClosed, 0, 0) != 0 ||
        StageAttachActiveCount + StageAttachCaptureCount >= STAGE_ATTACH_LIMIT_GLOBAL) {
        status = STATUS_DEVICE_BUSY;
        goto Exit;
    }
    for (link = StageAttachTearingDownInstances.Flink;
         link != &StageAttachTearingDownInstances; link = link->Flink) {
        if (CONTAINING_RECORD(link, STAGE_ATTACH_INSTANCE_TOMBSTONE, Link)->Instance == Instance) {
            status = STATUS_VOLUME_DISMOUNTED;
            goto Exit;
        }
    }
    for (link = StageAttachLookup.Flink; link != &StageAttachLookup; link = link->Flink)
        if (CONTAINING_RECORD(link, STAGE_ATTACH_TRANSACTION, LookupLink)->InstanceIdentity == Instance) ++instanceCount;
    for (index = 0; index < STAGE_ATTACH_LIMIT_GLOBAL; ++index) {
        if (StageAttachCaptures[index] == Instance) ++instanceCount;
        else if (StageAttachCaptures[index] == NULL && freeSlot == STAGE_ATTACH_LIMIT_GLOBAL) freeSlot = index;
    }
    if (instanceCount >= STAGE_ATTACH_LIMIT_PER_INSTANCE || freeSlot == STAGE_ATTACH_LIMIT_GLOBAL) {
        status = STATUS_DEVICE_BUSY;
        goto Exit;
    }
    if (StageAttachActiveCount + StageAttachCaptureCount == 0) KeClearEvent(&StageAttachDrained);
    StageAttachCaptures[freeSlot] = Instance;
    ++StageAttachCaptureCount;
    *Slot = freeSlot;
Exit:
    StageStreamReleaseSpinLock(&StageAttachLock, irql);
    return status;
}

/* Returns a reservation that never became an active transaction, after every
 * resource captured under it has been released. Exactly once per reservation. */
_IRQL_requires_max_(APC_LEVEL)
static VOID StageAttachReturnCapture(_In_ ULONG Slot)
{
    KIRQL irql;
    NT_ASSERT(Slot < STAGE_ATTACH_LIMIT_GLOBAL);
    if (Slot >= STAGE_ATTACH_LIMIT_GLOBAL) return;
    StageStreamAcquireSpinLock(&StageAttachLock, &irql);
    NT_ASSERT(StageAttachCaptures[Slot] != NULL && StageAttachCaptureCount > 0);
    StageAttachCaptures[Slot] = NULL;
    --StageAttachCaptureCount;
    if (StageAttachActiveCount + StageAttachCaptureCount == 0)
        KeSetEvent(&StageAttachDrained, IO_NO_INCREMENT, FALSE);
    StageStreamReleaseSpinLock(&StageAttachLock, irql);
    KeSetEvent(&StageAttachChanged, IO_NO_INCREMENT, FALSE);
}

static NTSTATUS StageAttachQueueCreate(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, PFLT_FILE_NAME_INFORMATION Name,
    SAFEUPLOAD_VOLUME_KIND VolumeKind, LONG64 ExpectedGeneration,
    BOOLEAN PrivateNamespace, BOOLEAN ById, BOOLEAN TakeNameOwnership,
    PSTAGE_ADMISSION_TOKEN_SLOT AdmissionSlot)
{
    PSTAGE_ATTACH_TRANSACTION transaction = NULL;
    PFLT_FILE_NAME_INFORMATION nameSnapshot = NULL;
    PLIST_ENTRY link;
    ULONG instanceCount = 0;
    KIRQL irql;
    NTSTATUS status;
    BOOLEAN lookupLinked = FALSE;
    BOOLEAN lookupRemoved = FALSE;
    BOOLEAN captureReserved = FALSE;
    ULONG captureSlot = STAGE_ATTACH_LIMIT_GLOBAL;
    if (Data == NULL || Objects == NULL || Name == NULL || AdmissionSlot == NULL ||
        AdmissionSlot->Token == NULL || AdmissionSlot->Owner != StageAdmissionTokenDispatch ||
        Data->Iopb->MajorFunction != IRP_MJ_CREATE || !FLT_IS_IRP_OPERATION(Data) ||
        KeGetCurrentIrql() != PASSIVE_LEVEL || IoGetTopLevelIrp() != NULL ||
        FLT_IS_FASTIO_OPERATION(Data) || FltIsIoCanceled(Data))
        return STATUS_DEVICE_NOT_READY;

    /* Capacity covers the capture itself: names, transaction, references,
     * subject, EA and security copies are all acquired under a reservation. */
    status = StageAttachReserveCapture(Objects->Instance, &captureSlot);
    if (!NT_SUCCESS(status)) return status;
    captureReserved = TRUE;
    status = StageAttachSnapshotName(Name, &nameSnapshot);
    if (!NT_SUCCESS(status)) { StageAttachReturnCapture(captureSlot); return status; }
    transaction = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*transaction), STAGE_TAG);
    if (transaction == NULL) {
        ExFreePoolWithTag(nameSnapshot, STAGE_TAG);
        StageAttachReturnCapture(captureSlot);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(transaction, sizeof(*transaction));
    InitializeListHead(&transaction->QueueLink);
    InitializeListHead(&transaction->LookupLink);
    KeInitializeEvent(&transaction->PreOpReturnEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&transaction->CancelCallbackExited, NotificationEvent, FALSE);
    KeInitializeEvent(&transaction->Completed, NotificationEvent, FALSE);
    transaction->References = 1; /* producer reference until the dispatch wrapper commits */
    transaction->CallbackData = Data;
    transaction->NameInfo = nameSnapshot;
    transaction->NameInfoIsSynthetic = TRUE;
    transaction->OwnNameInfo = TRUE;
    RtlCopyMemory(&transaction->RelatedObjects, Objects, sizeof(transaction->RelatedObjects));
    transaction->InstanceIdentity = Objects->Instance;
    status = FltObjectReference(Objects->Filter);
    if (!NT_SUCCESS(status)) goto Fail;
    transaction->ReferencedFilter = Objects->Filter;
    status = FltObjectReference(Objects->Instance);
    if (!NT_SUCCESS(status)) goto Fail;
    transaction->ReferencedInstance = Objects->Instance;
    status = FltObjectReference(Objects->Volume);
    if (!NT_SUCCESS(status)) goto Fail;
    transaction->ReferencedVolume = Objects->Volume;
    ObReferenceObject(Objects->FileObject);
    transaction->ReferencedFileObject = Objects->FileObject;
    transaction->RequestorProcess = FltGetRequestorProcess(Data);
    if (transaction->RequestorProcess == NULL) { status = STATUS_ACCESS_DENIED; goto Fail; }
    ObReferenceObject(transaction->RequestorProcess);
    transaction->RequestorProcessId = FltGetRequestorProcessId(Data);
    /* Every queued writer, including an existing-view reopen, owns the
     * original effective static subject. Preserve its actual token level;
     * later backend checks cannot promote it or substitute SYSTEM. */
    status = SafeUploadStagePublicCaptureCreateSubject(Data, &transaction->OriginalSubject);
    if (!NT_SUCCESS(status)) goto Fail;
    transaction->OriginalSubjectValid = TRUE;
    status = StageAttachCaptureCreateInput(Data, &transaction->CreateInput);
    if (!NT_SUCCESS(status)) goto Fail;
    status = SafeUploadStagePublicCaptureCreateLookup(Data, Objects, &transaction->CreateInput);
    if (!NT_SUCCESS(status)) goto Fail;
    transaction->VolumeKind = VolumeKind;
    transaction->ExpectedGeneration = ExpectedGeneration;
    transaction->DirectorySequence = AdmissionSlot->DirectorySequence;
    transaction->PrivateNamespace = PrivateNamespace;
    transaction->ById = ById;
    transaction->DriverInstanceId = StageDriverInstanceId;
    transaction->AdmissionToken = (PSAFEUPLOAD_ADMISSION_EPOCH_TOKEN)AdmissionSlot->Token;

    /* Capacity and lookup visibility are reserved before cancellation can
     * call back. No allocation or fallible queue insertion follows arming. */
    StageStreamAcquireSpinLock(&StageAttachLock, &irql);
    if (!StageAttachAccepting || StageAttachStopping || !StageAttachThreadRunning ||
        InterlockedCompareExchange(&StageUnloadAdmissionClosed, 0, 0) != 0 ||
        InterlockedCompareExchange(&StageAttachActiveCount, 0, 0) >= STAGE_ATTACH_LIMIT_GLOBAL) {
        StageStreamReleaseSpinLock(&StageAttachLock, irql);
        status = STATUS_DEVICE_BUSY;
        transaction->AdmissionToken = NULL; /* caller still owns its slot */
        goto Fail;
    }
    for (link = StageAttachTearingDownInstances.Flink;
         link != &StageAttachTearingDownInstances; link = link->Flink) {
        PSTAGE_ATTACH_INSTANCE_TOMBSTONE item = CONTAINING_RECORD(link,
            STAGE_ATTACH_INSTANCE_TOMBSTONE, Link);
        if (item->Instance == Objects->Instance) {
            StageStreamReleaseSpinLock(&StageAttachLock, irql);
            status = STATUS_VOLUME_DISMOUNTED;
            transaction->AdmissionToken = NULL;
            goto Fail;
        }
    }
    for (link = StageAttachLookup.Flink; link != &StageAttachLookup; link = link->Flink) {
        PSTAGE_ATTACH_TRANSACTION current = CONTAINING_RECORD(link,
            STAGE_ATTACH_TRANSACTION, LookupLink);
        if (current->InstanceIdentity == Objects->Instance) ++instanceCount;
        if (current->CallbackData == Data) {
            StageStreamReleaseSpinLock(&StageAttachLock, irql);
            status = STATUS_INVALID_DEVICE_STATE;
            transaction->AdmissionToken = NULL;
            goto Fail;
        }
    }
    if (instanceCount >= STAGE_ATTACH_LIMIT_PER_INSTANCE) {
        StageStreamReleaseSpinLock(&StageAttachLock, irql);
        status = STATUS_DEVICE_BUSY;
        transaction->AdmissionToken = NULL;
        goto Fail;
    }
    if (InterlockedCompareExchange(&StageAttachActiveCount, 0, 0) == 0)
        KeClearEvent(&StageAttachDrained);
    StageAttachReference(transaction); /* lookup reference */
    InsertTailList(&StageAttachLookup, &transaction->LookupLink);
    transaction->LookupLinked = TRUE;
    /* The capture reservation becomes this active count in one lock hold. */
    StageAttachCaptures[captureSlot] = NULL;
    --StageAttachCaptureCount;
    captureReserved = FALSE;
    InterlockedIncrement(&StageAttachActiveCount);
    lookupLinked = TRUE;
    StageStreamReleaseSpinLock(&StageAttachLock, irql);

    status = FltSetCancelCompletion(Data, StageAttachCancelCallback);
    if (!NT_SUCCESS(status)) goto Fail;
    transaction->CancelRegistered = TRUE;
    StageAttachReference(transaction); /* queue/worker reference */
    transaction->WorkItemQueued = TRUE;
    StageStreamAcquireSpinLock(&StageAttachLock, &irql);
    InsertTailList(&StageAttachQueue, &transaction->QueueLink);
    StageStreamReleaseSpinLock(&StageAttachLock, irql);
    AdmissionSlot->Token = NULL;
    AdmissionSlot->Transaction = transaction;
    AdmissionSlot->Owner = StageAdmissionTokenAttach;
    if (TakeNameOwnership) ExFreePoolWithTag(Name, STAGE_TAG);
    KeSetEvent(&StageAttachQueueEvent, IO_NO_INCREMENT, FALSE);
    return STATUS_PENDING;

Fail:
    if (transaction->CancelRegistered) {
        NTSTATUS clearStatus = FltClearCancelCompletion(Data);
        if (clearStatus == STATUS_CANCELLED) {
            KeWaitForSingleObject(&transaction->CancelCallbackExited,
                Executive, KernelMode, FALSE, NULL);
        }
        transaction->CancelRegistered = FALSE;
    }
    /* On failure the dispatch callback still owns AdmissionSlot->Token. */
    transaction->AdmissionToken = NULL;
    /* Close root/lease holds before removing the instance-rundown lookup. */
    StageAttachReleaseRelatedObjects(transaction);
    if (lookupLinked) lookupRemoved = StageAttachRemoveLookup(transaction);
    StageAttachTransactionDereference(transaction);
    if (lookupRemoved) StageAttachReleaseActive();
    if (captureReserved) StageAttachReturnCapture(captureSlot);
    return status;
}

static VOID StageAttachCommitPreOpReturn(PSTAGE_ATTACH_TRANSACTION Transaction)
{
    if (Transaction == NULL || InterlockedCompareExchange(&Transaction->PreOpReturnCommitted, 1, 0) != 0)
        return;
    KeSetEvent(&Transaction->PreOpReturnEvent, IO_NO_INCREMENT, FALSE);
    StageAttachTransactionDereference(Transaction); /* producer reference */
}

static BOOLEAN StageAttachHasInstance(_In_ PFLT_INSTANCE Instance)
{
    PLIST_ENTRY link;
    KIRQL irql;
    BOOLEAN found = FALSE;
    ULONG index;
    StageStreamAcquireSpinLock(&StageAttachLock, &irql);
    for (link = StageAttachLookup.Flink; link != &StageAttachLookup; link = link->Flink) {
        PSTAGE_ATTACH_TRANSACTION tx = CONTAINING_RECORD(link,
            STAGE_ATTACH_TRANSACTION, LookupLink);
        if (tx->InstanceIdentity == Instance) { found = TRUE; break; }
    }
    for (index = 0; !found && index < STAGE_ATTACH_LIMIT_GLOBAL; ++index)
        if (StageAttachCaptures[index] == Instance) found = TRUE;
    StageStreamReleaseSpinLock(&StageAttachLock, irql);
    return found;
}

static BOOLEAN StageAttachIsInstanceTearingDown(_In_ PFLT_INSTANCE Instance)
{
    PLIST_ENTRY link;
    KIRQL irql;
    BOOLEAN found = FALSE;
    if (SafeUploadStageMandatoryTeardownActive()) return TRUE;
    StageStreamAcquireSpinLock(&StageAttachLock, &irql);
    for (link = StageAttachTearingDownInstances.Flink;
         link != &StageAttachTearingDownInstances; link = link->Flink) {
        PSTAGE_ATTACH_INSTANCE_TOMBSTONE item = CONTAINING_RECORD(link,
            STAGE_ATTACH_INSTANCE_TOMBSTONE, Link);
        if (item->Instance == Instance) { found = TRUE; break; }
    }
    StageStreamReleaseSpinLock(&StageAttachLock, irql);
    return found;
}

_Use_decl_annotations_
BOOLEAN SafeUploadStageAttachInstanceRetiring(PFLT_INSTANCE Instance)
{
    return StageAttachIsInstanceTearingDown(Instance);
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadStageAttachInstanceTeardownComplete(_In_ PFLT_INSTANCE Instance)
{
    PLIST_ENTRY link;
    PSTAGE_ATTACH_INSTANCE_TOMBSTONE found = NULL;
    KIRQL irql;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    StageStreamAcquireSpinLock(&StageAttachLock, &irql);
    for (link = StageAttachTearingDownInstances.Flink;
         link != &StageAttachTearingDownInstances; link = link->Flink) {
        PSTAGE_ATTACH_INSTANCE_TOMBSTONE item = CONTAINING_RECORD(link,
            STAGE_ATTACH_INSTANCE_TOMBSTONE, Link);
        if (item->Instance == Instance) {
            RemoveEntryList(&item->Link);
            InitializeListHead(&item->Link);
            found = item;
            break;
        }
    }
    StageStreamReleaseSpinLock(&StageAttachLock, irql);
    if (found != NULL) {
        FltObjectDereference(found->Instance);
        ExFreePoolWithTag(found, STAGE_TAG);
    }
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadStageAttachInstanceTeardownStart(_In_ PFLT_INSTANCE Instance)
{
    PLIST_ENTRY link;
    PSTAGE_ATTACH_INSTANCE_TOMBSTONE tombstone;
    KIRQL irql;
    LARGE_INTEGER interval;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    tombstone = SafeUploadStageMandatoryTeardownActive() ? NULL :
        ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*tombstone), STAGE_TAG);
    if (tombstone != NULL) {
        RtlZeroMemory(tombstone, sizeof(*tombstone));
        InitializeListHead(&tombstone->Link);
        if (NT_SUCCESS(FltObjectReference(Instance))) tombstone->Instance = Instance;
        else { ExFreePoolWithTag(tombstone, STAGE_TAG); tombstone = NULL; }
    }
    StageStreamAcquireSpinLock(&StageAttachLock, &irql);
    {
        BOOLEAN alreadyPresent = FALSE;
        for (link = StageAttachTearingDownInstances.Flink;
             link != &StageAttachTearingDownInstances; link = link->Flink) {
            PSTAGE_ATTACH_INSTANCE_TOMBSTONE item = CONTAINING_RECORD(link,
                STAGE_ATTACH_INSTANCE_TOMBSTONE, Link);
            if (item->Instance == Instance) { alreadyPresent = TRUE; break; }
        }
        if (!alreadyPresent && tombstone != NULL && !SafeUploadStageMandatoryTeardownActive()) {
            InsertTailList(&StageAttachTearingDownInstances, &tombstone->Link);
            tombstone = NULL;
        } else if (!alreadyPresent) {
            StageAttachAccepting = FALSE; /* allocation failure fails closed */
        }
    }
    for (link = StageAttachLookup.Flink; link != &StageAttachLookup; link = link->Flink) {
        PSTAGE_ATTACH_TRANSACTION tx = CONTAINING_RECORD(link,
            STAGE_ATTACH_TRANSACTION, LookupLink);
        if (tx->InstanceIdentity == Instance) {
            InterlockedExchange(&tx->TeardownRequested, 1);
            InterlockedExchange(&tx->CancelRequested, 1);
        }
    }
    StageStreamReleaseSpinLock(&StageAttachLock, irql);
    if (tombstone != NULL) {
        FltObjectDereference(tombstone->Instance);
        ExFreePoolWithTag(tombstone, STAGE_TAG);
    }
    KeSetEvent(&StageAttachQueueEvent, IO_NO_INCREMENT, FALSE);
    /* Instance teardown cannot return while a pended CREATE still owns this
     * instance's stream/view state. The separate worker is not behind the
     * maintenance queue or its unrelated service exchanges. */
    interval.QuadPart = -10 * 1000; /* 1 ms, bounded poll */
    while (StageAttachHasInstance(Instance))
        (VOID)KeDelayExecutionThread(KernelMode, FALSE, &interval);
}

static BOOLEAN StageAttachRetryAllowed(_In_ PSTAGE_ATTACH_TRANSACTION Transaction)
{
    LARGE_INTEGER zero;
    if (Transaction == NULL || Transaction->Stream == NULL ||
        InterlockedCompareExchange(&Transaction->TeardownRequested, 0, 0) != 0 ||
        InterlockedCompareExchange(&Transaction->QueueAborted, 0, 0) != 0 ||
        FltIsIoCanceled(Transaction->CallbackData) ||
        StageAttachIsInstanceTearingDown(Transaction->InstanceIdentity) ||
        !SafeUploadStageProtocolIsReady()) return FALSE;
    zero.QuadPart = 0;
    if (Transaction->RequestorProcess != NULL &&
        KeWaitForSingleObject(Transaction->RequestorProcess, Executive, KernelMode,
            FALSE, &zero) == STATUS_SUCCESS) return FALSE;
    return TRUE;
}

static NTSTATUS StageAttachValidateCurrent(_Inout_ PSTAGE_ATTACH_TRANSACTION Transaction,
    _Inout_ PSTAGE_STREAM Stream)
{
    PSTAGE_VIEW view;
    SAFEUPLOAD_STAGE_IDENTITY_V19 currentParent;
    UNICODE_STRING parent;
    USHORT index;
    NTSTATUS status;
    if (Transaction == NULL || Stream == NULL || Stream->View == NULL ||
        Stream->OriginalInstance == NULL || !Stream->StageIdentityValid ||
        !Stream->HasTransferId || Stream->DestinationGeneration == 0 ||
        !StageV19IdentityEqual(&Stream->StageIdentity, &Stream->ExpectedStageIdentity) ||
        Stream->AllocationParentDirectoryIdentity.VolumeSerialNumber !=
            Stream->View->ParentIdentity.VolumeSerialNumber ||
        !RtlEqualMemory(&Stream->AllocationParentDirectoryIdentity.FileId,
            &Stream->View->ParentIdentity.FileId, sizeof(FILE_ID_128)) ||
        !RtlEqualMemory(&Stream->DriverInstanceId, &Transaction->DriverInstanceId, sizeof(GUID)) ||
        !RtlEqualMemory(&Transaction->DriverInstanceId, &StageDriverInstanceId, sizeof(GUID)))
        return STATUS_INVALID_DEVICE_STATE;

    StageAcquire(&StageNamespaceResource);
    view = Stream->View;
    if (StageStopping || view == NULL || view->Detached || view->Current != Stream ||
        view->Owner != Transaction->RequestorProcess ||
        view->OwnerProcessId != Transaction->RequestorProcessId ||
        view->Generation != Transaction->ExpectedGeneration ||
        Stream->AttachTerminalPending || StageAttachIsInstanceTearingDown(Stream->OriginalInstance)) {
        StageRelease(&StageNamespaceResource);
        return STATUS_DELETE_PENDING;
    }
    StageRelease(&StageNamespaceResource);

    parent = Stream->Name;
    for (index = parent.Length / sizeof(WCHAR); index != 0; --index)
        if (parent.Buffer[index - 1] == L'\\') break;
    if (index == 0) return STATUS_OBJECT_PATH_INVALID;
    parent.Length = (index - 1) * sizeof(WCHAR);
    parent.MaximumLength = parent.Length;
    status = StageQueryNoReparseIdentity(Stream->OriginalInstance, &parent, TRUE, &currentParent);
    if (!NT_SUCCESS(status)) return status;
    if (!StageV19IdentityEqual(&currentParent, &Stream->AllocationParentDirectoryIdentity))
        return STATUS_OBJECT_NAME_COLLISION;

    return STATUS_SUCCESS;
}

static NTSTATUS StageAttachExchangeRetry(_Inout_ PSTAGE_ATTACH_TRANSACTION Transaction,
    _In_ UINT32 Operation, _Inout_ PSAFEUPLOAD_REQUEST Request, _Out_ PUINT32 Result)
{
    PSTAGE_STREAM stream;
    BOOLEAN requestMayExist = FALSE;
    BOOLEAN exactTerminalAllowed = FALSE;
    ULONG persistenceAttempt = 0;
    LARGE_INTEGER persistenceRetryInterval;
    NTSTATUS status;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (Result != NULL) *Result = 0;
    if (SafeUploadStageMandatoryTeardownActive()) return STATUS_PORT_DISCONNECTED;
    if (Transaction == NULL || (stream = Transaction->Stream) == NULL || Request == NULL || Result == NULL)
        return STATUS_INVALID_PARAMETER;
    /* Recorded op15 remains held on cancellation/teardown. The next live
     * owner CREATE drives replay; mandatory teardown never drives an RPC.
     * StageAttachLock is acquired/released by the instance check only; neither
     * that spin lock nor NamespaceResource spans the send below. */
    if (Operation == SAFEUPLOAD_OPERATION_STAGE_ATTACH_COMPLETION_PERMITTED &&
        (InterlockedCompareExchange(&Transaction->CancelRequested, 0, 0) != 0 ||
         !StageAttachRetryAllowed(Transaction))) return STATUS_CANCELLED;
    if (Request->RequestId == 0 && !StageAttachRetryAllowed(Transaction)) {
        /* Cancellation and teardown stop new admission/authorization RPCs,
         * but must not strand a service-side Prepared record or a committed
         * stage whose op15 was provably never sent. These exact terminal
         * operations are safe after local state/identity checks below their
         * callers; they still require the currently reconciled driver epoch. */
        if (Operation == SAFEUPLOAD_OPERATION_STAGE_ATTACH_ABORT &&
            stream->AttachPrepareKnown && !stream->AttachCompletionMayExist &&
            !stream->AttachCompletionKnown &&
            (!stream->AttachCommitKnown ||
             stream->AttachCommitResult == SAFEUPLOAD_STAGE_RESULT_ATTACH_COMMIT_DENIED))
            exactTerminalAllowed = TRUE;
        else if (Operation == SAFEUPLOAD_OPERATION_STAGE_RETIRE_UNEXPOSED &&
            Transaction->UnexposedRetirementAllowed && stream->AttachCommitKnown &&
            stream->AttachCommitResult == SAFEUPLOAD_STAGE_RESULT_ATTACH_COMMITTED &&
            !stream->AttachCompletionMayExist && !stream->AttachCompletionKnown)
            exactTerminalAllowed = TRUE;
        if (!exactTerminalAllowed || !SafeUploadStageProtocolIsReady())
            return InterlockedCompareExchange(&Transaction->TeardownRequested, 0, 0) != 0 ?
                STATUS_VOLUME_DISMOUNTED : STATUS_CANCELLED;
    }
    if (stream->View == NULL) return STATUS_INVALID_DEVICE_STATE;
    for (;;) {
        if (SafeUploadStageMandatoryTeardownActive()) return STATUS_PORT_DISCONNECTED;
        requestMayExist = FALSE;
        *Result = 0;
        status = SafeUploadStageAttachmentExchangeV20(stream->View->OwnerProcessId,
            &stream->Name, Transaction->VolumeKind, Operation, &stream->TransferId,
            stream->DestinationGeneration, &stream->StageIdentity, &Transaction->DriverInstanceId,
            &stream->AllocationParentDirectoryIdentity, Request, Result, &requestMayExist);
        if (requestMayExist) {
            Transaction->ServiceRequestMayExist = TRUE;
            StageAcquire(&StageNamespaceResource);
            if (Operation == SAFEUPLOAD_OPERATION_STAGE_ATTACH_PREPARE)
                stream->AttachPrepareMayExist = TRUE;
            else if (Operation == SAFEUPLOAD_OPERATION_STAGE_ATTACH_COMMIT)
                stream->AttachCommitMayExist = TRUE;
            else if (Operation == SAFEUPLOAD_OPERATION_STAGE_ATTACH_COMPLETION_PERMITTED)
                stream->AttachCompletionMayExist = TRUE;
            StageRelease(&StageNamespaceResource);
        }
        /* Retry only exact private-bookkeeping uncertainty, on this counted
         * CREATE and immutable request. Six exchanges, five waits totalling
         * 620 ms; RPC/storage time is separate. Exhaustion remains held/fails
         * closed through the existing lifecycle. No lock spans the wait. */
        if (status != STATUS_DEVICE_BUSY || *Result != SAFEUPLOAD_STAGE_RESULT_RETRYABLE_FAILURE ||
            (Operation != SAFEUPLOAD_OPERATION_STAGE_ATTACH_COMMIT &&
             Operation != SAFEUPLOAD_OPERATION_STAGE_ATTACH_COMPLETION_PERMITTED) ||
            persistenceAttempt == 5) break;
        if (!StageAttachRetryAllowed(Transaction) ||
            InterlockedCompareExchange(&Transaction->CancelRequested, 0, 0) != 0) return STATUS_CANCELLED;
        persistenceRetryInterval.QuadPart = -(((LONGLONG)20 << persistenceAttempt) * 10 * 1000);
        ++persistenceAttempt;
        (VOID)KeDelayExecutionThread(KernelMode, FALSE, &persistenceRetryInterval);
        if (SafeUploadStageMandatoryTeardownActive()) return STATUS_PORT_DISCONNECTED;
        if (!StageAttachRetryAllowed(Transaction) ||
            InterlockedCompareExchange(&Transaction->CancelRequested, 0, 0) != 0) return STATUS_CANCELLED;
    }
    return status;
}

static NTSTATUS StageAttachRunLifecycle(_Inout_ PSTAGE_ATTACH_TRANSACTION Transaction,
    _Inout_ PSTAGE_STREAM Stream)
{
    UINT32 result = 0;
    BOOLEAN terminalPending;
    BOOLEAN completionKnown;
    NTSTATUS status;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    NT_ASSERT(Stream->AttachLifecycleInFlight);
    StageAcquire(&StageNamespaceResource);
    terminalPending = Stream->AttachTerminalPending;
    completionKnown = Stream->AttachCompletionKnown;
    StageRelease(&StageNamespaceResource);
    if (terminalPending) return STATUS_DELETE_PENDING;
    /* A durable permit does not prove that this new CREATE still binds the
     * same live view/parent. Validate before accepting a cached op15 too. */
    status = StageAttachValidateCurrent(Transaction, Stream);
    if (!NT_SUCCESS(status)) {
        /* A previously prepared intent is still safe to abort if the public
         * name/parent or instance stopped matching before commit. This is a
         * monotonic service transition; if commit may already have won, op14
         * returns AlreadyCommitted and cannot undo it. */
        if (Stream->AttachCommitKnown &&
            Stream->AttachCommitResult == SAFEUPLOAD_STAGE_RESULT_ATTACH_COMMITTED &&
            !Stream->AttachCompletionMayExist && !Stream->AttachCompletionKnown) {
            Transaction->UnexposedRetirementAllowed = TRUE;
        } else if (Stream->AttachPrepareKnown && !Stream->AttachCompletionMayExist &&
            !Stream->AttachCompletionKnown &&
            (!Stream->AttachCommitKnown ||
             Stream->AttachCommitResult == SAFEUPLOAD_STAGE_RESULT_ATTACH_COMMIT_DENIED)) {
            UINT32 abortResult = 0;
            NTSTATUS abortStatus = StageAttachExchangeRetry(Transaction,
                SAFEUPLOAD_OPERATION_STAGE_ATTACH_ABORT, &Stream->AttachAbortRequest,
                &abortResult);
            if (NT_SUCCESS(abortStatus) &&
                abortResult == SAFEUPLOAD_STAGE_RESULT_ATTACH_ABORTED) {
                StageAttachQueueUnattachedAllocation(Stream);
            } else if (NT_SUCCESS(abortStatus) &&
                abortResult == SAFEUPLOAD_STAGE_RESULT_ATTACH_ALREADY_COMMITTED &&
                !Stream->AttachCompletionMayExist && !Stream->AttachCompletionKnown) {
                /* No op15 has ever entered the service in this transaction.
                 * Therefore AlreadyCommitted from op14 resolves only the
                 * op13 race and permits the exact op16 terminal path. */
                StageAcquire(&StageNamespaceResource);
                Stream->AttachCommitKnown = TRUE;
                Stream->AttachCommitResult = SAFEUPLOAD_STAGE_RESULT_ATTACH_COMMITTED;
                StageRelease(&StageNamespaceResource);
                Transaction->UnexposedRetirementAllowed = TRUE;
            }
        }
        return status;
    }
    if (completionKnown) {
        Transaction->CompletionKnown = TRUE;
        return STATUS_SUCCESS;
    }

    if (!Stream->AttachPrepareKnown) {
        status = StageAttachExchangeRetry(Transaction, SAFEUPLOAD_OPERATION_STAGE_ATTACH_PREPARE,
            &Stream->AttachPrepareRequest, &result);
        if (!NT_SUCCESS(status) && Stream->AttachPrepareMayExist &&
            (InterlockedCompareExchange(&Transaction->CancelRequested, 0, 0) != 0 ||
             InterlockedCompareExchange(&Transaction->TeardownRequested, 0, 0) != 0 ||
             FltIsIoCanceled(Transaction->CallbackData))) {
            /* Resolve an exact may-have-committed Prepare before deciding how
             * to retire it. The nonzero RequestId forces a byte-identical
             * replay; it cannot create a second attachment intent. */
            status = StageAttachExchangeRetry(Transaction,
                SAFEUPLOAD_OPERATION_STAGE_ATTACH_PREPARE,
                &Stream->AttachPrepareRequest, &result);
        }
        if (!NT_SUCCESS(status)) {
            /* No Commit or completion permission was sent. A lost Prepare
             * must be durably aborted before kind-5 cleanup, including when
             * it reaches the service after this failed CREATE unwinds. */
            StageAttachQueueUnattachedAllocation(Stream);
            return status;
        }
        if (result != SAFEUPLOAD_STAGE_RESULT_ATTACH_PREPARED) return STATUS_INVALID_BUFFER_SIZE;
        StageAcquire(&StageNamespaceResource);
        Stream->AttachPrepareKnown = TRUE;
        StageRelease(&StageNamespaceResource);
    }

    if (FltIsIoCanceled(Transaction->CallbackData))
        InterlockedExchange(&Transaction->CancelRequested, 1);

    if (InterlockedCompareExchange(&Transaction->CancelRequested, 0, 0) != 0 ||
        InterlockedCompareExchange(&Transaction->TeardownRequested, 0, 0) != 0) {
        status = StageAttachExchangeRetry(Transaction, SAFEUPLOAD_OPERATION_STAGE_ATTACH_ABORT,
            &Stream->AttachAbortRequest, &result);
        if (NT_SUCCESS(status) && result == SAFEUPLOAD_STAGE_RESULT_ATTACH_ABORTED) {
            StageAttachQueueUnattachedAllocation(Stream);
        }
        return NT_SUCCESS(status) ? STATUS_CANCELLED : status;
    }

    if (!Stream->AttachCommitKnown) {
        status = StageAttachValidateCurrent(Transaction, Stream);
        if (!NT_SUCCESS(status)) return status;
        status = StageAttachExchangeRetry(Transaction, SAFEUPLOAD_OPERATION_STAGE_ATTACH_COMMIT,
            &Stream->AttachCommitRequest, &result);
        if (!NT_SUCCESS(status) && Stream->AttachCommitMayExist &&
            (InterlockedCompareExchange(&Transaction->CancelRequested, 0, 0) != 0 ||
             InterlockedCompareExchange(&Transaction->TeardownRequested, 0, 0) != 0 ||
             FltIsIoCanceled(Transaction->CallbackData))) {
            /* Do not issue a new Commit after cancellation. Resolve only the
             * already-entered exact request; the service replays its durable
             * Committed/Denied result without reevaluating policy. */
            status = StageAttachExchangeRetry(Transaction,
                SAFEUPLOAD_OPERATION_STAGE_ATTACH_COMMIT,
                &Stream->AttachCommitRequest, &result);
        }
        if (!NT_SUCCESS(status)) {
            if (!Stream->AttachCommitMayExist ||
                InterlockedCompareExchange(&Transaction->CancelRequested, 0, 0) != 0 ||
                InterlockedCompareExchange(&Transaction->TeardownRequested, 0, 0) != 0 ||
                FltIsIoCanceled(Transaction->CallbackData)) {
                /* Op14 arbitrates an ambiguous op13 without creating a new
                 * approval: Prepared becomes Aborted; Committed returns the
                 * read-only AlreadyCommitted result. Since op15 has not been
                 * attempted, either exact result yields a safe terminal. */
                UINT32 abortResult = 0;
                NTSTATUS abortStatus = StageAttachExchangeRetry(Transaction,
                    SAFEUPLOAD_OPERATION_STAGE_ATTACH_ABORT,
                    &Stream->AttachAbortRequest, &abortResult);
                if (NT_SUCCESS(abortStatus) &&
                    abortResult == SAFEUPLOAD_STAGE_RESULT_ATTACH_ABORTED) {
                    StageAttachQueueUnattachedAllocation(Stream);
                } else if (NT_SUCCESS(abortStatus) &&
                    abortResult == SAFEUPLOAD_STAGE_RESULT_ATTACH_ALREADY_COMMITTED &&
                    !Stream->AttachCompletionMayExist && !Stream->AttachCompletionKnown) {
                    StageAcquire(&StageNamespaceResource);
                    Stream->AttachCommitKnown = TRUE;
                    Stream->AttachCommitResult = SAFEUPLOAD_STAGE_RESULT_ATTACH_COMMITTED;
                    StageRelease(&StageNamespaceResource);
                    Transaction->UnexposedRetirementAllowed = TRUE;
                }
            }
            return status;
        }
        if (result != SAFEUPLOAD_STAGE_RESULT_ATTACH_COMMITTED &&
            result != SAFEUPLOAD_STAGE_RESULT_ATTACH_COMMIT_DENIED &&
            result != SAFEUPLOAD_STAGE_RESULT_ATTACH_ALREADY_COMMITTED)
            return STATUS_INVALID_BUFFER_SIZE;
        StageAcquire(&StageNamespaceResource);
        Stream->AttachCommitKnown = TRUE;
        Stream->AttachCommitResult = result == SAFEUPLOAD_STAGE_RESULT_ATTACH_ALREADY_COMMITTED ?
            SAFEUPLOAD_STAGE_RESULT_ATTACH_COMMITTED : result;
        StageRelease(&StageNamespaceResource);
    }

    if (Stream->AttachCommitResult == SAFEUPLOAD_STAGE_RESULT_ATTACH_COMMIT_DENIED) {
        status = StageAttachExchangeRetry(Transaction, SAFEUPLOAD_OPERATION_STAGE_ATTACH_ABORT,
            &Stream->AttachAbortRequest, &result);
        if (!NT_SUCCESS(status)) return status;
        if (result != SAFEUPLOAD_STAGE_RESULT_ATTACH_ABORTED) return STATUS_INVALID_DEVICE_STATE;
        StageAttachQueueUnattachedAllocation(Stream);
        return STATUS_ACCESS_DENIED;
    }

    /* Resolve cancellation/teardown only after the exact commit result is
     * known. Op16 is eligible only while no op15 request has ever been sent. */
    if (FltIsIoCanceled(Transaction->CallbackData))
        InterlockedExchange(&Transaction->CancelRequested, 1);
    if ((InterlockedCompareExchange(&Transaction->CancelRequested, 0, 0) != 0 ||
         InterlockedCompareExchange(&Transaction->TeardownRequested, 0, 0) != 0 ||
         !NT_SUCCESS(StageAttachValidateCurrent(Transaction, Stream))) &&
        !Stream->AttachCompletionMayExist) {
        Transaction->UnexposedRetirementAllowed = TRUE;
        return InterlockedCompareExchange(&Transaction->TeardownRequested, 0, 0) != 0 ?
            STATUS_VOLUME_DISMOUNTED : STATUS_CANCELLED;
    }

    if (!Stream->AttachCompletionKnown) {
        /* The owner's next live CREATE reuses this recorded request verbatim.
         * A timeout, cancellation or generic DENY never authorizes op16. */
        if (Stream->AttachCompletionMayExist && Stream->AttachCompletionRequest.RequestId == 0)
            return STATUS_INVALID_DEVICE_STATE;
        if (Stream->AttachCompletionRequest.RequestId == 0) {
            status = StageAttachValidateCurrent(Transaction, Stream);
            if (!NT_SUCCESS(status)) {
                Transaction->UnexposedRetirementAllowed = TRUE;
                return status;
            }
        }
        status = StageAttachExchangeRetry(Transaction,
            SAFEUPLOAD_OPERATION_STAGE_ATTACH_COMPLETION_PERMITTED,
            &Stream->AttachCompletionRequest, &result);
        if (!NT_SUCCESS(status)) {
            /* The exchange helper only reports this local gate before it
             * enters FltSendMessage. With no prior op15 ambiguity, that is
             * enough to take the exact op16 path after the binding rolls
             * back. Any sent request sets AttachCompletionMayExist and is
             * never classified as unexposed here. */
            if (!Stream->AttachCompletionMayExist)
                Transaction->UnexposedRetirementAllowed = TRUE;
            StageAcquire(&StageNamespaceResource);
            Stream->DrainStatus = status;
            Stream->Wait = STAGE_WAIT_SERVICE;
            StageRelease(&StageNamespaceResource);
            return status;
        }
        if (result != SAFEUPLOAD_STAGE_RESULT_COMPLETION_PERMITTED)
            return STATUS_INVALID_BUFFER_SIZE;
        StageAcquire(&StageNamespaceResource);
        Stream->AttachCompletionKnown = TRUE;
        Stream->AttachCompletionMayExist = TRUE;
        StageRelease(&StageNamespaceResource);
    }
    Transaction->CompletionKnown = TRUE;
    return STATUS_SUCCESS;
}

static VOID StageAttachRollbackBinding(_Inout_ PSTAGE_ATTACH_TRANSACTION Transaction,
    _Inout_ PSTAGE_STREAM Stream)
{
    PFILE_OBJECT file;
    PSTAGE_HANDLE handle;
    BOOLEAN last = FALSE;
    KIRQL irql;
    if (Transaction == NULL || Stream == NULL || Transaction->RelatedObjects.FileObject == NULL) return;
    file = Transaction->RelatedObjects.FileObject;
    handle = file->FsContext2;
    if (handle == NULL || handle->Stream != Stream) {
        Transaction->BindingInstalled = FALSE;
        return;
    }
    StageAcquire(&StageNamespaceResource);
    StageAcquire(&Stream->Resource);
    if (!handle->Cleaned) {
        IoRemoveShareAccess(file, &Stream->ShareAccess);
        if (handle->DeleteOnClose) {
            if (Stream->DeleteOnCloseCount != 0) --Stream->DeleteOnCloseCount;
            handle->DeleteOnClose = FALSE;
        }
        Stream->DiscardOnClose = Stream->DiscardDisposition || Stream->DeleteOnCloseCount != 0;
        handle->Cleaned = TRUE;
        (VOID)CcUninitializeCacheMap(file, NULL, NULL);
    }
    file->FsContext = NULL;
    file->FsContext2 = NULL;
    file->SectionObjectPointer = NULL;
    StageRelease(&Stream->Resource);
    StageStreamAcquireSpinLock(&StageListLock, &irql);
    if (InterlockedCompareExchange(&Stream->FileObjects, 0, 0) > 0) {
        last = InterlockedDecrement(&Stream->FileObjects) == 0;
        InterlockedDecrement(&StageFileObjects);
    } else {
        NT_ASSERT(FALSE);
    }
    StageStreamReleaseSpinLock(&StageListLock, irql);
    StageRelease(&StageNamespaceResource);
    SafeUploadStageNativeCloseWriter(Stream->OriginalInstance, file);
    SafeUploadStagePublicReleaseWriter(handle->WriterLease);
    handle->WriterLease = NULL;
    ExFreePoolWithTag(handle, STAGE_TAG);
    Transaction->BindingInstalled = FALSE;
    if (last) StageQueueStream(Stream, &StageCounters.WakeClose);
}

static VOID StageAttachQueueUnattachedAllocation(_Inout_ PSTAGE_STREAM Stream)
{
    if (Stream == NULL) return;
    StageAcquire(&StageNamespaceResource);
    if (!Stream->HasTransferId || !Stream->StageIdentityValid ||
        Stream->DestinationGeneration == 0 ||
        Stream->AttachCompletionMayExist || Stream->AttachCompletionKnown) {
        StageRelease(&StageNamespaceResource);
        return;
    }
    Stream->AttachTerminalPending = TRUE;
    Stream->AttachCompletionPending = FALSE;
    Stream->AllocationReceiptPending = TRUE;
    Stream->AllocationTupleKnown = TRUE;
    Stream->AllocationRecoveryPending = FALSE;
    Stream->DiscardRpcKind = SAFEUPLOAD_STAGE_DISCARD_KIND_UNATTACHED_ALLOCATION;
    Stream->DiscardRpcPending = FALSE; /* StageProcessStream queues only after local detach/close */
    Stream->Wait = STAGE_WAIT_EXCHANGE;
    StageQueueStream(Stream, &StageCounters.WakeInline);
    StageRelease(&StageNamespaceResource);
}

static NTSTATUS StageAttachRetireUnexposed(_Inout_ PSTAGE_ATTACH_TRANSACTION Transaction,
    _Inout_ PSTAGE_STREAM Stream)
{
    UINT32 result = 0;
    NTSTATUS status;
    PSTAGE_STREAM parent;
    if (SafeUploadStageMandatoryTeardownActive()) return STATUS_PORT_DISCONNECTED;
    if (Transaction == NULL || Stream == NULL || !Transaction->UnexposedRetirementAllowed)
        return STATUS_INVALID_DEVICE_STATE;
    StageAcquire(&StageNamespaceResource);
    if (Stream->AttachCompletionMayExist || !Stream->AttachCommitKnown ||
        Stream->AttachCommitResult != SAFEUPLOAD_STAGE_RESULT_ATTACH_COMMITTED ||
        Stream->View == NULL || Stream->View->Current != Stream ||
        InterlockedCompareExchange(&Stream->FileObjects, 0, 0) != 0) {
        StageRelease(&StageNamespaceResource);
        return STATUS_DEVICE_BUSY;
    }
    StageAcquire(&Stream->Resource);
    if (Stream->ShareAccess.OpenCount != 0 || Stream->Sections.SharedCacheMap != NULL ||
        Stream->Sections.DataSectionObject != NULL || Stream->Sections.ImageSectionObject != NULL) {
        StageRelease(&Stream->Resource);
        StageRelease(&StageNamespaceResource);
        return STATUS_DEVICE_BUSY;
    }
    StageCloseBacking(Stream); /* exact op16 must observe the object absent, not merely delete-pending */
    StageRelease(&Stream->Resource);
    Stream->AttachRetirePending = TRUE;
    StageRelease(&StageNamespaceResource);
    status = StageAttachExchangeRetry(Transaction, SAFEUPLOAD_OPERATION_STAGE_RETIRE_UNEXPOSED,
        &Stream->AttachRetireRequest, &result);
    if (!NT_SUCCESS(status)) return status;
    if (result != SAFEUPLOAD_STAGE_RESULT_ATTACH_RETIRED_UNEXPOSED)
        return STATUS_INVALID_BUFFER_SIZE;

    StageAcquire(&StageNamespaceResource);
    Stream->Discarded = TRUE;
    Stream->Sealed = TRUE;
    Stream->Retired = TRUE;
    Stream->AttachTerminalPending = FALSE;
    Stream->AttachRetirePending = FALSE;
    Stream->AttachCompletionPending = FALSE;
    Stream->AllocationReceiptPending = FALSE;
    Stream->AllocationRecoveryPending = FALSE;
    Stream->AllocationTupleKnown = FALSE;
    if (Stream->ReservationLinked) StageRemoveAllocationNameReservation(Stream);
    StageClearPrivateDelete(Stream);
    if (Stream->View != NULL && Stream->View->Current == Stream) Stream->View->Detached = TRUE;
    parent = Stream->AllocationReceiptParent;
    if (parent != NULL) {
        if (parent->AllocationReceiptReferences != 0) --parent->AllocationReceiptReferences;
        Stream->AllocationReceiptParent = NULL;
    }
    RtlZeroMemory(&Stream->AllocationIntent, sizeof(Stream->AllocationIntent));
    RtlZeroMemory(&Stream->AllocationRequest, sizeof(Stream->AllocationRequest));
    StageQueueStream(Stream, &StageCounters.WakeInline);
    StageRelease(&StageNamespaceResource);
    return STATUS_SUCCESS;
}

static NTSTATUS StageAttachResumeOrRun(_Inout_ PSTAGE_ATTACH_TRANSACTION Transaction,
    _Out_ PBOOLEAN NewBinding)
{
    PFILE_OBJECT file = Transaction->RelatedObjects.FileObject;
    PSTAGE_STREAM stream;
    BOOLEAN handled = TRUE;
    NTSTATUS status;
    if (NewBinding != NULL) *NewBinding = FALSE;
    if (Transaction == NULL || NewBinding == NULL || file == NULL ||
        Transaction->NameInfo == NULL) return STATUS_INVALID_PARAMETER;
    if (InterlockedCompareExchange(&Transaction->CancelRequested, 0, 0) != 0 ||
        InterlockedCompareExchange(&Transaction->TeardownRequested, 0, 0) != 0)
        return STATUS_CANCELLED;

    StageAcquire(&StageNamespaceResource);
    {
        PSTAGE_VIEW view = Transaction->ById ?
            StageFindId(Transaction->RequestorProcess, Transaction->RelatedObjects.Instance,
                &Transaction->NameInfo->Name) :
            StageFindView(Transaction->RequestorProcess, &Transaction->NameInfo->Name);
        PSTAGE_STREAM current = view != NULL ? view->Current : NULL;
        if (current != NULL && current->AttachRetirePending) {
            InterlockedIncrement(&current->RpcReferences);
            Transaction->Stream = current;
            Transaction->UnexposedRetirementAllowed = current->AttachCommitKnown &&
                current->AttachCommitResult == SAFEUPLOAD_STAGE_RESULT_ATTACH_COMMITTED &&
                !current->AttachCompletionMayExist;
        } else if (current != NULL && current->AttachTerminalPending) {
            status = STATUS_DELETE_PENDING;
            if (current->AllocationReceiptPending &&
                !current->AttachCompletionMayExist && !current->AttachCompletionKnown)
                status = STATUS_SHARING_VIOLATION;
            StageRelease(&StageNamespaceResource);
            return status;
        }
    }
    StageRelease(&StageNamespaceResource);
    if (Transaction->Stream != NULL) {
        /* The pin taken above is the transaction's: StageAttachDrainTransaction
         * releases it exactly once (and requeues at zero). Releasing it here
         * as well drove RpcReferences to -1, so the stream could never be
         * retired and mandatory teardown waited forever. One op16 attempt per
         * transaction: a failed one stays AttachRetirePending for the next
         * CREATE, and the drain must not resend op16 for a retired stream. */
        status = StageAttachRetireUnexposed(Transaction, Transaction->Stream);
        Transaction->UnexposedRetirementAllowed = FALSE;
        return NT_SUCCESS(status) ? STATUS_DELETE_PENDING : status;
    }

    if (SafeUploadStageProtocolBoundAllocationReady()) {
        SAFEUPLOAD_STAGE_WRITER_REFUSAL reason;
        SAFEUPLOAD_STAGE_PUBLIC_BINDING binding;
        if (!Transaction->OriginalSubjectValid || Transaction->VolumeKind != SafeUploadVolumeFixed)
            return STATUS_DEVICE_NOT_READY;
        status = SafeUploadStagePublicOpenWriter(Transaction->RelatedObjects.Instance,
            &Transaction->CreateInput, &Transaction->OriginalSubject, Transaction->RequestorProcess,
            &Transaction->WriterLease, &reason);
        if (status != STATUS_SUCCESS) return status;
        SafeUploadStagePublicGetWriterBinding(Transaction->WriterLease, &binding);
        Transaction->WriterGrantedAccess = binding.GrantedAccess;
    }

    status = StageCreate(Transaction->CallbackData, &Transaction->RelatedObjects,
        Transaction->NameInfo, Transaction->VolumeKind, TRUE,
        Transaction->ExpectedGeneration, Transaction->ById,
        Transaction->PrivateNamespace, TRUE, Transaction, &handled);
    if (!handled && NT_SUCCESS(status)) return STATUS_ACCESS_DENIED;
    if (status == STAGE_STATUS_READMIT) return STATUS_SHARING_VIOLATION;
    if (!NT_SUCCESS(status)) return status;
    StageAcquire(&StageNamespaceResource);
    stream = StageStreamForObject(file);
    if (stream == NULL) {
        StageRelease(&StageNamespaceResource);
        return STATUS_INVALID_DEVICE_STATE;
    }
    Transaction->Stream = stream;
    if (stream->View != NULL) Transaction->ExpectedGeneration = stream->View->Generation;
    Transaction->BindingInstalled = TRUE;
    InterlockedIncrement(&stream->RpcReferences);
    if (stream->AttachAcknowledged && !stream->AttachCompletionPending) {
        StageRelease(&StageNamespaceResource);
        return STATUS_SUCCESS; /* ordinary writer open on a previously attached version */
    }
    if (!stream->AttachCompletionPending) {
        StageRelease(&StageNamespaceResource);
        return STATUS_INVALID_DEVICE_STATE;
    }
    Transaction->NeedsAttachCommit = TRUE;
    *NewBinding = TRUE;
    StageRelease(&StageNamespaceResource);
    return StageAttachRunLifecycle(Transaction, stream);
}

static BOOLEAN StageAttachNativeEligible(PFLT_CALLBACK_DATA Data)
{
    ACCESS_MASK access;
    if (Data->Iopb->Parameters.Create.SecurityContext == NULL) return FALSE;
    access = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    return (Data->Iopb->Parameters.Create.Options >> 24) == FILE_OPEN && FlagOn(access, DELETE) &&
        !FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE | FILE_OPEN_BY_FILE_ID | FILE_OPEN_REPARSE_POINT) &&
        !FlagOn(access, FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
            FILE_DELETE_CHILD | GENERIC_WRITE | GENERIC_ALL | MAXIMUM_ALLOWED) &&
        !(FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE) && FlagOn(access, FILE_WRITE_ATTRIBUTES));
}

static NTSTATUS StageAttachExchangeNative(PSTAGE_ATTACH_TRANSACTION Transaction)
{
    PSAFEUPLOAD_STAGE_NATIVE_SNAPSHOT snapshot = &Transaction->NativeSnapshot;
    SAFEUPLOAD_NATIVE_LIFECYCLE_REPLY reply;
    UINT64 attemptedRevision = 0;
    NTSTATUS status = STATUS_DEVICE_NOT_READY;
    /* A queued CREATE has not reached NTFS. Do not let its admission epoch
     * prevent the publisher ahead of it from draining the namespace gate. */
    SafeUploadPolicyAdmissionRelease(Transaction->AdmissionToken);
    Transaction->AdmissionToken = NULL;
    for (;;) {
        if (FltIsIoCanceled(Transaction->CallbackData) ||
            InterlockedCompareExchange(&Transaction->CancelRequested, 0, 0) != 0 ||
            InterlockedCompareExchange(&Transaction->TeardownRequested, 0, 0) != 0)
            return STATUS_CANCELLED;
        {
            NTSTATUS readStatus = SafeUploadStageNativeSnapshot(Transaction->NativeRecord,
                snapshot, &Transaction->NativePrepareRevision);
            if (!NT_SUCCESS(readStatus)) return readStatus;
        }
        if (snapshot->Forwarded || snapshot->CreateOutcomeKnown || snapshot->CleanupCoverageLost)
            return STATUS_INVALID_DEVICE_STATE;
        if (attemptedRevision == Transaction->NativePrepareRevision) return status;
        attemptedRevision = Transaction->NativePrepareRevision;
        if (Transaction->OrdinaryPublicOpen) {
            status = SafeUploadStagePublicOpenExchange(snapshot, attemptedRevision, SAFEUPLOAD_PUBLIC_OPEN_PREPARE,
                &Transaction->PublicOpenReceipt, &Transaction->NativePrepareAuthority);
            if (status == STATUS_SUCCESS) {
                Transaction->NativeGeneration = 0;
                return SafeUploadPolicyAdmissionAcquire(&Transaction->AdmissionToken);
            }
        } else {
            status = SafeUploadStageNativeExchange(snapshot, attemptedRevision, SAFEUPLOAD_NATIVE_PREPARE,
                &reply, &Transaction->NativePrepareAuthority);
            if (status == STATUS_SUCCESS) {
                Transaction->NativeGeneration = reply.JournalGeneration;
                return SafeUploadPolicyAdmissionAcquire(&Transaction->AdmissionToken);
            }
        }
        /* Retry only after a real map event changed the snapshot. The exact
         * transfer/nonce/operation replays its durable intent at the new revision. */
    }
}

static NTSTATUS StageAttachPrepareNative(PSTAGE_ATTACH_TRANSACTION Transaction)
{
    SAFEUPLOAD_STAGE_NATIVE_BINDING binding;
    PVOID cookie;
    LONG64 epoch;
    ULONG servicePid;
    NTSTATUS status;
    RtlZeroMemory(&binding, sizeof(binding));
    Transaction->NativePath = TRUE;
    Transaction->OrdinaryPublicOpen = !FlagOn(Transaction->CreateInput.Options, FILE_DELETE_ON_CLOSE);
    if (!Transaction->OriginalSubjectValid ||
        !SafeUploadConnectionGetAuthenticatedIdentity(NULL, &cookie, &epoch, &servicePid) ||
        !SafeUploadStageProtocolNativeForwardAllowed((UINT64)epoch, 0)) return STATUS_DEVICE_NOT_READY;
    binding.DriverInstanceId = Transaction->DriverInstanceId;
    binding.ConnectionEpoch = (UINT64)epoch;
    binding.OsBootSequence = SharedUserData->BootId;
    binding.CreateOptions = Transaction->CreateInput.Options;
    status = ExUuidCreate(&binding.TransferId);
    if (!NT_SUCCESS(status)) return status;
    status = ExUuidCreate(&binding.RequestNonce);
    if (!NT_SUCCESS(status)) return status;
    status = ExUuidCreate(&binding.OperationId);
    if (!NT_SUCCESS(status)) return status;
    status = SafeUploadStagePublicCaptureNativeName(Transaction->RelatedObjects.Instance, Transaction->NameInfo,
        &Transaction->OriginalSubject, Transaction->RequestorProcess,
        Transaction->CreateInput.DesiredAccess,
        Transaction->CreateInput.ShareAccess, binding.CreateOptions, &binding.Public);
    if (!NT_SUCCESS(status)) return status;
    status = SafeUploadStageNativeReserve(Transaction->RelatedObjects.Instance,
        Transaction->RelatedObjects.FileObject, &binding, &Transaction->NativeRecord);
    if (!NT_SUCCESS(status)) return status;
    return StageAttachExchangeNative(Transaction);
}

static NTSTATUS StageAttachWorkerBody(_Inout_ PSTAGE_ATTACH_TRANSACTION Transaction)
{
    BOOLEAN newBinding = FALSE;
    NTSTATUS status;
    if (!Transaction->PrivateNamespace && !Transaction->ById && Transaction->VolumeKind == SafeUploadVolumeFixed &&
        Transaction->CreateInput.NativeEligible && SafeUploadStageProtocolNativeForwardAllowed(0, 0)) {
        BOOLEAN ownerView;
        StageAcquire(&StageNamespaceResource);
        ownerView = StageFindView(Transaction->RequestorProcess, &Transaction->NameInfo->Name) != NULL;
        StageRelease(&StageNamespaceResource);
        if (!ownerView) return StageAttachPrepareNative(Transaction);
    }
    status = StageAttachResumeOrRun(Transaction, &newBinding);
    Transaction->NeedsAttachCommit = Transaction->NeedsAttachCommit || newBinding;
    return status;
}

/* Retire only the callback-data lookup key before Filter Manager can reuse its
 * address. The lookup entry and its teardown/accounting owners remain linked
 * until the existing final drain. Cancellation has already been disarmed/joined. */
static VOID StageAttachFinishCallback(_Inout_ PSTAGE_ATTACH_TRANSACTION Transaction,
    _In_ FLT_PREOP_CALLBACK_STATUS Result, _In_opt_ PVOID Context)
{
    PFLT_CALLBACK_DATA data;
    KIRQL irql;
    NT_ASSERT(!Transaction->CancelRegistered);
    StageStreamAcquireSpinLock(&StageAttachLock, &irql);
    data = Transaction->CallbackData;
    Transaction->CallbackData = NULL;
    StageStreamReleaseSpinLock(&StageAttachLock, irql);
    NT_ASSERT(data != NULL);
    FltCompletePendedPreOperation(data, Result, Context);
}

static VOID StageAttachComplete(_Inout_ PSTAGE_ATTACH_TRANSACTION Transaction, _In_ NTSTATUS Status)
{
    NTSTATUS clearStatus = STATUS_SUCCESS;
    BOOLEAN cancelled;
    PSTAGE_STREAM stream;
    if (Transaction == NULL ||
        InterlockedCompareExchange(&Transaction->CompletionClaimed, 1, 0) != 0) return;
    Transaction->WorkerOwnsCompletion = TRUE;
    if (Transaction->CancelRegistered) {
        clearStatus = FltClearCancelCompletion(Transaction->CallbackData);
        if (clearStatus == STATUS_CANCELLED) {
            KeWaitForSingleObject(&Transaction->CancelCallbackExited,
                Executive, KernelMode, FALSE, NULL);
        } else if (!NT_SUCCESS(clearStatus)) {
            InterlockedExchange(&Transaction->CancelRequested, 1);
        }
        Transaction->CancelRegistered = FALSE;
    }
    cancelled = SafeUploadStageMandatoryTeardownActive() ||
        clearStatus != STATUS_SUCCESS || FltIsIoCanceled(Transaction->CallbackData) ||
        InterlockedCompareExchange(&Transaction->CancelRequested, 0, 0) != 0 ||
        InterlockedCompareExchange(&Transaction->TeardownRequested, 0, 0) != 0 ||
        StageAttachIsInstanceTearingDown(Transaction->InstanceIdentity);
    stream = Transaction->Stream;
    if (NT_SUCCESS(Status) && cancelled) Status = STATUS_CANCELLED;

    if (NT_SUCCESS(Status) && Transaction->NeedsAttachCommit && stream != NULL) {
        StageAcquire(&StageNamespaceResource);
        if (stream->View == NULL || stream->View->Current != stream || stream->View->Detached ||
            !stream->AttachCompletionKnown || stream->AttachTerminalPending || StageStopping ||
            SafeUploadStageMandatoryTeardownActive()) {
            Status = STATUS_DELETE_PENDING;
        } else {
            stream->AttachAcknowledged = TRUE;
            stream->AttachCompletionPending = FALSE;
            stream->AttachCompletionFence = TRUE;
            stream->AttachCompletionMayExist = TRUE;
            stream->AllocationRecoveryPending = FALSE;
            stream->AllocationRecoveryInFlight = FALSE;
            stream->AllocationReceiptPending = FALSE;
            stream->AllocationTupleKnown = FALSE;
            if (stream->ReservationLinked) StageRemoveAllocationNameReservation(stream);
            if (stream->AllocationReceiptParent != NULL) {
                PSTAGE_STREAM parent = stream->AllocationReceiptParent;
                if (parent->AllocationReceiptReferences != 0) --parent->AllocationReceiptReferences;
                stream->AllocationReceiptParent = NULL;
                StageQueueStream(parent, &StageCounters.WakeInline);
            }
        }
        StageRelease(&StageNamespaceResource);
    }
    if (!NT_SUCCESS(Status) && Transaction->BindingInstalled && stream != NULL)
        StageAttachRollbackBinding(Transaction, stream);

    /* Filter Manager permits completion before the pre-op callback returns;
     * the producer reference and this event keep the transaction alive across
     * that race. NULL is required for FLT_PREOP_COMPLETE. */
    KeWaitForSingleObject(&Transaction->PreOpReturnEvent,
        Executive, KernelMode, FALSE, NULL);
    if (Transaction->NativePath) {
        PSAFEUPLOAD_STAGE_NATIVE_RECORD record = Transaction->NativeRecord;
        while (NT_SUCCESS(Status)) {
            StageAcquire(&StageNamespaceResource);
            if (StageStopping || SafeUploadPolicyAdmissionMustRetry() || FltIsIoCanceled(Transaction->CallbackData) ||
                InterlockedCompareExchange(&Transaction->CancelRequested, 0, 0) != 0 ||
                InterlockedCompareExchange(&Transaction->TeardownRequested, 0, 0) != 0 ||
                StageFindView(Transaction->RequestorProcess, &Transaction->NameInfo->Name) != NULL)
                Status = STATUS_CANCELLED;
            else Status = SafeUploadStageNativeMarkForwarded(record,
                Transaction->NativeGeneration, Transaction->NativePrepareRevision, Transaction->NativePrepareAuthority,
                Transaction->OrdinaryPublicOpen ? &Transaction->PublicOpenReceipt : NULL);
            StageRelease(&StageNamespaceResource);
            if (Status != STATUS_RETRY) break;
            Status = StageAttachExchangeNative(Transaction); /* I/O is outside NamespaceResource. */
        }
        Transaction->NativeRecord = NULL;
        if (NT_SUCCESS(Status)) {
            /* Pending I/O owns the original object. Drop our extra reference
             * before forwarding so an upper-filter cancellation can reach CLOSE. */
            ObDereferenceObject(Transaction->ReferencedFileObject);
            Transaction->ReferencedFileObject = NULL;
            StageAttachFinishCallback(Transaction, FLT_PREOP_SUCCESS_WITH_CALLBACK, record);
        } else {
            BOOLEAN nativeReadFallback = FALSE;
            if (record != NULL) {
                (VOID)SafeUploadStageNativeMarkNotForwarded(record);
                SafeUploadStageNativeReleaseRecord(record);
            }
            if (Transaction->OrdinaryPublicOpen && !cancelled) {
                StageAcquire(&StageNamespaceResource);
                nativeReadFallback = !StageStopping && !SafeUploadStageMandatoryTeardownActive() &&
                    !StageFindView(Transaction->RequestorProcess, &Transaction->NameInfo->Name) &&
                    !StageAttachIsInstanceTearingDown(Transaction->InstanceIdentity);
                StageRelease(&StageNamespaceResource);
            }
            if (nativeReadFallback) {
                /* Failed metadata tracking cannot invent a failed ordinary
                 * read open. Forward the original CREATE without disposition
                 * authority; a later mutation requires exact automatic rebind.
                 * The negative reservation receipt stays for lease release. */
                StageAttachFinishCallback(Transaction, FLT_PREOP_SUCCESS_NO_CALLBACK, NULL);
                goto CompletionFinished;
            }
            Transaction->CallbackData->IoStatus.Status = Status;
            Transaction->CallbackData->IoStatus.Information = 0;
            StageAttachFinishCallback(Transaction, FLT_PREOP_COMPLETE, NULL);
        }
        goto CompletionFinished;
    }
    if (NT_SUCCESS(Status) && stream != NULL && stream->BoundAllocation) {
        PSTAGE_HANDLE handle = Transaction->RelatedObjects.FileObject->FsContext2;
        SAFEUPLOAD_STAGE_WRITER_REFUSAL reason;
        if (handle == NULL || handle->WriterLease == NULL || !StageBoundSeedReady(stream))
            Status = STATUS_DEVICE_NOT_READY;
        else {
            Status = SafeUploadStagePublicRevalidateWriter(handle->WriterLease, &reason);
            if (Status == STATUS_SUCCESS)
                Status = SafeUploadStagePublicWriterMetadataCurrent(handle->WriterLease, &reason);
            if (Status == STATUS_SUCCESS && FlagOn(handle->GrantedAccess, DELETE)) {
                SafeUploadPolicyAdmissionRelease(Transaction->AdmissionToken);
                Transaction->AdmissionToken = NULL;
                Status = SafeUploadStageNativeBindWriter(Transaction->RelatedObjects.Instance,
                    Transaction->RelatedObjects.FileObject, handle->WriterLease);
                if (Status == STATUS_SUCCESS) Status = SafeUploadPolicyAdmissionAcquire(&Transaction->AdmissionToken);
                if (Status == STATUS_SUCCESS && SafeUploadPolicyAdmissionMustRetry()) Status = STATUS_DEVICE_NOT_READY;
            }
        }
        StageAcquire(&StageNamespaceResource);
        if (NT_SUCCESS(Status) && (stream->View == NULL || stream->View->Current != stream ||
            stream->View->Detached || stream->View->Generation != Transaction->ExpectedGeneration ||
            StageStopping || FltIsIoCanceled(Transaction->CallbackData) ||
            InterlockedCompareExchange(&Transaction->CancelRequested, 0, 0) != 0 ||
            InterlockedCompareExchange(&Transaction->TeardownRequested, 0, 0) != 0 ||
            stream->SeedCompletion.AuthorityRevision != SafeUploadStageProtocolNativeAuthority()))
            Status = STATUS_CANCELLED;
        StageRelease(&StageNamespaceResource);
    }
    if (NT_SUCCESS(Status)) {
        KIRQL irql;
        /* Serialize the last staged success decision, including an ordinary
         * reopen without a new attachment ACK, with the permanent fence.
         * A success claimed first already owns its counted FILE_OBJECT;
         * teardown drains it even if completion returns after the fence. */
        StageStreamAcquireSpinLock(&StageAttachLock, &irql);
        if (SafeUploadStageMandatoryTeardownActive()) Status = STATUS_CANCELLED;
        else InterlockedExchange(&Transaction->ExposeClaimed, 1);
        StageStreamReleaseSpinLock(&StageAttachLock, irql);
    }
    if (!NT_SUCCESS(Status) && Transaction->BindingInstalled && stream != NULL)
        StageAttachRollbackBinding(Transaction, stream);
    Transaction->CallbackData->IoStatus.Status = Status;
    if (!NT_SUCCESS(Status)) Transaction->CallbackData->IoStatus.Information = 0;
    StageAttachFinishCallback(Transaction, FLT_PREOP_COMPLETE, NULL);

    if (NT_SUCCESS(Status) && Transaction->NeedsAttachCommit && stream != NULL) {
        StageAcquire(&StageNamespaceResource);
        stream->AttachCompletionFence = FALSE;
        /* The allocation-only name reservation (StageReserveAllocationName)
         * ends once the exact allocation is attached. Left set, it answered
         * every other process's open of the name with DELETE_PENDING and
         * parked the worker before seal (m2t5boot8). A real delete-on-close
         * or discard keeps its reservation; failed or ambiguous attachments
         * never reach this block. Requeue so a parked worker resumes. */
        if (!stream->DiscardOnClose && !stream->Discarded) StageClearPrivateDelete(stream);
        StageQueueStream(stream, &StageCounters.WakeInline);
        StageRelease(&StageNamespaceResource);
    }
CompletionFinished:
    if (Transaction->AdmissionToken != NULL) {
        SafeUploadPolicyAdmissionRelease(Transaction->AdmissionToken);
        Transaction->AdmissionToken = NULL;
    }
    KeSetEvent(&Transaction->Completed, IO_NO_INCREMENT, FALSE);
}

static VOID StageAttachDrainTransaction(_Inout_ PSTAGE_ATTACH_TRANSACTION Transaction)
{
    NTSTATUS status;
    BOOLEAN lookupRemoved;
    if (Transaction == NULL) return;
    status = StageAttachWorkerBody(Transaction);
    if (!NT_SUCCESS(status) && Transaction->BindingInstalled && Transaction->Stream != NULL) {
        StageAttachRollbackBinding(Transaction, Transaction->Stream);
    }
    if (!SafeUploadStageMandatoryTeardownActive() &&
        !NT_SUCCESS(status) && Transaction->UnexposedRetirementAllowed &&
        Transaction->Stream != NULL) {
        /* The binding must be gone before op16 can claim exact absence. A
         * failed op16 leaves the stage private and replayable, never kind-5. */
        (VOID)StageAttachRetireUnexposed(Transaction, Transaction->Stream);
    }
    StageAttachComplete(Transaction, status);
    if (Transaction->Stream != NULL) {
        StageAcquire(&StageNamespaceResource);
        /* Completion/rollback has finished before relinquishing this claim.
         * NamespaceResource then StageListLock (queue); no wait under either. */
        Transaction->Stream->AttachLifecycleInFlight = FALSE;
        if (Transaction->Stream->AttachCompletionPending || Transaction->Stream->AttachCompletionFence) {
            Transaction->Stream->DrainStatus = NT_SUCCESS(status) ? STATUS_CANCELLED : status;
            Transaction->Stream->Wait = STAGE_WAIT_SERVICE;
        }
        if (InterlockedDecrement(&Transaction->Stream->RpcReferences) == 0)
            StageQueueStream(Transaction->Stream, &StageCounters.WakeInline);
        StageRelease(&StageNamespaceResource);
        Transaction->Stream = NULL;
    }
    StageAttachReleaseRelatedObjects(Transaction);
    lookupRemoved = StageAttachRemoveLookup(Transaction);
    StageAttachTransactionDereference(Transaction); /* queue/worker reference; releases instance pins */
    if (lookupRemoved) StageAttachReleaseActive();
}

static VOID StageAttachWorkerThread(_In_ PVOID Context)
{
    PVOID objects[2];
    UNREFERENCED_PARAMETER(Context);
    objects[0] = &StageAttachThreadStop;
    objects[1] = &StageAttachQueueEvent;
    for (;;) {
        NTSTATUS wait = KeWaitForMultipleObjects(2, objects, WaitAny,
            Executive, KernelMode, FALSE, NULL, NULL);
        for (;;) {
            PSTAGE_ATTACH_TRANSACTION transaction = NULL;
            KIRQL irql;
            StageStreamAcquireSpinLock(&StageAttachLock, &irql);
            if (!IsListEmpty(&StageAttachQueue)) {
                transaction = CONTAINING_RECORD(RemoveHeadList(&StageAttachQueue),
                    STAGE_ATTACH_TRANSACTION, QueueLink);
                InitializeListHead(&transaction->QueueLink);
                transaction->WorkItemQueued = FALSE;
            }
            StageStreamReleaseSpinLock(&StageAttachLock, irql);
            if (transaction == NULL) break;
            KeWaitForSingleObject(&transaction->PreOpReturnEvent,
                Executive, KernelMode, FALSE, NULL);
            StageAttachDrainTransaction(transaction);
        }
        if (wait == STATUS_WAIT_0) {
            BOOLEAN empty;
            KIRQL irql;
            StageStreamAcquireSpinLock(&StageAttachLock, &irql);
            empty = IsListEmpty(&StageAttachQueue);
            StageStreamReleaseSpinLock(&StageAttachLock, irql);
            if (empty) break;
        }
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}
#endif


/* Materialize the extended range with ordinary noncached backing writes.
 * Paging writes do not advance NTFS's valid data length. Claiming a larger
 * upper VDL without zeroing could expose old disk contents when Cc advances it.
 * Preserve an existing partial sector; the backing has no second data cache.
 * Backing I/O only: the caller drained the upper cache with StageFlushUpper. */
static NTSTATUS StageZeroGrowth(PSTAGE_STREAM Stream, LARGE_INTEGER Size)
{
    PVOID buffer;
    LARGE_INTEGER offset;
    LONGLONG rounded = (Size.QuadPart + Stream->SectorSize - 1) & ~((LONGLONG)Stream->SectorSize - 1);
    ULONG length, transferred, tail;
    NTSTATUS status;
    if (Size.QuadPart <= Stream->Header.FileSize.QuadPart) return STATUS_SUCCESS;
    status = FltFlushBuffers(Stream->BackingInstance, Stream->BackingObject);
    if (!NT_SUCCESS(status)) return status;
    buffer = FltAllocatePoolAlignedWithTag(Stream->BackingInstance, NonPagedPoolNx, 65536, STAGE_TAG);
    if (buffer == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(buffer, 65536);
    offset.QuadPart = Stream->Header.FileSize.QuadPart & ~((LONGLONG)Stream->SectorSize - 1);
    tail = (ULONG)(Stream->Header.FileSize.QuadPart - offset.QuadPart);
    if (tail != 0) {
        status = FltReadFile(Stream->BackingInstance, Stream->BackingObject, &offset,
            Stream->SectorSize, buffer, FLTFL_IO_OPERATION_NON_CACHED |
            FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, &transferred, NULL, NULL);
        if (!NT_SUCCESS(status) || transferred < tail) {
            if (NT_SUCCESS(status)) status = STATUS_UNEXPECTED_IO_ERROR;
            goto Exit;
        }
        RtlZeroMemory((PUCHAR)buffer + tail, 65536 - tail);
    }
    while (offset.QuadPart < rounded) {
        length = (ULONG)min(65536LL, rounded - offset.QuadPart);
        status = FltWriteFile(Stream->BackingInstance, Stream->BackingObject, &offset,
            length, buffer, FLTFL_IO_OPERATION_NON_CACHED |
            FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, &transferred, NULL, NULL);
        if (!NT_SUCCESS(status) || transferred != length) {
            if (NT_SUCCESS(status)) status = STATUS_UNEXPECTED_IO_ERROR;
            goto Exit;
        }
        offset.QuadPart += length;
        if (tail != 0) { RtlZeroMemory(buffer, 65536); tail = 0; }
    }
Exit:
    FltFreePoolAlignedWithTag(Stream->BackingInstance, buffer, STAGE_TAG);
    return status;
}

static NTSTATUS StageResizeBacking(PSTAGE_STREAM Stream, LARGE_INTEGER Size)
{
    FILE_END_OF_FILE_INFORMATION end;
    NTSTATUS status = StageZeroGrowth(Stream, Size);
    if (!NT_SUCCESS(status)) return status;
    end.EndOfFile = Size;
    return FltSetInformationFile(Stream->BackingInstance, Stream->BackingObject,
        &end, sizeof(end), FileEndOfFileInformation);
}

typedef struct _STAGE_RESIZE_WORK {
    PSTAGE_STREAM Stream;
    LARGE_INTEGER Size;
    NTSTATUS Status;
    KEVENT Done;
} STAGE_RESIZE_WORK, *PSTAGE_RESIZE_WORK;

static VOID StageResizeBackingWorker(_In_ PFLT_GENERIC_WORKITEM WorkItem, _In_ PVOID FltObject,
    _In_opt_ PVOID Context)
{
    PSTAGE_RESIZE_WORK work = (PSTAGE_RESIZE_WORK)Context;
    UNREFERENCED_PARAMETER(FltObject);
    if (work == NULL) { FltFreeGenericWorkItem(WorkItem); return; }
    work->Status = StageResizeBacking(work->Stream, work->Size);
    FltFreeGenericWorkItem(WorkItem);
    KeSetEvent(&work->Done, IO_NO_INCREMENT, FALSE);
}

/* Mm's FsRtlSetFileSize (section creation/extension) runs with FSRTL_FSP_TOP_LEVEL_IRP. NTFS
 * refuses backing I/O issued under it with STATUS_FILE_LOCK_CONFLICT, and MiCreateSectionCommon
 * retries on that status forever: the C02 extending-map livelock (2026-10-07). Minifilters may
 * not change the top-level IRP, so the backing work runs on a system worker, which has none.
 * The waiter holds only this stream's resource; the worker touches only the backing file. */
static NTSTATUS StagePostResizeBacking(PSTAGE_STREAM Stream, LARGE_INTEGER Size)
{
    STAGE_RESIZE_WORK work;
    PFLT_GENERIC_WORKITEM item = FltAllocateGenericWorkItem();
    NTSTATUS status;
    if (item == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    work.Stream = Stream;
    work.Size = Size;
    work.Status = STATUS_UNSUCCESSFUL;
    KeInitializeEvent(&work.Done, NotificationEvent, FALSE);
    status = FltQueueGenericWorkItem(item, SafeUploadData.Filter, StageResizeBackingWorker,
        DelayedWorkQueue, &work);
    if (!NT_SUCCESS(status)) {
        FltFreeGenericWorkItem(item);
        return status;
    }
    (VOID)KeWaitForSingleObject(&work.Done, Executive, KernelMode, FALSE, NULL);
    return work.Status;
}

static NTSTATUS StageResize(PSTAGE_STREAM Stream, PFILE_OBJECT FileObject, LARGE_INTEGER Size)
{
    CC_FILE_SIZES sizes;
    NTSTATUS status;
    NT_ASSERT(ExIsResourceAcquiredExclusiveLite(&Stream->Resource));
    if (Stream->ReadOnly || Stream->RenameExchange != NULL) return STATUS_ACCESS_DENIED;
    if (Size.QuadPart < 0 || Size.QuadPart > STAGE_MAX_BYTES) return STATUS_FILE_TOO_LARGE;
    if (Size.QuadPart < Stream->Header.FileSize.QuadPart &&
        !MmCanFileBeTruncated(&Stream->Sections, &Size)) return STATUS_USER_MAPPED_FILE;
    /* The upper flush stays on this thread even when recursive: in C02 this thread is still
     * creating the control area, so a cross-thread MmFlushSection could wait on it. */
    status = STATUS_SUCCESS;
    if (Size.QuadPart > Stream->Header.FileSize.QuadPart) status = StageFlushUpper(Stream);
    if (NT_SUCCESS(status)) status = IoGetTopLevelIrp() == NULL ?
        StageResizeBacking(Stream, Size) : StagePostResizeBacking(Stream, Size);
    /* A recursive caller may be section creation, which retries these statuses forever.
     * Fail instead of livelocking. */
    if (IoGetTopLevelIrp() != NULL &&
        (status == STATUS_FILE_LOCK_CONFLICT || status == (NTSTATUS)0xC0000476L))
        status = STATUS_UNEXPECTED_IO_ERROR;
    if (!NT_SUCCESS(status)) return status;
    Stream->Header.FileSize = Size;
    Stream->Header.AllocationSize.QuadPart = (Size.QuadPart + PAGE_SIZE - 1) & ~((LONGLONG)PAGE_SIZE - 1);
    Stream->Header.ValidDataLength = Size; /* Every extended byte was materialized. */
    StageBasicWritten(Stream);
    if (Stream->Sections.SharedCacheMap != NULL) {
        StageInitializeCache(Stream, FileObject);
        sizes.AllocationSize = Stream->Header.AllocationSize;
        sizes.FileSize = Size;
        sizes.ValidDataLength = Size;
        CcSetFileSizes(FileObject, &sizes);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS StageReadWrite(PFLT_CALLBACK_DATA Data, PSTAGE_STREAM Stream)
{
    BOOLEAN write = Data->Iopb->MajorFunction == IRP_MJ_WRITE;
    ULONG length = write ? Data->Iopb->Parameters.Write.Length : Data->Iopb->Parameters.Read.Length;
    LARGE_INTEGER offset = write ? Data->Iopb->Parameters.Write.ByteOffset : Data->Iopb->Parameters.Read.ByteOffset;
    PFILE_OBJECT file = Data->Iopb->TargetFileObject;
    PMDL mdl = write ? Data->Iopb->Parameters.Write.MdlAddress : Data->Iopb->Parameters.Read.MdlAddress;
    PVOID buffer;
    NTSTATUS status;
    if (write && (Stream->ReadOnly || Stream->RenameExchange != NULL)) return STATUS_ACCESS_DENIED;
    if (length == 0) return STATUS_SUCCESS;
    if (mdl == NULL && !FLT_IS_SYSTEM_BUFFER(Data)) {
        status = FltLockUserBuffer(Data);
        if (!NT_SUCCESS(status)) return status;
        mdl = write ? Data->Iopb->Parameters.Write.MdlAddress : Data->Iopb->Parameters.Read.MdlAddress;
    }
    buffer = mdl != NULL ? MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute) :
        write ? Data->Iopb->Parameters.Write.WriteBuffer : Data->Iopb->Parameters.Read.ReadBuffer;
    if (buffer == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    StageAcquire(&Stream->Resource);
    __try {
        LARGE_INTEGER lockLength;
        /* Rename publishes its freeze while holding this same resource.
         * The early check can become stale while locking the user's buffer. */
        if (write && (Stream->ReadOnly || Stream->RenameExchange != NULL)) {
            status = STATUS_ACCESS_DENIED;
            __leave;
        }
        if (write && (offset.QuadPart == (LONGLONG)(LONG)FILE_WRITE_TO_END_OF_FILE ||
            !FlagOn(((PSTAGE_HANDLE)file->FsContext2)->GrantedAccess, FILE_WRITE_DATA))) offset = Stream->Header.FileSize;
        if (offset.QuadPart == (LONGLONG)(LONG)FILE_USE_FILE_POINTER_POSITION) offset = file->CurrentByteOffset;
        if (offset.QuadPart < 0 || offset.QuadPart > STAGE_MAX_BYTES ||
            length > STAGE_MAX_BYTES - (ULONGLONG)offset.QuadPart) {
            status = STATUS_INVALID_PARAMETER;
            __leave;
        }
        lockLength.QuadPart = length;
        if (write ? !FsRtlFastCheckLockForWrite(Stream->ByteLocks, &offset, &lockLength,
                Data->Iopb->Parameters.Write.Key, file, FltGetRequestorProcess(Data)) :
            !FsRtlFastCheckLockForRead(Stream->ByteLocks, &offset, &lockLength,
                Data->Iopb->Parameters.Read.Key, file, FltGetRequestorProcess(Data))) {
            status = STATUS_FILE_LOCK_CONFLICT;
            __leave;
        }
        if (!write) {
            if (offset.QuadPart >= Stream->Header.FileSize.QuadPart) {
                status = STATUS_END_OF_FILE;
                __leave;
            }
            length = (ULONG)min((LONGLONG)length, Stream->Header.FileSize.QuadPart - offset.QuadPart);
        } else if (offset.QuadPart + length > Stream->Header.FileSize.QuadPart) {
            LARGE_INTEGER size;
            size.QuadPart = offset.QuadPart + length;
            status = StageResize(Stream, file, size);
            if (!NT_SUCCESS(status)) __leave;
        }
        StageInitializeCache(Stream, file);
        if (write) {
            CcCopyWrite(file, &offset, length, TRUE, buffer);
            Data->IoStatus.Information = length;
            status = STATUS_SUCCESS;
            /* A later app write supersedes an earlier explicit write date;
             * delayed paging for this write does not supersede a later setter. */
            StageBasicWritten(Stream);
            if (FlagOn(file->Flags, FO_WRITE_THROUGH)) status = StageFlush(Stream);
        } else {
            CcCopyRead(file, &offset, length, TRUE, buffer, &Data->IoStatus);
            status = Data->IoStatus.Status;
        }
        if (NT_SUCCESS(status) && FlagOn(file->Flags, FO_SYNCHRONOUS_IO))
            file->CurrentByteOffset.QuadPart = offset.QuadPart + Data->IoStatus.Information;
    } __except(EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
    StageRelease(&Stream->Resource);
    return status;
}

static NTSTATUS StageQuery(PFLT_CALLBACK_DATA Data, PSTAGE_STREAM Stream, PSTAGE_HANDLE Handle)
{
    FILE_INFORMATION_CLASS cls = Data->Iopb->Parameters.QueryFileInformation.FileInformationClass;
    ULONG length = Data->Iopb->Parameters.QueryFileInformation.Length;
    PVOID output = Data->Iopb->Parameters.QueryFileInformation.InfoBuffer;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG returned = 0;
    ULONG prefix = 0, copied;
    PFILE_NAME_INFORMATION name;
    UNICODE_STRING relative = Stream->Name;
    StageAcquire(&Stream->Resource);
    relative.Buffer = (PWCH)((PUCHAR)relative.Buffer + Stream->VolumeLength);
    relative.Length -= Stream->VolumeLength;
    __try {
        if (cls == FileAllInformation) {
            PFILE_ALL_INFORMATION all;
            ULONG bytes = sizeof(FILE_ALL_INFORMATION) + SAFEUPLOAD_MAX_PATH_BYTES;
            prefix = FIELD_OFFSET(FILE_ALL_INFORMATION, NameInformation);
            if (length < prefix + sizeof(ULONG)) { status = STATUS_INFO_LENGTH_MISMATCH; __leave; }
            all = ExAllocatePool2(POOL_FLAG_PAGED, bytes, STAGE_TAG);
            if (all == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; __leave; }
            status = FltQueryInformationFile(Stream->BackingInstance, Stream->BackingObject,
                all, bytes, cls, &returned);
            if (NT_SUCCESS(status)) {
                StageOverlayBasic(Stream, &all->BasicInformation);
                all->StandardInformation.EndOfFile = Stream->Header.FileSize;
                all->StandardInformation.AllocationSize = Stream->Header.AllocationSize;
                all->InternalInformation.IndexNumber.QuadPart = 0; /* No invented destination file ID. */
                all->AccessInformation.AccessFlags = Handle->GrantedAccess;
                all->PositionInformation.CurrentByteOffset = Data->Iopb->TargetFileObject->CurrentByteOffset;
                RtlCopyMemory(output, all, prefix);
            }
            ExFreePoolWithTag(all, STAGE_TAG);
            if (!NT_SUCCESS(status)) __leave;
        }
        if (cls == FileNameInformation || cls == FileNormalizedNameInformation || cls == FileAllInformation) {
            if (length < prefix + sizeof(ULONG)) { status = STATUS_INFO_LENGTH_MISMATCH; __leave; }
            name = (PFILE_NAME_INFORMATION)((PUCHAR)output + prefix);
            name->FileNameLength = relative.Length;
            copied = min(relative.Length, length - prefix - FIELD_OFFSET(FILE_NAME_INFORMATION, FileName));
            copied &= ~1UL;
            RtlCopyMemory(name->FileName, relative.Buffer, copied);
            Data->IoStatus.Information = prefix + sizeof(ULONG) + copied;
            status = copied == relative.Length ? STATUS_SUCCESS : STATUS_BUFFER_OVERFLOW;
        } else if (cls == FilePositionInformation) {
            if (length < sizeof(FILE_POSITION_INFORMATION)) { status = STATUS_INFO_LENGTH_MISMATCH; __leave; }
            ((PFILE_POSITION_INFORMATION)output)->CurrentByteOffset = Data->Iopb->TargetFileObject->CurrentByteOffset;
            Data->IoStatus.Information = sizeof(FILE_POSITION_INFORMATION);
        } else if (cls == FileAccessInformation) {
            if (length < sizeof(FILE_ACCESS_INFORMATION)) { status = STATUS_INFO_LENGTH_MISMATCH; __leave; }
            ((PFILE_ACCESS_INFORMATION)output)->AccessFlags = Handle->GrantedAccess;
            Data->IoStatus.Information = sizeof(FILE_ACCESS_INFORMATION);
        } else if (cls == FileAlternateNameInformation) {
            status = STATUS_OBJECT_NAME_NOT_FOUND;
        } else if (cls == FileIdInformation) {
            if (length < sizeof(FILE_ID_INFORMATION)) { status = STATUS_INFO_LENGTH_MISMATCH; __leave; }
            RtlCopyMemory(output, &Stream->View->Identity, sizeof(FILE_ID_INFORMATION));
            Data->IoStatus.Information = sizeof(FILE_ID_INFORMATION);
        } else if (cls == FileBasicInformation || cls == FileStandardInformation ||
            cls == FileNetworkOpenInformation || cls == FileAttributeTagInformation ||
            cls == FileStandardLinkInformation) {
            /* Link counts, delete-pending and directory come from the backing file like FileStandardInformation's
             * (U01: a first sign-in queries FileStandardLinkInformation on a staged stream; reads are never refused). */
            status = FltQueryInformationFile(Stream->BackingInstance, Stream->BackingObject,
                output, length, cls, &returned);
            Data->IoStatus.Information = returned;
            if (NT_SUCCESS(status) && cls == FileStandardInformation) {
                ((PFILE_STANDARD_INFORMATION)output)->EndOfFile = Stream->Header.FileSize;
                ((PFILE_STANDARD_INFORMATION)output)->AllocationSize = Stream->Header.AllocationSize;
            } else if (NT_SUCCESS(status) && cls == FileBasicInformation) {
                StageOverlayBasic(Stream, (PFILE_BASIC_INFORMATION)output);
            } else if (NT_SUCCESS(status) && (cls == FileNetworkOpenInformation || cls == FileAttributeTagInformation)) {
                FILE_BASIC_INFORMATION basic = {0};
                StageOverlayBasic(Stream, &basic);
                if (cls == FileAttributeTagInformation) {
                    if (basic.FileAttributes != 0) ((PFILE_ATTRIBUTE_TAG_INFORMATION)output)->FileAttributes = basic.FileAttributes;
                } else {
                    PFILE_NETWORK_OPEN_INFORMATION network = output;
                    if (basic.CreationTime.QuadPart != 0) network->CreationTime = basic.CreationTime;
                    if (basic.LastAccessTime.QuadPart != 0) network->LastAccessTime = basic.LastAccessTime;
                    if (basic.LastWriteTime.QuadPart != 0) network->LastWriteTime = basic.LastWriteTime;
                    if (basic.FileAttributes != 0) network->FileAttributes = basic.FileAttributes;
                }
            }
        } else status = STATUS_NOT_SUPPORTED;
    } __except(EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
    StageRelease(&Stream->Resource);
    return status;
}

/* Resource is held; overlay the logical version, not its service-owned flags. */
static VOID StageBasicWritten(_Inout_ PSTAGE_STREAM Stream)
{
    Stream->BasicOverrides.LastWriteTime.QuadPart = 0;
    if (Stream->BasicOverrides.FileAttributes != 0)
        Stream->BasicOverrides.FileAttributes =
            (Stream->BasicOverrides.FileAttributes & ~FILE_ATTRIBUTE_NORMAL) | FILE_ATTRIBUTE_ARCHIVE;
}

static BOOLEAN StageBasicReadonly(_In_ const STAGE_STREAM *Stream)
{
    return BooleanFlagOn(Stream->SealBasicValid ? Stream->SealBasic.FileAttributes :
        Stream->BasicOverrides.FileAttributes, FILE_ATTRIBUTE_READONLY);
}

static VOID StageInitializeBasic(_Inout_ PSTAGE_STREAM Stream, _In_opt_ const STAGE_STREAM *Previous,
    _In_ BOOLEAN Exists, _In_ ULONG Disposition, _In_ ULONG Attributes)
{
    if (Previous != NULL && Previous->SealBasicValid && Disposition != FILE_SUPERSEDE) {
        Stream->BasicOverrides = Previous->SealBasic;
        if (Disposition == FILE_OVERWRITE || Disposition == FILE_OVERWRITE_IF) StageBasicWritten(Stream);
    }
    if (!Exists || Disposition == FILE_SUPERSEDE)
        Stream->BasicOverrides.FileAttributes = (Attributes & ~FILE_ATTRIBUTE_NORMAL) | FILE_ATTRIBUTE_ARCHIVE;
}

static VOID StageOverlayBasic(_In_ const STAGE_STREAM *Stream, _Inout_ PFILE_BASIC_INFORMATION Basic)
{
    const FILE_BASIC_INFORMATION *over = &Stream->BasicOverrides;
    if (Stream->SealBasicValid) { *Basic = Stream->SealBasic; return; }
    if (over->CreationTime.QuadPart != 0) Basic->CreationTime = over->CreationTime;
    if (over->LastAccessTime.QuadPart != 0) Basic->LastAccessTime = over->LastAccessTime;
    if (over->LastWriteTime.QuadPart != 0) Basic->LastWriteTime = over->LastWriteTime;
    if (over->FileAttributes != 0) Basic->FileAttributes = over->FileAttributes;
}

_Use_decl_annotations_
static NTSTATUS StageSetBasicInformation(PFLT_CALLBACK_DATA Data, PSTAGE_STREAM Stream, ACCESS_MASK GrantedAccess)
{
    FILE_BASIC_INFORMATION basic;
    NTSTATUS status = STATUS_SUCCESS;
    PAGED_CODE();
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;
    if (!FlagOn(GrantedAccess, FILE_WRITE_ATTRIBUTES)) return STATUS_ACCESS_DENIED;
    if (Data->Iopb->Parameters.SetFileInformation.Length < sizeof(basic) ||
        Data->Iopb->Parameters.SetFileInformation.InfoBuffer == NULL) return STATUS_INFO_LENGTH_MISMATCH;
    __try { basic = *(PFILE_BASIC_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
    /* Suppression/resumption is per upper FILE_OBJECT. A shared lower handle
     * must never give one upper caller another caller's suppression state. */
    if (basic.CreationTime.QuadPart < 0 || basic.LastAccessTime.QuadPart < 0 ||
        basic.LastWriteTime.QuadPart < 0 || basic.ChangeTime.QuadPart < 0 ||
        FlagOn(basic.FileAttributes, ~STAGE_BASIC_ATTRIBUTES)) return STATUS_NOT_SUPPORTED;
    if (FlagOn(basic.FileAttributes, ~FILE_ATTRIBUTE_NORMAL)) basic.FileAttributes &= ~FILE_ATTRIBUTE_NORMAL;
    StageAcquire(&Stream->Resource);
    if (Stream->ReadOnly || Stream->Sealed || Stream->RenameExchange != NULL || Stream->BackingObject == NULL)
        status = STATUS_ACCESS_DENIED;
    else {
        if (basic.CreationTime.QuadPart != 0) Stream->BasicOverrides.CreationTime = basic.CreationTime;
        if (basic.LastAccessTime.QuadPart != 0) Stream->BasicOverrides.LastAccessTime = basic.LastAccessTime;
        if (basic.LastWriteTime.QuadPart != 0) Stream->BasicOverrides.LastWriteTime = basic.LastWriteTime;
        if (basic.FileAttributes != 0) Stream->BasicOverrides.FileAttributes = basic.FileAttributes;
        /* ChangeTime belongs to physical publication, per the owner decision. */
    }
    StageRelease(&Stream->Resource);
    return status;
}

/* The seal RPC pin owns this drained backing. No namespace/stream lock spans
 * the lower query. Cache flush and the writable handle's cleanup already ended. */
_Use_decl_annotations_
static NTSTATUS StageCaptureSealBasic(PSTAGE_STREAM Stream)
{
    FILE_BASIC_INFORMATION basic;
    NTSTATUS status;
    ULONG returned = 0;
    PAGED_CODE();
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || IoGetTopLevelIrp() != NULL) return STATUS_INVALID_DEVICE_STATE;
    if (Stream->SealBasicValid) return STATUS_SUCCESS;
    if (!Stream->ReadOnly || Stream->BackingObject == NULL) return STATUS_INVALID_DEVICE_STATE;
    RtlZeroMemory(&basic, sizeof(basic));
    status = FltQueryInformationFile(Stream->BackingInstance, Stream->BackingObject,
        &basic, sizeof(basic), FileBasicInformation, &returned);
    if (status != STATUS_SUCCESS) return NT_SUCCESS(status) ? STATUS_UNEXPECTED_IO_ERROR : status;
    if (returned != sizeof(basic)) return STATUS_INFO_LENGTH_MISMATCH;
    StageAcquire(&Stream->Resource);
    StageOverlayBasic(Stream, &basic);
    if (basic.CreationTime.QuadPart < 0 || basic.LastAccessTime.QuadPart < 0 ||
        basic.LastWriteTime.QuadPart < 0 || FlagOn(basic.FileAttributes, ~STAGE_BASIC_ATTRIBUTES))
        status = STATUS_NOT_SUPPORTED;
    else { Stream->SealBasic = basic; Stream->SealBasicValid = TRUE; }
    StageRelease(&Stream->Resource);
    return status;
}

static NTSTATUS StageExchangeStatus(PSAFEUPLOAD_EXCHANGE Exchange)
{
#if SAFEUPLOAD_STAGING_PROTOTYPE
    return SafeUploadStageRenameExchangeV19(Exchange);
#else
    BOOLEAN answered = FALSE;
    UINT32 verdict;
    NTSTATUS status = SafeUploadRequestVerdict(Exchange, &verdict, &answered);
    return SafeUploadStageExchangeResult(status, answered, verdict);
#endif
}

static VOID StageSetRenameOperation(PSAFEUPLOAD_EXCHANGE Exchange, UINT32 Operation)
{
    Exchange->Request.Operation = Operation;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    ((PSAFEUPLOAD_STAGE_RENAME_V20)Exchange->Request.ImageName)->Operation = Operation;
#endif
}

/* For seal and rename, a refusal or absent service waits for the next connection. Anything else (no reply, no memory for the request)
 * is retried on the timer: nothing else would ever resend it (Luna T4 review P1). Discard denials use a timer because stage deletion
 * can fail transiently while the connected service is still available. */
static UCHAR StageWaitFor(NTSTATUS Status)
{
    return Status == STATUS_ACCESS_DENIED || Status == STATUS_PORT_DISCONNECTED ||
        Status == STATUS_INVALID_BUFFER_SIZE || Status == STATUS_INVALID_PARAMETER ? STAGE_WAIT_SERVICE : STAGE_WAIT_EXCHANGE;
}

/* Queue the retained exchange. The worker owns the port call after dropping
 * NamespaceResource; callers leave the namespace frozen until exact apply. */
static VOID StageFinishRename(PSTAGE_STREAM Stream)
{
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (Stream->RenameExchange == NULL) return;
    if (Stream->RenameWait == STAGE_WAIT_SERVICE) { Stream->Wait = STAGE_WAIT_SERVICE; return; }
    Stream->Wait = STAGE_WAIT_EXCHANGE;
    Stream->RenameWait = STAGE_WAIT_EXCHANGE;
    if (Stream->RenameRpcPending || Stream->RenameRpcInFlight) return;
    Stream->RenameRpcPending = TRUE;
#else
    NTSTATUS status;
    KIRQL irql;
    if (Stream->RenameExchange == NULL) return;
    status = StageExchangeStatus(Stream->RenameExchange);
    if (status == STATUS_SUCCESS) {
        PSAFEUPLOAD_EXCHANGE exchange;
        StageAcquire(&Stream->Resource);
        exchange = Stream->RenameExchange;
        StageStreamAcquireSpinLock(&StageListLock, &irql);
        Stream->RenameExchange = NULL;
        if (exchange->Request.Operation == SAFEUPLOAD_OPERATION_STAGE_RENAME_COMMIT) {
            Stream->RenameCommits++;
            Stream->Disposed = FALSE;
            Stream->DisposeDeferred = FALSE;
        } else if (Stream->DisposeDeferred) {
            Stream->Disposed = TRUE;
            Stream->DisposeOutcome = Stream->DeferredOutcome;
            Stream->DisposeDeferred = FALSE;
        }
        StageStreamReleaseSpinLock(&StageListLock, irql);
        StageRelease(&Stream->Resource);
        ExFreePoolWithTag(exchange, STAGE_TAG);
        Stream->Wait = STAGE_WAIT_NONE;
    } else Stream->Wait = StageWaitFor(status);
#endif
}

#if SAFEUPLOAD_STAGING_PROTOTYPE
/* Apply only the exact exchange still owned by this stream. Called after the
 * service response and after reacquiring NamespaceResource. */
static VOID StageApplyRenameReply(PSTAGE_STREAM Stream, PSAFEUPLOAD_EXCHANGE Exchange,
    NTSTATUS Status)
{
    KIRQL irql;
    PSAFEUPLOAD_STAGE_RENAME_V20 source = (PSAFEUPLOAD_STAGE_RENAME_V20)Exchange->Request.ImageName;
    if (Stream->RenameExchange != Exchange) return;
    if (!NT_SUCCESS(Status)) {
        Stream->RenameRpcPending = TRUE;
        Stream->RenameWait = StageWaitFor(Status);
        Stream->Wait = Stream->RenameWait;
        return;
    }
    /* Out-of-lock transport validation alone cannot authorize a changed local
     * object/view/epoch. Abort also checks the original tuple and never adopts. */
    if (!Stream->Listed || Stream->View == NULL || source->RequestId != Exchange->Request.RequestId ||
        source->Operation != Exchange->Request.Operation || source->OwnerProcessId != Stream->View->OwnerProcessId ||
        source->ViewGeneration != (UINT64)Stream->View->Generation ||
        source->SourceGeneration != Stream->DestinationGeneration ||
        !RtlEqualMemory(&source->TransferId, &Stream->TransferId, sizeof(GUID)) ||
        !StageV19IdentityEqual(&source->StageIdentity, &Stream->StageIdentity) ||
        !StageV19IdentityEqual(&source->ParentDirectoryIdentity, &Stream->AllocationParentDirectoryIdentity) ||
        !RtlEqualMemory(&source->DriverInstanceId, &Stream->DriverInstanceId, sizeof(GUID)) ||
        !RtlEqualMemory(&Stream->DriverInstanceId, &StageDriverInstanceId, sizeof(GUID)) ||
        (Exchange->Request.Operation == SAFEUPLOAD_OPERATION_STAGE_RENAME_COMMIT &&
            (!Exchange->RenameReceiptValid || Exchange->RenameAck.RequestId != source->RequestId ||
             Exchange->RenameAck.Operation != SAFEUPLOAD_OPERATION_STAGE_RENAME_COMMIT ||
             Exchange->RenameAck.Result != SAFEUPLOAD_STAGE_RESULT_RENAME_COMMITTED ||
             Exchange->RenameAck.SourceGeneration != source->SourceGeneration ||
             Exchange->RenameAck.OwnerProcessId != source->OwnerProcessId ||
             Exchange->RenameAck.ViewGeneration != source->ViewGeneration ||
             !RtlEqualMemory(&Exchange->RenameAck.TransferId, &source->TransferId, sizeof(GUID)) ||
             !StageV19IdentityEqual(&Exchange->RenameAck.StageIdentity, &source->StageIdentity) ||
             !RtlEqualMemory(&Exchange->RenameAck.DriverInstanceId, &source->DriverInstanceId, sizeof(GUID)) ||
             !StageV19IdentityEqual(&Exchange->RenameAck.ParentDirectoryIdentity, &source->ParentDirectoryIdentity) ||
             Exchange->RenameDestinationGeneration == 0 || Stream->Name.Length != Exchange->Request.PathLength ||
             !RtlEqualMemory(Stream->Name.Buffer, Exchange->Request.Path, Stream->Name.Length)))) {
        Stream->RenameRpcPending = TRUE;
        Stream->RenameWait = STAGE_WAIT_SERVICE;
        Stream->Wait = STAGE_WAIT_SERVICE;
        return;
    }
    StageAcquire(&Stream->Resource);
    StageStreamAcquireSpinLock(&StageListLock, &irql);
    if (Exchange->Request.Operation == SAFEUPLOAD_OPERATION_STAGE_RENAME_COMMIT) {
        /* Generations are per name: the target can be lower than the source.
         * Adopt ONLY the exact journal receipt, before releasing the fence. */
        Stream->DestinationGeneration = Exchange->RenameDestinationGeneration;
        Stream->RenameCommits++;
        Stream->Disposed = FALSE;
        Stream->DisposeDeferred = FALSE;
    } else if (Stream->DisposeDeferred) {
        Stream->Disposed = TRUE;
        Stream->DisposeOutcome = Stream->DeferredOutcome;
        Stream->DisposeDeferred = FALSE;
    }
    Stream->RenameExchange = NULL;
    Stream->RenameWait = STAGE_WAIT_NONE;
    Stream->RenameRetryAfter = 0;
    Stream->RenameRpcPending = FALSE;
    StageStreamReleaseSpinLock(&StageListLock, irql);
    StageRelease(&Stream->Resource);
    ExFreePoolWithTag(Exchange, STAGE_TAG);
    Stream->Wait = STAGE_WAIT_NONE;
    StageQueueStream(Stream, &StageCounters.WakeInline);
}

#endif

/* T5: STATUS_SUCCESS when no public file has Name (the delete of a private-only name, such as the common file dialog's test file or
 * an application's temporary name); STATUS_ACCESS_DENIED when one does, or when that cannot be determined. Caller owns
 * NamespaceResource, as StageRename does for the same query. */
static NTSTATUS StagePublicNameFree(PFLT_INSTANCE Instance, PUNICODE_STRING Name)
{
    FILE_ID_INFORMATION identity;
    NTSTATUS status = SafeUploadStageQueryIdentity(Instance, Name, FALSE, &identity);
    if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND) return STATUS_SUCCESS;
    return STATUS_ACCESS_DENIED;
}

#if SAFEUPLOAD_STAGING_PROTOTYPE
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageCancelSealedPrivate(_In_ PSTAGE_STREAM Stream, _In_ BOOLEAN NativeNamespace);
#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, StageCancelSealedPrivate)
#endif
_IRQL_requires_(PASSIVE_LEVEL)
_Use_decl_annotations_
static NTSTATUS StageCancelSealedPrivate(PSTAGE_STREAM Stream, BOOLEAN NativeNamespace)
{
    SAFEUPLOAD_PRIVATE_CANCEL_REQUEST request = {0};
    SAFEUPLOAD_PRIVATE_CANCEL_REPLY reply = {0};
    GUID operation = {0};
    NTSTATUS status;
    PAGED_CODE();
    status = ExUuidCreate(&operation);
    if (!NT_SUCCESS(status)) return status;
    StageAcquire(&StageNamespaceResource);
    if (Stream->PrivateCancellationAccepted) {
        StageRelease(&StageNamespaceResource);
        return STATUS_SUCCESS;
    }
    if (!Stream->Sealed || Stream->View == NULL || Stream->PrivateCancellationBusy ||
        (Stream->BoundAllocation && (Stream->View->Current != Stream || Stream->View->Detached ||
            !SafeUploadStageProtocolNativeForwardAllowed(0, 0))) ||
        Stream->RenameExchange != NULL || !SafeUploadStageProtocolIsReady()) {
        StageRelease(&StageNamespaceResource);
        return STATUS_CANNOT_DELETE;
    }
    if (NativeNamespace) {
        BOOLEAN closed;
        StageAcquire(&Stream->Resource);
        closed = Stream->ShareAccess.OpenCount == 0;
        StageRelease(&Stream->Resource);
        if (!closed) {
            StageRelease(&StageNamespaceResource);
            return STATUS_SHARING_VIOLATION;
        }
    }
    if (Stream->PrivateCancellation.Version == 0) {
        Stream->PrivateCancellation.Version = SAFEUPLOAD_PRIVATE_CANCEL_VERSION;
        Stream->PrivateCancellation.StructSize = sizeof(request);
        Stream->PrivateCancellation.OperationId = operation;
        Stream->PrivateCancellation.TransferId = Stream->TransferId;
        Stream->PrivateCancellation.DriverInstanceId = Stream->DriverInstanceId;
        Stream->PrivateCancellation.StageIdentity = Stream->StageIdentity;
        Stream->PrivateCancellation.Generation = Stream->DestinationGeneration;
        Stream->PrivateCancellation.OwnerProcessId = Stream->View->OwnerProcessId;
        Stream->PrivateCancellation.OwnerCreationTime = PsGetProcessCreateTimeQuadPart(Stream->View->Owner);
    }
    request = Stream->PrivateCancellation;
    Stream->PrivateCancellationBusy = TRUE;
    InterlockedIncrement(&Stream->RpcReferences);
    StageRelease(&StageNamespaceResource);
    status = SafeUploadStageCancelPrivate(&request, &reply); /* no namespace/stream resource across the turn/RPC */
    StageAcquire(&StageNamespaceResource);
    if (status == STATUS_SUCCESS && reply.Result == SAFEUPLOAD_PRIVATE_CANCELED) {
        Stream->PrivateCancellationAccepted = TRUE;
        if (Stream->View != NULL && Stream->View->Current == Stream) Stream->View->Detached = TRUE;
        /* Keep sealed bytes/identity for exact cleanup; this is no discard ACK. */
    } else if (status == STATUS_SUCCESS && NativeNamespace) {
        Stream->MvpPublicationObserved = TRUE;
        if (Stream->View != NULL && Stream->View->Current == Stream) Stream->View->Detached = TRUE;
        /* Native source, or a staged replacement target: publication won.
         * The original operation still must pass its own Windows grants. */
    } else if (status == STATUS_SUCCESS) {
        /* Publication won. Only a freshly checked real public DELETE can now
         * remove it. This handle has no such authority; never emulate it. */
        status = STATUS_CANNOT_DELETE;
    }
    Stream->PrivateCancellationBusy = FALSE;
    InterlockedDecrement(&Stream->RpcReferences);
    if (status == STATUS_SUCCESS) StageQueueStream(Stream, &StageCounters.WakeInline);
    StageRelease(&StageNamespaceResource);
    return status;
}
#endif

#if SAFEUPLOAD_STAGING_PROTOTYPE
/* Demo compatibility (owner, 2026-10-16): applications close a new file and at once delete or rename it (the Save As
 * write probe, temporary-file renames). The exact op19 handle receipt for that close is then still travelling, and the
 * checks below would answer BUSY/ACCESS_DENIED. Wait, bounded and with no lock held, until the receipt settles; the
 * checks themselves are unchanged and still decide. A stream found through a live file object stays allocated. */
_IRQL_requires_max_(APC_LEVEL)
static VOID StageWaitHandleReceiptSettled(_In_ PSTAGE_STREAM Stream, _In_ BOOLEAN NamespaceReopen);
#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, StageWaitHandleReceiptSettled)
#endif
_Use_decl_annotations_
static VOID StageWaitHandleReceiptSettled(PSTAGE_STREAM Stream, BOOLEAN NamespaceReopen)
{
    LARGE_INTEGER interval;
    ULONGLONG deadline;
    BOOLEAN busy;
    PAGED_CODE();
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return;
    interval.QuadPart = -10 * 1000 * 10; /* 10 ms */
    deadline = KeQueryInterruptTime() + 10ULL * 1000 * 1000 * 10; /* 10 s */
    for (;;) {
        StageAcquire(&StageNamespaceResource);
        busy = Stream->HandleReceiptPending || Stream->HandleReceiptInFlight ||
            (Stream->AnyHandleCleanupObserved && !Stream->HandleReceiptAcknowledged) ||
            (NamespaceReopen && Stream->ReadOnly && !Stream->Sealed && !Stream->DiscardOnClose &&
                !Stream->Discarded && !Stream->Retired && !Stream->PrivateCancellationAccepted && !StageStopping);
        StageRelease(&StageNamespaceResource);
        if (!busy || KeQueryInterruptTime() >= deadline) return;
        (VOID)KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }
}
#endif

/* T5 (driver/T5-DELETES.md R3): a delete of the owner's own private version discards it at the last cleanup; it is never sealed,
 * inspected or published, and the public name, if any, is untouched. FILE_DISPOSITION_ON_CLOSE sets or clears the handle's
 * delete-on-close instead, as on NTFS. The bound sealed branch first durably
 * cancels its exact generation; legacy sealed-handle behavior stays below. */
static NTSTATUS StageSetDisposition(PFLT_CALLBACK_DATA Data, PSTAGE_STREAM Stream, PSTAGE_HANDLE Handle)
{
    PVOID buffer = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    ULONG length = Data->Iopb->Parameters.SetFileInformation.Length;
    BOOLEAN extended = Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformationEx;
    ULONG flags;
    NTSTATUS status = STATUS_SUCCESS;
    if (!Data->Iopb->TargetFileObject->DeleteAccess) return STATUS_ACCESS_DENIED;
    if (buffer == NULL || length < (extended ? sizeof(ULONG) : sizeof(BOOLEAN))) return STATUS_INFO_LENGTH_MISMATCH;
    flags = extended ? *(PULONG)buffer :
        (((PFILE_DISPOSITION_INFORMATION)buffer)->DeleteFile ? FILE_DISPOSITION_DELETE : 0);
    if (FlagOn(flags, ~(FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS | FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK |
        FILE_DISPOSITION_ON_CLOSE | FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE)))
        return STATUS_INVALID_PARAMETER;
    if (FlagOn(flags, FILE_DISPOSITION_DELETE) && !FlagOn(flags, FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE)) {
        BOOLEAN readonlyAttribute;
        StageAcquire(&Stream->Resource);
        readonlyAttribute = StageBasicReadonly(Stream);
        StageRelease(&Stream->Resource);
        if (readonlyAttribute) return STATUS_CANNOT_DELETE;
    }
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (Stream->Sealed && FlagOn(flags, FILE_DISPOSITION_DELETE)) {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL || FlagOn(flags, FILE_DISPOSITION_ON_CLOSE)) return STATUS_CANNOT_DELETE;
        return StageCancelSealedPrivate(Stream, FALSE);
    }
    StageWaitHandleReceiptSettled(Stream, FALSE);
#endif
    /* NamespaceResource serializes this legacy/unsealed private discard with
     * creates and renames. Public deletion uses the separate exact relay. */
    StageAcquire(&StageNamespaceResource);
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (Stream->HandleReceiptPending || Stream->HandleReceiptInFlight ||
        (Stream->AnyHandleCleanupObserved && !Stream->HandleReceiptAcknowledged)) {
        status = STATUS_DEVICE_BUSY;
        goto ExitNamespace;
    }
#endif
    if (FlagOn(flags, FILE_DISPOSITION_DELETE)) {
        status = StagePublicNameFree(Stream->OriginalInstance, &Stream->Name);
        if (!NT_SUCCESS(status)) goto ExitNamespace;
    }
    StageAcquire(&Stream->Resource);
    if (Stream->ReadOnly || Stream->Sealed) status = STATUS_CANNOT_DELETE;
    else if (FlagOn(flags, FILE_DISPOSITION_DELETE) && !FlagOn(flags, FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE) &&
        StageBasicReadonly(Stream)) status = STATUS_CANNOT_DELETE;
    else if (Stream->RenameExchange != NULL) status = STATUS_SHARING_VIOLATION;
    else if (FlagOn(flags, FILE_DISPOSITION_DELETE) && Stream->Sections.ImageSectionObject != NULL) status = STATUS_CANNOT_DELETE;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (NT_SUCCESS(status) && FlagOn(flags, FILE_DISPOSITION_DELETE))
        status = StageReservePrivateDelete(Stream);
#endif
    if (NT_SUCCESS(status) && FlagOn(flags, FILE_DISPOSITION_ON_CLOSE)) {
        BOOLEAN deleteOnClose = BooleanFlagOn(flags, FILE_DISPOSITION_DELETE);
        if (Handle->DeleteOnClose != deleteOnClose) {
            if (deleteOnClose) ++Stream->DeleteOnCloseCount;
            else if (Stream->DeleteOnCloseCount != 0) --Stream->DeleteOnCloseCount;
            Handle->DeleteOnClose = deleteOnClose;
        }
        Stream->DiscardOnClose = Stream->DiscardDisposition || Stream->DeleteOnCloseCount != 0;
    } else if (NT_SUCCESS(status)) {
        Stream->DiscardDisposition = BooleanFlagOn(flags, FILE_DISPOSITION_DELETE);
        Stream->DiscardOnClose = Stream->DiscardDisposition || Stream->DeleteOnCloseCount != 0;
    }
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (NT_SUCCESS(status) && !Stream->DiscardOnClose && !Stream->Discarded)
        StageClearPrivateDelete(Stream);
#endif
    StageRelease(&Stream->Resource);
ExitNamespace:
    StageRelease(&StageNamespaceResource);
    return status;
}

/* Resource held by the caller. NTFS requires the OTHER opens to share delete;
 * the DELETE-authorized handle performing the rename need not share it with
 * another opener. IoUpdateShareAccess counted this handle too. Do not change
 * the ledger or exclude any other FILE_OBJECT. A duplicated handle still
 * refers to this same open and adds no share participant. */
_IRQL_requires_max_(APC_LEVEL)
_Use_decl_annotations_
static BOOLEAN StageRenameShareAllowed(const SHARE_ACCESS *ShareAccess, PFILE_OBJECT FileObject)
{
    PAGED_CODE();
    if (!FileObject->DeleteAccess || ShareAccess->OpenCount == 0 ||
        ShareAccess->SharedDelete > ShareAccess->OpenCount)
        return FALSE;
    return ShareAccess->OpenCount - ShareAccess->SharedDelete == (FileObject->SharedDelete ? 0UL : 1UL);
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageRenameAuthorizeReplacement(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PSTAGE_STREAM Stream, _In_ PSTAGE_VIEW Target, _In_ PUNICODE_STRING Destination,
    _In_ BOOLEAN Replace);
#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, StageRenameAuthorizeReplacement)
#endif
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageRenameAuthorizeReplacement(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PSTAGE_STREAM Stream, _In_ PSTAGE_VIEW Target, _In_ PUNICODE_STRING Destination,
    _In_ BOOLEAN Replace)
{
    NTSTATUS status;
    PAGED_CODE();
    status = SafeUploadStageCheckSubjectAccess(Data, Target->Security, DELETE);
    if (!NT_SUCCESS(status)) return status;
    return SafeUploadStageCheckRenameAccess(Data, Stream->OriginalInstance, Destination, Replace);
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageRename(_In_ PFLT_CALLBACK_DATA Data, _In_ PSTAGE_STREAM Stream);
#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, StageRename)
#endif
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageRename(_In_ PFLT_CALLBACK_DATA Data, _In_ PSTAGE_STREAM Stream)
{
    PFILE_RENAME_INFORMATION rename = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    PFLT_FILE_NAME_INFORMATION destination = NULL;
    PSTAGE_VIEW view = Stream->View, target = NULL;
    PSTAGE_STREAM targetStream = NULL;
    PSTAGE_TOMBSTONE old = NULL, reused = NULL;
    BOOLEAN hidePublic = FALSE;
    PSAFEUPLOAD_EXCHANGE exchange = NULL;
    ULONG length = Data->Iopb->Parameters.SetFileInformation.Length;
#if !SAFEUPLOAD_STAGING_PROTOTYPE
    ULONG basename;
#endif
    BOOLEAN extended = Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformationEx;
    BOOLEAN replace, posix;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    BOOLEAN targetPinned = FALSE;
    LONG64 viewGeneration = 0, targetGeneration = 0, namespaceSequence = 0;
    GUID transferSnapshot;
    UINT64 destinationGenerationSnapshot = 0;
    SAFEUPLOAD_STAGE_IDENTITY_V19 stageIdentitySnapshot;
#endif
    NTSTATUS status;
    PAGED_CODE();
    if (!Data->Iopb->TargetFileObject->DeleteAccess) return STATUS_ACCESS_DENIED;
    if (rename == NULL || length < (ULONG)FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName) ||
        rename->FileNameLength == 0 || (rename->FileNameLength & 1) ||
        rename->FileNameLength > length - (ULONG)FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName))
        return STATUS_INVALID_PARAMETER;
    replace = extended ? BooleanFlagOn(*(PULONG)rename, FILE_RENAME_REPLACE_IF_EXISTS) : rename->ReplaceIfExists;
    posix = extended && BooleanFlagOn(*(PULONG)rename, FILE_RENAME_POSIX_SEMANTICS);
    if (extended && FlagOn(*(PULONG)rename, ~(FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS)))
        return STATUS_NOT_SUPPORTED;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    StageWaitHandleReceiptSettled(Stream, FALSE);
#endif
    StageAcquire(&StageNamespaceResource);
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (InterlockedCompareExchange(&StageDirectoryMutationActive, 0, 0) != 0) {
        status = STATUS_SHARING_VIOLATION; goto Exit;
    }
    if (Stream->PrivateCancellationBusy || Stream->PrivateCancellationAccepted) {
        status = STATUS_DELETE_PENDING;
        goto Exit;
    }
    if ((Stream->AnyHandleCleanupObserved && !Stream->HandleReceiptAcknowledged) ||
        Stream->HandleReceiptPending || Stream->HandleReceiptInFlight) {
        status = STATUS_ACCESS_DENIED;
        goto Exit;
    }
#endif
    if (Stream->DiscardOnClose) { status = STATUS_DELETE_PENDING; goto Exit; } /* T5: a deleted version is not renamed */
    if (StageStopping || view->Detached || view->Current != Stream || Stream->RenameExchange != NULL ||
        (Stream->ReadOnly && !Stream->Sealed)) {
        status = STATUS_SHARING_VIOLATION; goto Exit;
    }
    status = FltGetDestinationFileNameInformation(Stream->OriginalInstance,
        Data->Iopb->TargetFileObject, rename->RootDirectory, rename->FileName,
        rename->FileNameLength, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY |
            FLT_FILE_NAME_REQUEST_FROM_CURRENT_PROVIDER, &destination);
    if (!NT_SUCCESS(status)) goto Exit;
    status = FltParseFileNameInformation(destination);
    if (!NT_SUCCESS(status)) goto Exit;
    if (destination->Name.Length > sizeof(Stream->NameBuffer) || destination->Stream.Length != 0) {
        status = STATUS_NOT_SUPPORTED; goto Exit;
    }
    if (destination->Volume.Length != Stream->VolumeLength ||
        RtlCompareMemory(Stream->Name.Buffer, destination->Volume.Buffer, Stream->VolumeLength) != Stream->VolumeLength) {
        status = STATUS_NOT_SAME_DEVICE; goto Exit;
    }
    if (RtlEqualUnicodeString(&view->Name, &destination->Name, TRUE)) { status = STATUS_SUCCESS; goto Exit; }
    StageAcquire(&Stream->Resource);
    status = StageRenameShareAllowed(&Stream->ShareAccess, Data->Iopb->TargetFileObject) ?
        STATUS_SUCCESS : STATUS_SHARING_VIOLATION;
    StageRelease(&Stream->Resource);
    if (!NT_SUCCESS(status)) goto Exit;
    target = StageFindView(view->Owner, &destination->Name);
    if (target != NULL && !replace) { status = STATUS_OBJECT_NAME_COLLISION; goto Exit; }
#if SAFEUPLOAD_STAGING_PROTOTYPE
    viewGeneration = view->Generation;
    namespaceSequence = StageDirectorySequence;
    if (target != NULL) {
        targetStream = target->Current;
        targetGeneration = target->Generation;
        if (targetStream == NULL) { status = STATUS_SHARING_VIOLATION; goto Exit; }
        StageAcquire(&targetStream->Resource);
        status = StageBasicReadonly(targetStream) ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
        StageRelease(&targetStream->Resource);
        if (!NT_SUCCESS(status)) goto Exit;
        InterlockedIncrement(&targetStream->RpcReferences);
        targetPinned = TRUE;
    }
#endif
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (targetStream != NULL && targetStream->Sealed) {
        BOOLEAN closed;
        /* Pin retains target->Security even after cancellation detaches its
         * view. Check the original caller BEFORE irreversible cancellation. */
        StageAcquire(&targetStream->Resource);
        closed = targetStream->ShareAccess.OpenCount == 0;
        StageRelease(&targetStream->Resource);
        if (!closed) { status = STATUS_SHARING_VIOLATION; goto Exit; }
        destinationGenerationSnapshot = Stream->DestinationGeneration;
        StageRelease(&StageNamespaceResource);
        status = StageRenameAuthorizeReplacement(Data, Stream, target, &destination->Name, replace);
        StageAcquire(&StageNamespaceResource);
        if (!NT_SUCCESS(status)) goto Exit; /* No cancel on a denied replacement. */
        if (view->Current != Stream || view->Detached || view->Generation != viewGeneration ||
            Stream->DestinationGeneration != destinationGenerationSnapshot || Stream->RenameExchange != NULL ||
            target->Current != targetStream || target->Detached || target->Generation != targetGeneration ||
            StageFindView(view->Owner, &destination->Name) != target ||
            namespaceSequence != StageDirectorySequence ||
            InterlockedCompareExchange(&StageDirectoryMutationActive, 0, 0) != 0) {
            status = STATUS_SHARING_VIOLATION; goto Exit;
        }
        StageRelease(&StageNamespaceResource);
        status = StageCancelSealedPrivate(targetStream, !targetStream->BoundAllocation);
        if (NT_SUCCESS(status))
            status = StageRenameAuthorizeReplacement(Data, Stream, target, &destination->Name, replace);
        StageAcquire(&StageNamespaceResource);
        if (!NT_SUCCESS(status) || view->Current != Stream || view->Detached ||
            view->Generation != viewGeneration || Stream->DestinationGeneration != destinationGenerationSnapshot ||
            Stream->RenameExchange != NULL || namespaceSequence != StageDirectorySequence ||
            InterlockedCompareExchange(&StageDirectoryMutationActive, 0, 0) != 0) {
            status = STATUS_SHARING_VIOLATION; goto Exit;
        }
        if (target->Current != targetStream || target->Generation != targetGeneration ||
            !RtlEqualUnicodeString(&target->Name, &destination->Name, TRUE)) {
            status = STATUS_SHARING_VIOLATION; goto Exit;
        }
        InterlockedDecrement(&targetStream->RpcReferences);
        StageQueueStream(targetStream, &StageCounters.WakeInline);
        targetPinned = FALSE;
        target = StageFindView(view->Owner, &destination->Name);
        if (target != NULL) { status = STATUS_SHARING_VIOLATION; goto Exit; }
        targetStream = NULL;
    }
#endif
    if (target != NULL) {
        PSTAGE_STREAM replaced = target->Current;
        status = SafeUploadStageCheckSubjectAccess(Data, target->Security, DELETE);
        if (!NT_SUCCESS(status)) goto Exit;
        StageAcquire(&replaced->Resource);
        if (StageBasicReadonly(replaced)) status = STATUS_ACCESS_DENIED;
        else if (replaced->RenameExchange != NULL || (replaced->ReadOnly && !replaced->Sealed) ||
            (!posix && replaced->ShareAccess.OpenCount != 0) ||
            replaced->ShareAccess.OpenCount != replaced->ShareAccess.SharedDelete ||
            replaced->Sections.ImageSectionObject != NULL)
            status = STATUS_SHARING_VIOLATION;
        StageRelease(&replaced->Resource);
        if (!NT_SUCCESS(status)) goto Exit;
    }
    status = SafeUploadStageCheckRenameAccess(Data, Stream->OriginalInstance, &destination->Name, replace);
    if (!NT_SUCCESS(status)) goto Exit;
    /* The name being left stays logically absent for the owner while a public file has it (the service publishes the move
     * later). One record per owner and name: an existing one is reused. Allocated before the exchange so that the commit
     * cannot fail; a full table refuses the rename (fails closed). A name with no public file needs no record: an
     * application's private temporary names would otherwise fill the table for the life of the process. */
    reused = StageHiddenTombstone(view->Owner, &view->Name);
    if (reused == NULL) {
        FILE_ID_INFORMATION publicIdentity;
        NTSTATUS publicStatus = SafeUploadStageQueryIdentity(Stream->OriginalInstance, &view->Name, FALSE, &publicIdentity);
        hidePublic = publicStatus != STATUS_OBJECT_NAME_NOT_FOUND && publicStatus != STATUS_OBJECT_PATH_NOT_FOUND;
    }
    if (reused == NULL && hidePublic) {
        if (StageTombstoneCount >= STAGE_TOMBSTONE_LIMIT) {
            InterlockedIncrement64((volatile LONG64 *)&StageCounters.TombstoneRefusals);
            status = STATUS_INSUFFICIENT_RESOURCES; goto Exit;
        }
        old = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*old) + view->Name.Length, STAGE_TAG);
        if (old == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
        old->Name.Buffer = (PWCH)(old + 1);
        old->Name.Length = old->Name.MaximumLength = view->Name.Length;
        RtlCopyMemory(old->Name.Buffer, view->Name.Buffer, view->Name.Length);
    }
    exchange = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*exchange), STAGE_TAG);
    if (exchange == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    exchange->Request.Version = SAFEUPLOAD_PROTOCOL_VERSION;
    exchange->Request.StructSize = sizeof(SAFEUPLOAD_REQUEST);
    exchange->Request.RequestId = (UINT64)InterlockedIncrement64(&SafeUploadData.NextRequestId);
    exchange->Request.Operation = SAFEUPLOAD_OPERATION_STAGE_RENAME;
    exchange->Request.RequestorProcessId = view->OwnerProcessId;
    exchange->Request.PathLength = destination->Name.Length;
    RtlCopyMemory(exchange->Request.Path, destination->Name.Buffer, destination->Name.Length);
#if SAFEUPLOAD_STAGING_PROTOTYPE
    {
        PSAFEUPLOAD_STAGE_RENAME_V20 source = (PSAFEUPLOAD_STAGE_RENAME_V20)exchange->Request.ImageName;
        exchange->Request.Reserved = SAFEUPLOAD_STAGE_EXTENSION_VERSION;
        exchange->Request.ImageNameLength = sizeof(*source);
        if (StageVolumeKind(Stream->OriginalInstance) == SafeUploadVolumeRemovable)
            exchange->Request.Flags = SAFEUPLOAD_REQUEST_FLAG_STAGE_REMOVABLE;
        else if (StageVolumeKind(Stream->OriginalInstance) == SafeUploadVolumeNetwork)
            exchange->Request.Flags = SAFEUPLOAD_REQUEST_FLAG_STAGE_NETWORK;
        source->Version = SAFEUPLOAD_STAGE_EXTENSION_VERSION;
        source->StructSize = sizeof(*source);
        source->Operation = SAFEUPLOAD_OPERATION_STAGE_RENAME;
        source->RequestId = exchange->Request.RequestId;
        source->TransferId = Stream->TransferId;
        source->SourceGeneration = Stream->DestinationGeneration;
        source->StageIdentity = Stream->StageIdentity;
        source->DriverInstanceId = Stream->DriverInstanceId;
        source->ParentDirectoryIdentity = Stream->AllocationParentDirectoryIdentity;
        source->ViewGeneration = (UINT64)view->Generation;
        source->OwnerProcessId = view->OwnerProcessId;
        source->SealedVersion = Stream->Sealed ? 1 : 0;
    }
#else
    exchange->Request.Reserved = Stream->Sealed ? 1 : 0;
    basename = Stream->StageName.Length / sizeof(WCHAR);
    while (basename > 0 && Stream->StageName.Buffer[basename - 1] != L'\\') --basename;
    exchange->Request.ImageNameLength = 32 * sizeof(WCHAR);
    RtlCopyMemory(exchange->Request.ImageName, Stream->StageName.Buffer + basename, 32 * sizeof(WCHAR));
#endif
    StageAcquire(&Stream->Resource);
    {
        KIRQL irql;
        StageStreamAcquireSpinLock(&StageListLock, &irql); /* a disposal arriving from now on is deferred */
        Stream->RenameExchange = exchange;
        StageStreamReleaseSpinLock(&StageListLock, irql);
    }
    StageRelease(&Stream->Resource);
    exchange = NULL; /* Stream owns uncertain transactions through disconnect. */
#if SAFEUPLOAD_STAGING_PROTOTYPE
    transferSnapshot = Stream->TransferId;
    destinationGenerationSnapshot = Stream->DestinationGeneration;
    stageIdentitySnapshot = Stream->StageIdentity;
    Stream->RenameRpcInFlight = TRUE;
    InterlockedIncrement(&Stream->RpcReferences);
    StageRelease(&StageNamespaceResource);
    status = StageExchangeStatus(Stream->RenameExchange);
    StageAcquire(&StageNamespaceResource);
    Stream->RenameRpcInFlight = FALSE;
    InterlockedDecrement(&Stream->RpcReferences);
    if (targetPinned) {
        InterlockedDecrement(&targetStream->RpcReferences);
        targetPinned = FALSE;
    }
    if (InterlockedCompareExchange(&StageDirectoryMutationActive, 0, 0) != 0 ||
        namespaceSequence != StageDirectorySequence || Stream->RenameExchange == NULL || Stream->View != view ||
        view->Current != Stream || view->Detached || view->Generation != viewGeneration ||
        !RtlEqualMemory(&Stream->TransferId, &transferSnapshot, sizeof(GUID)) ||
        Stream->DestinationGeneration != destinationGenerationSnapshot ||
        !StageV19IdentityEqual(&Stream->StageIdentity, &stageIdentitySnapshot) ||
        (target != NULL && (StageFindView(view->Owner, &destination->Name) != target ||
            target->Current != targetStream || target->Detached || target->Generation != targetGeneration)) ||
        (target == NULL && StageFindView(view->Owner, &destination->Name) != NULL) ||
        !NT_SUCCESS(status) ||
        !NT_SUCCESS(SafeUploadStageCheckRenameAccess(Data, Stream->OriginalInstance,
            &destination->Name, replace))) {
        if (Stream->RenameExchange != NULL)
            StageSetRenameOperation(Stream->RenameExchange, SAFEUPLOAD_OPERATION_STAGE_RENAME_ABORT);
        StageFinishRename(Stream);
        StageQueueStream(Stream, &StageCounters.WakeInline);
        status = STATUS_SHARING_VIOLATION;
        goto Exit;
    }
#else
    if (StageExchangeStatus(Stream->RenameExchange) != STATUS_SUCCESS) {
        StageSetRenameOperation(Stream->RenameExchange, SAFEUPLOAD_OPERATION_STAGE_RENAME_ABORT);
        StageQueueStream(Stream, &StageCounters.WakeInline);
        status = STATUS_SHARING_VIOLATION;
        goto Exit;
    }
#endif
    if (old != NULL || reused != NULL) {
        PSTAGE_TOMBSTONE tombstone = old != NULL ? old : reused;
        PWCH digits = StageTransferDigits(Stream);
        if (old != NULL) {
            old->Owner = view->Owner; ObReferenceObject(old->Owner);
            old->OwnerProcessId = view->OwnerProcessId;
            InsertTailList(&StageTombstones, &old->Link);
            StageTombstoneCount++;
            old = NULL;
        }
        tombstone->Sequence = ++StageNamespaceSequence; /* Caller owns namespace resource. */
        RtlCopyMemory(tombstone->TransferId, digits, sizeof(tombstone->TransferId));
        tombstone->TransferName.Buffer = tombstone->TransferId;
        tombstone->TransferName.Length = tombstone->TransferName.MaximumLength = sizeof(tombstone->TransferId);
    }
    StageAcquire(&Stream->Resource);
    if (target != NULL) target->Detached = TRUE;
    RtlCopyUnicodeString(&Stream->Name, &destination->Name);
    RtlCopyUnicodeString(&view->Name, &destination->Name);
    StageRelease(&Stream->Resource);
    StageDropTombstone(view->Owner, &view->Name); /* the view takes the destination name */
    /* The replaced version is unreachable by name now; it is released once nothing holds it. */
    if (target != NULL) StageQueueStream(target->Current, &StageCounters.WakeInline);
    StageSetRenameOperation(Stream->RenameExchange, SAFEUPLOAD_OPERATION_STAGE_RENAME_COMMIT);
    StageFinishRename(Stream);
    if (Stream->RenameExchange != NULL) KeSetEvent(&StageWorkEvent, IO_NO_INCREMENT, FALSE); /* arm the retry */
    (VOID)FltPurgeFileNameInformationCache(Stream->OriginalInstance, NULL);
    status = STATUS_SUCCESS;
Exit:
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (targetPinned) InterlockedDecrement(&targetStream->RpcReferences);
#endif
    if (exchange != NULL) ExFreePoolWithTag(exchange, STAGE_TAG);
    if (old != NULL) ExFreePoolWithTag(old, STAGE_TAG);
    if (destination != NULL) FltReleaseFileNameInformation(destination);
    StageRelease(&StageNamespaceResource);
    return status;
}

typedef struct _STAGE_PAGING_IO {
    PSTAGE_STREAM Stream;
    PFLT_CALLBACK_DATA Original;
    PVOID AdmissionToken;
    volatile LONG References; /* Submission and completion own one each. */
    volatile LONG State;      /* 0 submitting, 1 pended, 2 completed inline. */
} STAGE_PAGING_IO, *PSTAGE_PAGING_IO;

static NTSTATUS StageClonePagingMdls(PMDL Source, PMDL *Target)
{
    *Target = NULL;
    while (Source != NULL) {
        PMDL mdl = IoAllocateMdl(MmGetMdlVirtualAddress(Source),
            MmGetMdlByteCount(Source), FALSE, FALSE, NULL);
        if (mdl == NULL) return STATUS_INSUFFICIENT_RESOURCES;
        IoBuildPartialMdl(Source, mdl, MmGetMdlVirtualAddress(Source), 0);
        *Target = mdl;
        Target = &mdl->Next;
        Source = Source->Next;
    }
    return STATUS_SUCCESS;
}

static VOID StageReleasePagingIo(PSTAGE_PAGING_IO Io)
{
    if (InterlockedDecrement(&Io->References) == 0)
        ExFreePoolWithTag(Io, STAGE_TAG);
}

static VOID StagePagingComplete(PFLT_CALLBACK_DATA Data, PVOID Context)
{
    PSTAGE_PAGING_IO io = Context;
    PFLT_CALLBACK_DATA original = io->Original;
    original->IoStatus = Data->IoStatus;
    /* The child owns partial MDLs over the original request's still-locked
     * pages. FltFreeCallbackData frees its MDL chain, never the upper MDLs. */
    FltFreeCallbackData(Data);
    if (InterlockedCompareExchange(&io->State, 2, 0) == 1) {
        ExReleaseRundownProtection(&io->Stream->PagingRundown);
        FltCompletePendedPreOperation(original, FLT_PREOP_COMPLETE, NULL);
#if SAFEUPLOAD_STAGING_PROTOTYPE
        SafeUploadPolicyAdmissionRelease((PSAFEUPLOAD_ADMISSION_EPOCH_TOKEN)io->AdmissionToken);
        io->AdmissionToken = NULL;
#endif
    }
    StageReleasePagingIo(io);
}

static FLT_PREOP_CALLBACK_STATUS StageRoutePaging(PFLT_CALLBACK_DATA Data,
    PSTAGE_STREAM Stream, PVOID AdmissionToken)
{
    PSTAGE_PAGING_IO io;
    PFLT_CALLBACK_DATA child = NULL;
    NTSTATUS status;
    FLT_PREOP_CALLBACK_STATUS result;
    if ((Stream->ReadOnly && Data->Iopb->MajorFunction != IRP_MJ_READ) ||
        !ExAcquireRundownProtection(&Stream->PagingRundown)) {
        Data->IoStatus.Status = STATUS_MEDIA_WRITE_PROTECTED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    /* Do not retarget the upper IRP: its actual remaining stack locations can
     * be smaller than the backing device's stack even after the CREATE guard.
     * The generic allocator is needed here for APC-level paging and Cc's
     * AdvanceOnly SET_INFORMATION, preserving the original operation/MDL. */
    if (KeGetCurrentIrql() > APC_LEVEL ||
        (!FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO) && KeGetCurrentIrql() != PASSIVE_LEVEL)) {
        status = STATUS_INVALID_DEVICE_STATE;
        goto Fail;
    }
    if (FltIsIoCanceled(Data)) { status = STATUS_CANCELLED; goto Fail; }
    io = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*io), STAGE_TAG);
    if (io == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Fail; }
    status = FltAllocateCallbackDataEx(Stream->BackingInstance, Stream->BackingObject,
        FLT_ALLOCATE_CALLBACK_DATA_PREALLOCATE_ALL_MEMORY, &child);
    if (!NT_SUCCESS(status)) { ExFreePoolWithTag(io, STAGE_TAG); goto Fail; }
    child->Iopb->MajorFunction = Data->Iopb->MajorFunction;
    child->Iopb->MinorFunction = Data->Iopb->MinorFunction;
    child->Iopb->OperationFlags = Data->Iopb->OperationFlags;
    child->Iopb->Parameters = Data->Iopb->Parameters;
    if (Data->Iopb->MajorFunction == IRP_MJ_READ || Data->Iopb->MajorFunction == IRP_MJ_WRITE) {
        PMDL sourceMdl = Data->Iopb->MajorFunction == IRP_MJ_READ ?
            Data->Iopb->Parameters.Read.MdlAddress : Data->Iopb->Parameters.Write.MdlAddress;
        PMDL *targetMdl = Data->Iopb->MajorFunction == IRP_MJ_READ ?
            &child->Iopb->Parameters.Read.MdlAddress : &child->Iopb->Parameters.Write.MdlAddress;
        status = StageClonePagingMdls(sourceMdl, targetMdl);
        if (!NT_SUCCESS(status)) {
            FltFreeCallbackData(child);
            ExFreePoolWithTag(io, STAGE_TAG);
            goto Fail;
        }
    }
    /* Buffer ownership, allocation and completion flags belong to the newly
     * generated IRP. Only the original I/O semantics are transferable. */
    child->Iopb->IrpFlags = Data->Iopb->IrpFlags &
        (IRP_NOCACHE | IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO);
    child->Iopb->TargetInstance = Stream->BackingInstance;
    child->Iopb->TargetFileObject = Stream->BackingObject;
    io->Stream = Stream;
    io->Original = Data;
    io->AdmissionToken = AdmissionToken;
    io->References = 2;
    io->State = 0;
    /* FltPerformAsynchronousIo always invokes completion, even on failure;
     * completion may run before this call returns. Both paths complete the
     * upper operation exactly once and release rundown only after lower I/O. */
    (VOID)FltPerformAsynchronousIo(child, StagePagingComplete, io);
    if (InterlockedCompareExchange(&io->State, 1, 0) == 2) {
        ExReleaseRundownProtection(&Stream->PagingRundown);
        result = FLT_PREOP_COMPLETE;
    } else result = FLT_PREOP_PENDING;
    StageReleasePagingIo(io);
    return result;
Fail:
    ExReleaseRundownProtection(&Stream->PagingRundown);
    Data->IoStatus.Status = status;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}


static FLT_PREOP_CALLBACK_STATUS StagePreOperationCore(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, PVOID *CompletionContext,
    PSTAGE_ADMISSION_TOKEN_SLOT AdmissionSlot)
{
    PSTAGE_STREAM stream;
    PSTAGE_HANDLE handle;
    PFILE_OBJECT file = Data->Iopb->TargetFileObject;
    NTSTATUS status = STATUS_NOT_SUPPORTED;
    UNREFERENCED_PARAMETER(Objects);
    *CompletionContext = NULL;
    stream = StageStreamForObject(file);
    if (stream == NULL) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (Data->Iopb->MajorFunction == IRP_MJ_QUERY_OPEN) return FLT_PREOP_DISALLOW_FSFILTER_IO;
    if (FLT_IS_FASTIO_OPERATION(Data)) return FLT_PREOP_DISALLOW_FASTIO;
    Data->IoStatus.Information = 0;
    handle = file->FsContext2;
    switch (Data->Iopb->MajorFunction) {
    case IRP_MJ_LOCK_CONTROL:
        if (handle == NULL || handle->Cleaned) { status = STATUS_FILE_CLOSED; break; }
        {
            PEPROCESS process = FltGetRequestorProcess(Data);
            ULONG index;
            FLT_PREOP_CALLBACK_STATUS lockResult;
            if (process == NULL) { status = STATUS_ACCESS_DENIED; break; }
            StageAcquire(&stream->Resource);
            for (index = 0; index < handle->LockOwnerCount; ++index)
                if (handle->LockOwners[index] == process) break;
            if (index == handle->LockOwnerCount) {
                if (index == RTL_NUMBER_OF(handle->LockOwners)) {
                    StageRelease(&stream->Resource);
                    status = STATUS_INSUFFICIENT_RESOURCES; break;
                }
                ObReferenceObject(process);
                handle->LockOwners[handle->LockOwnerCount++] = process;
            }
            /* FltMgr owns waiting, cancellation and completion. The request's
             * file object pins this version until a pending lock completes. */
            lockResult = FltProcessFileLock(stream->ByteLocks, Data, NULL);
            StageRelease(&stream->Resource);
            return lockResult;
        }
    case IRP_MJ_READ:
    case IRP_MJ_WRITE:
        if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) {
            /* The upper cache/section and original request stay on the
             * destination. A separate backing I/O owns paging rundown. */
            FLT_PREOP_CALLBACK_STATUS pagingResult = StageRoutePaging(Data, stream,
                AdmissionSlot != NULL ? AdmissionSlot->Token : NULL);
            if (pagingResult == FLT_PREOP_PENDING && AdmissionSlot != NULL) {
                AdmissionSlot->Token = NULL;
                AdmissionSlot->Owner = StageAdmissionTokenPaging;
            }
            return pagingResult;
        }
        if (handle == NULL || handle->Cleaned) {
            status = STATUS_FILE_CLOSED;
            break;
        }
        status = StageReadWrite(Data, stream);
        break;
    case IRP_MJ_QUERY_INFORMATION:
        status = StageQuery(Data, stream, handle);
        break;
    case IRP_MJ_QUERY_VOLUME_INFORMATION:
        status = FltQueryVolumeInformation(stream->OriginalInstance, &Data->IoStatus,
            Data->Iopb->Parameters.QueryVolumeInformation.VolumeBuffer,
            Data->Iopb->Parameters.QueryVolumeInformation.Length,
            Data->Iopb->Parameters.QueryVolumeInformation.FsInformationClass);
        break;
    case IRP_MJ_SET_INFORMATION:
        if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileEndOfFileInformation &&
            Data->Iopb->Parameters.SetFileInformation.AdvanceOnly) {
            /* Cc may advance the on-disk VDL after cleanup. This is not a
             * resize and must never reinitialize the upper private cache map. */
            return StageRoutePaging(Data, stream,
                AdmissionSlot != NULL ? AdmissionSlot->Token : NULL);
        }
        if (handle == NULL || handle->Cleaned) {
            status = STATUS_FILE_CLOSED;
            break;
        }
        if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation ||
            Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformationEx) {
            if (KeGetCurrentIrql() != PASSIVE_LEVEL) status = STATUS_INVALID_DEVICE_STATE;
            else status = StageRename(Data, stream);
        }
        else if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformation ||
            Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformationEx)
            status = StageSetDisposition(Data, stream, handle);
        else if ((stream->ReadOnly || stream->RenameExchange != NULL) &&
            Data->Iopb->Parameters.SetFileInformation.FileInformationClass != FilePositionInformation) {
            status = STATUS_ACCESS_DENIED;
        }
        else if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileBasicInformation)
            status = KeGetCurrentIrql() == PASSIVE_LEVEL ?
                StageSetBasicInformation(Data, stream, handle->GrantedAccess) : STATUS_INVALID_DEVICE_STATE;
        else if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileEndOfFileInformation &&
            Data->Iopb->Parameters.SetFileInformation.Length >= sizeof(FILE_END_OF_FILE_INFORMATION)) {
            StageAcquire(&stream->Resource);
            __try {
                status = StageResize(stream, file,
                    ((PFILE_END_OF_FILE_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer)->EndOfFile);
            } __except(EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
            StageRelease(&stream->Resource);
        } else if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FilePositionInformation &&
            Data->Iopb->Parameters.SetFileInformation.Length >= sizeof(FILE_POSITION_INFORMATION)) {
            LARGE_INTEGER position = ((PFILE_POSITION_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer)->CurrentByteOffset;
            if (position.QuadPart >= 0) { file->CurrentByteOffset = position; status = STATUS_SUCCESS; }
            else status = STATUS_INVALID_PARAMETER;
        } else if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileAllocationInformation &&
            Data->Iopb->Parameters.SetFileInformation.Length >= sizeof(FILE_ALLOCATION_INFORMATION)) {
            PFILE_ALLOCATION_INFORMATION allocation = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
            FILE_STANDARD_INFORMATION standard = {0};
            StageAcquire(&stream->Resource);
            __try {
                if (stream->ReadOnly || stream->RenameExchange != NULL)
                    status = STATUS_ACCESS_DENIED;
                else if (allocation->AllocationSize.QuadPart < 0 || allocation->AllocationSize.QuadPart > STAGE_MAX_BYTES)
                    status = STATUS_FILE_TOO_LARGE;
                else {
                    status = STATUS_SUCCESS;
                    if (allocation->AllocationSize.QuadPart < stream->Header.FileSize.QuadPart)
                        status = StageResize(stream, file, allocation->AllocationSize);
                    if (NT_SUCCESS(status)) status = FltSetInformationFile(stream->BackingInstance,
                        stream->BackingObject, allocation, sizeof(*allocation), FileAllocationInformation);
                    if (NT_SUCCESS(status)) status = FltQueryInformationFile(stream->BackingInstance,
                        stream->BackingObject, &standard, sizeof(standard), FileStandardInformation, NULL);
                    if (NT_SUCCESS(status)) {
                        stream->Header.AllocationSize = standard.AllocationSize;
                        if (stream->Sections.SharedCacheMap != NULL) {
                            CC_FILE_SIZES sizes;
                            StageInitializeCache(stream, file);
                            sizes.AllocationSize = standard.AllocationSize;
                            sizes.FileSize = stream->Header.FileSize;
                            sizes.ValidDataLength = stream->Header.ValidDataLength;
                            CcSetFileSizes(file, &sizes);
                        }
                    }
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
            StageRelease(&stream->Resource);
        }
        break;
    case IRP_MJ_FLUSH_BUFFERS:
        status = StageFlush(stream);
        break;
    case IRP_MJ_CLEANUP:
        if (handle != NULL && !handle->Cleaned) {
            ULONG index;
            BOOLEAN lastHandle;
            BOOLEAN queueReceipt;
            PSAFEUPLOAD_STAGE_WRITER_LEASE writerLease;
            PSAFEUPLOAD_STAGE_WRITER_LEASE evidenceToClose = NULL;
            /* Combined public hold closes before any dependent private drain;
             * ordinary disposition never changes private data routing. */
            SafeUploadStageNativeCloseWriter(Objects->Instance, file);
            StageAcquire(&StageNamespaceResource);
            StageAcquire(&stream->Resource);
            /* Monotonic evidence: once any user file object observes CLEANUP,
             * publication/discard must wait for the exact op19 receipt. */
            stream->AnyHandleCleanupObserved = TRUE;
            if (!stream->HandleReceiptAcknowledged) {
                stream->HandleReceiptPending = TRUE;
                queueReceipt = TRUE;
            } else queueReceipt = FALSE;
            stream->DrainStatus = StageFlush(stream);
            if (handle->DeleteOnClose) {
                if (!stream->ReadOnly) stream->DiscardDisposition = TRUE;
                if (stream->DeleteOnCloseCount != 0) --stream->DeleteOnCloseCount;
                handle->DeleteOnClose = FALSE;
            }
            stream->DiscardOnClose = stream->DiscardDisposition || stream->DeleteOnCloseCount != 0;
            IoRemoveShareAccess(file, &stream->ShareAccess);
            handle->Cleaned = TRUE;
            writerLease = handle->WriterLease;
            handle->WriterLease = NULL;
            if (stream->BoundAllocation && stream->PublicationWriterLease == NULL && writerLease != NULL) {
                stream->PublicationWriterLease = writerLease;
                evidenceToClose = writerLease; /* Close outside callback-needed resources below. */
                writerLease = NULL;
            }
            /* Cleanup can run in a different process from a lock issued via
             * a duplicate. Retain and unlock every participating process. */
            for (index = 0; index < handle->LockOwnerCount; ++index)
                (VOID)FsRtlFastUnlockAll(stream->ByteLocks, file, handle->LockOwners[index], NULL);
            SetFlag(file->Flags, FO_CLEANUP_COMPLETE);
            (VOID)CcUninitializeCacheMap(file, NULL, NULL);
            lastHandle = stream->ShareAccess.OpenCount == 0;
            if (lastHandle && stream->DiscardOnClose && !stream->Sealed) {
                /* Name ownership ends at last cleanup. The old version stays
                 * in the retained stream list until local drain and the exact
                 * service cleanup ACK; no new create reuses its identity. */
                if (stream->View != NULL && stream->View->Current == stream)
                    stream->View->Detached = TRUE;
                stream->PrivateDeleteReserved = FALSE;
            }
            queueReceipt = queueReceipt || stream->HandleReceiptPending;
            StageRelease(&stream->Resource);
            StageRelease(&StageNamespaceResource);
            if (evidenceToClose != NULL) {
                SafeUploadStagePublicCloseWriterEvidence(evidenceToClose);
                StageAcquire(&StageNamespaceResource);
                stream->PublicationEvidenceClosed = TRUE;
                StageRelease(&StageNamespaceResource);
            }
            if (writerLease != NULL) {
                /* CLEANUP is a PASSIVE callback; this branch documents the
                 * local-I/O contract without touching legacy null owners. */
                NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
                SafeUploadStagePublicReleaseWriter(writerLease);
            }
            /* T4: the last handle is gone; this file object keeps the stream allocated while it is queued. */
            if (lastHandle || queueReceipt) StageQueueStream(stream, &StageCounters.WakeCleanup);
        }
        status = STATUS_SUCCESS;
        break;
    case IRP_MJ_CLOSE:
        if (handle != NULL) {
            ULONG index;
            KIRQL irql;
            BOOLEAN last;
            for (index = 0; index < handle->LockOwnerCount; ++index)
                ObDereferenceObject(handle->LockOwners[index]);
            /* Canceled original CREATE may reach CLOSE without CLEANUP. */
            if (handle->WriterLease != NULL) {
                NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
                SafeUploadStageNativeCloseWriter(Objects->Instance, file);
                SafeUploadStagePublicReleaseWriter(handle->WriterLease);
                handle->WriterLease = NULL;
            }
            ExFreePoolWithTag(handle, STAGE_TAG);
            file->FsContext2 = NULL;
            InterlockedDecrement(&StageFileObjects);
            /* T4: the decrement and the queueing are one step under StageListLock. The worker releases a stream only when it
             * sees FileObjects == 0 and the stream not queued under this lock, so it cannot free the stream between them.
             * Nothing may touch the stream after the lock is released. */
            StageStreamAcquireSpinLock(&StageListLock, &irql);
            last = InterlockedDecrement(&stream->FileObjects) == 0;
            if (last) (VOID)StageQueueLocked(stream);
            StageStreamReleaseSpinLock(&StageListLock, irql);
            if (last) {
                InterlockedIncrement64((volatile LONG64 *)&StageCounters.WakeClose);
                KeSetEvent(&StageWorkEvent, IO_NO_INCREMENT, FALSE);
            }
        }
        status = STATUS_SUCCESS;
        break;
    case IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION:
        StageAcquire(&stream->Resource);
        if (((stream->ReadOnly || stream->RenameExchange != NULL) ||
             !SafeUploadIsAuthenticatedClient() ||
             !SafeUploadInstanceTrustGateSatisfied(stream->OriginalInstance)) &&
            Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType == SyncTypeCreateSection &&
            FlagOn(Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection,
                PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) {
            StageRelease(&stream->Resource);
            status = STATUS_ACCESS_DENIED;
        } else status = STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY;
        break;
    case IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION:
        StageRelease(&stream->Resource);
        status = STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY;
        break;
    case IRP_MJ_ACQUIRE_FOR_MOD_WRITE:
        KeEnterCriticalRegion();
        if (ExAcquireResourceSharedLite(&stream->PagingResource, FALSE)) {
            *Data->Iopb->Parameters.AcquireForModifiedPageWriter.ResourceToRelease = &stream->PagingResource;
            status = STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY;
        } else { KeLeaveCriticalRegion(); status = STATUS_CANT_WAIT; }
        break;
    case IRP_MJ_RELEASE_FOR_MOD_WRITE:
        StageRelease(&stream->PagingResource);
        status = STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY;
        break;
    case IRP_MJ_ACQUIRE_FOR_CC_FLUSH:
        StageAcquire(&stream->PagingResource);
        status = STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY;
        break;
    case IRP_MJ_RELEASE_FOR_CC_FLUSH:
        StageRelease(&stream->PagingResource);
        status = STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY;
        break;
    default:
        break; /* Never let a foreign filesystem decode an owned upper FCB. */
    }
    Data->IoStatus.Status = status;
    if (status == STATUS_NOT_SUPPORTED &&
        (Data->Iopb->MajorFunction == IRP_MJ_SET_EA ||
         (Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION &&
          Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileBasicInformation)))
        SafeUploadDenyDetail(Data, SAFEUPLOAD_DENY_REASON_METADATA_UNSUPPORTED, status, &stream->Name);
    if (!NT_SUCCESS(status) || Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[SafeUploadStage] op=%u class=%u status=%08x\n", Data->Iopb->MajorFunction,
            Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION ?
                Data->Iopb->Parameters.SetFileInformation.FileInformationClass : 0, status);
    }
    return FLT_PREOP_COMPLETE;
}

static FLT_PREOP_CALLBACK_STATUS StagePreOperation(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, PVOID *CompletionContext,
    PSTAGE_ADMISSION_TOKEN_SLOT AdmissionSlot)
{
    FLT_PREOP_CALLBACK_STATUS result;
    if (!ExAcquireRundownProtection(&StageOwnedCallbackBodies)) {
        *CompletionContext = NULL;
        Data->IoStatus.Status = STATUS_FLT_DELETING_OBJECT;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    result = StagePreOperationCore(Data, Objects, CompletionContext, AdmissionSlot);
    ExReleaseRundownProtection(&StageOwnedCallbackBodies);
    return result;
}

NTSTATUS SafeUploadStageGenerateName(PFLT_INSTANCE Instance, PFILE_OBJECT FileObject,
    PFLT_CALLBACK_DATA Data, FLT_FILE_NAME_OPTIONS Options, PBOOLEAN CacheName,
    PFLT_NAME_CONTROL Output)
{
    PSTAGE_STREAM stream = StageStreamForObject(FileObject);
    PFLT_FILE_NAME_INFORMATION lower = NULL;
    NTSTATUS status;
    /* The bounded probe deliberately avoids a second namespace cache. Names
     * can change on every upper handle when a virtual rename completes. */
    *CacheName = FALSE;
    if (stream != NULL) {
        if (FltGetFileNameFormat(Options) == FLT_FILE_NAME_SHORT)
            return STATUS_OBJECT_NAME_NOT_FOUND;
        if (!ExAcquireRundownProtection(&StageOwnedCallbackBodies)) return STATUS_FLT_DELETING_OBJECT;
        StageAcquire(&stream->Resource);
        status = FltCheckAndGrowNameControl(Output, stream->Name.Length);
        if (NT_SUCCESS(status)) RtlCopyUnicodeString(&Output->Name, &stream->Name);
        StageRelease(&stream->Resource);
        ExReleaseRundownProtection(&StageOwnedCallbackBodies);
        return status;
    }
    Options &= ~FLT_FILE_NAME_REQUEST_FROM_CURRENT_PROVIDER;
    Options |= FLT_FILE_NAME_DO_NOT_CACHE;
    if (Data != NULL) status = FltGetFileNameInformation(Data, Options, &lower);
    else status = FltGetFileNameInformationUnsafe(FileObject, Instance, Options, &lower);
    if (NT_SUCCESS(status)) {
        status = FltCheckAndGrowNameControl(Output, lower->Name.Length);
        if (NT_SUCCESS(status)) RtlCopyUnicodeString(&Output->Name, &lower->Name);
        FltReleaseFileNameInformation(lower);
    }
    return status;
}

NTSTATUS SafeUploadStageNormalizeComponent(PFLT_INSTANCE Instance, PCUNICODE_STRING Parent,
    USHORT VolumeNameLength, PCUNICODE_STRING Component, PFILE_NAMES_INFORMATION Output,
    ULONG Length, FLT_NORMALIZE_NAME_FLAGS Flags, PVOID *Context)
{
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io;
    HANDLE directory = NULL;
    PFILE_OBJECT object = NULL;
    UNICODE_STRING parent = *Parent, component = *Component;
    ULONG returned;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(VolumeNameLength);
    UNREFERENCED_PARAMETER(Context);
    InitializeObjectAttributes(&attributes, &parent, OBJ_KERNEL_HANDLE |
        (FlagOn(Flags, FLTFL_NORMALIZE_NAME_CASE_SENSITIVE) ? 0 : OBJ_CASE_INSENSITIVE), NULL, NULL);
    status = FltCreateFileEx(SafeUploadData.Filter, Instance, &directory, &object,
        FILE_LIST_DIRECTORY | SYNCHRONIZE, &attributes, &io, NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0, IO_IGNORE_SHARE_ACCESS_CHECK);
    if (NT_SUCCESS(status)) {
        status = FltQueryDirectoryFile(Instance, object, Output, Length,
            FileNamesInformation, TRUE, &component, TRUE, &returned);
        ObDereferenceObject(object);
        FltClose(directory);
    }
    return status;
}


/* Caller owns NamespaceResource, then Resource. Sections cannot be recreated
 * without an upper file object; the namespace lock excludes fresh CREATEs. */
static NTSTATUS StageDrain(PSTAGE_STREAM Stream)
{
    NTSTATUS status;
    if (Stream->ShareAccess.OpenCount != 0) return STATUS_DEVICE_BUSY;
    /* A user-mapped view, or a section that survives the purge, ends with no request to the file system (an unmap sends none),
     * so the retry timer covers that wait: STATUS_USER_MAPPED_FILE. Handles and file objects end with cleanup and close
     * events: STATUS_DEVICE_BUSY. */
    if (!MmCanFileBeTruncated(&Stream->Sections, NULL)) return STATUS_USER_MAPPED_FILE;
    status = StageFlush(Stream);
    if (!NT_SUCCESS(status)) return status;
    if (!CcPurgeCacheSection(&Stream->Sections, NULL, 0, TRUE) ||
        Stream->Sections.SharedCacheMap != NULL || Stream->Sections.DataSectionObject != NULL ||
        Stream->Sections.ImageSectionObject != NULL) return STATUS_USER_MAPPED_FILE;
    if (InterlockedCompareExchange(&Stream->FileObjects, 0, 0) != 0) return STATUS_DEVICE_BUSY;
    /* Postoperations, including asynchronous paging and Cc AdvanceOnly, release
     * this rundown. It is forbidden to close the backing before they finish. */
    ExWaitForRundownProtectionRelease(&Stream->PagingRundown);
    status = Stream->ReadOnly ? STATUS_SUCCESS : FltFlushBuffers(Stream->BackingInstance, Stream->BackingObject);
    ExReInitializeRundownProtection(&Stream->PagingRundown);
    return status;
}

/* A sealed version keeps its read-only backing open so that its owner can still read it. The backing is opened with
 * FILE_SHARE_DELETE so the service can remove the stage (BLOCK cleanup after the hand-back window): NTFS then marks it delete-pending
 * and keeps the name until the last handle closes. Once nobody holds the version (no handle, file object or section) and the
 * backing is delete-pending, close it so the file really goes away, and detach the private view so later opens resolve to the
 * public name. Before this, no sealed stage could ever be deleted while the driver was loaded (sharing violation on every try).
 * Caller owns NamespaceResource. Returns TRUE when the version was retired. */
static BOOLEAN StageRetireDeletedStream(PSTAGE_STREAM Stream)
{
    FILE_STANDARD_INFORMATION standard;
    NTSTATUS status;
    BOOLEAN retired = FALSE;
    StageAcquire(&Stream->Resource);
    if (Stream->BackingObject != NULL && Stream->ShareAccess.OpenCount == 0 &&
        InterlockedCompareExchange(&Stream->FileObjects, 0, 0) == 0 &&
        Stream->Sections.SharedCacheMap == NULL && Stream->Sections.DataSectionObject == NULL &&
        Stream->Sections.ImageSectionObject == NULL) {
        RtlZeroMemory(&standard, sizeof(standard));
        status = FltQueryInformationFile(Stream->BackingInstance, Stream->BackingObject,
            &standard, sizeof(standard), FileStandardInformation, NULL);
        if (NT_SUCCESS(status) && standard.DeletePending) {
            /* No handle, file object or section exists, so no paging I/O can be in flight; the wait is the same barrier StageDrain
             * uses, and the rundown is re-armed so the unload path's wait on this stream still returns. */
            ExWaitForRundownProtectionRelease(&Stream->PagingRundown);
            StageCloseBacking(Stream);
            Stream->Retired = TRUE;
            retired = TRUE;
            if (Stream->View != NULL && Stream->View->Current == Stream) Stream->View->Detached = TRUE;
            ExReInitializeRundownProtection(&Stream->PagingRundown);
        }
    }
    StageRelease(&Stream->Resource);
    return retired;
}

/* ---- T4: the stage worker runs on events, not on a 250 ms poll (driver/T4-STAGE-LIFETIME.md) ---- */

_IRQL_requires_(DISPATCH_LEVEL)
static BOOLEAN StageQueueLocked(PSTAGE_STREAM Stream)
{
    if (Stream->WorkQueued) return FALSE;
    InsertTailList(&StageWorkQueue, &Stream->WorkLink);
    Stream->WorkQueued = TRUE;
    return TRUE;
}

/* The caller keeps the stream allocated across the call: it owns a live file object of the stream or NamespaceResource. */
static VOID StageQueueStream(PSTAGE_STREAM Stream, volatile UINT64 *Reason)
{
    KIRQL irql;
    StageStreamAcquireSpinLock(&StageListLock, &irql);
    (VOID)StageQueueLocked(Stream);
    StageStreamReleaseSpinLock(&StageListLock, irql);
    if (Reason != NULL) InterlockedIncrement64((volatile LONG64 *)Reason);
    KeSetEvent(&StageWorkEvent, IO_NO_INCREMENT, FALSE);
}

/* Caller owns NamespaceResource. T5 (driver/T5-DELETES.md R3): the owner deleted this never-sealed version. Once the service has
 * journaled it Discarded (and removed the stage), the version is terminal like a sealed one but never inspected or published: it
 * leaves the owner's namespace and is released when nothing holds it. The public name, if any, is untouched. */
static VOID StageDiscardVersion(PSTAGE_STREAM Stream)
{
#if SAFEUPLOAD_STAGING_PROTOTYPE
    /* Never call the service while NamespaceResource is held. The worker
     * pins and exchanges this exact version after dropping that resource. */
    if (!Stream->StageIdentityValid || !Stream->HasTransferId) {
        Stream->Wait = STAGE_WAIT_EXCHANGE;
        return;
    }
    Stream->DiscardRpcKind = SAFEUPLOAD_STAGE_DISCARD_KIND_PRIVATE_VERSION;
    Stream->DiscardRpcPending = TRUE;
    Stream->Wait = STAGE_WAIT_EXCHANGE;
#else
    NTSTATUS status = SafeUploadStageDiscard(Stream->View->OwnerProcessId, &Stream->StageName);
    if (NT_SUCCESS(status)) {
        Stream->Discarded = TRUE;
        Stream->Sealed = TRUE;
        Stream->Retired = TRUE;
        Stream->Wait = STAGE_WAIT_NONE;
        if (Stream->View->Current == Stream) Stream->View->Detached = TRUE;
    } else Stream->Wait = status == STATUS_PORT_DISCONNECTED ? STAGE_WAIT_SERVICE : STAGE_WAIT_EXCHANGE;
#endif
}

/* Caller owns NamespaceResource. */
static VOID StageSealVersion(PSTAGE_STREAM Stream)
{
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (!StageBoundSeedReady(Stream)) {
        Stream->DrainStatus = STATUS_DEVICE_NOT_READY;
        Stream->Wait = STAGE_WAIT_SERVICE;
        SafeUploadStagePublicRecordWriterRefusal(StageWriterSeedCompletionUnproved);
        return;
    }
    if (Stream->AttachCompletionPending || Stream->HandleReceiptPending ||
        Stream->HandleReceiptInFlight ||
        (Stream->AnyHandleCleanupObserved && !Stream->HandleReceiptAcknowledged)) {
        Stream->Wait = STAGE_WAIT_SERVICE;
        return;
    }
    if (!Stream->StageIdentityValid || !Stream->HasTransferId ||
        Stream->DestinationGeneration == 0) {
        Stream->Wait = STAGE_WAIT_EXCHANGE;
        return;
    }
    if (!Stream->SealRpcPending && !Stream->SealRpcInFlight) {
        Stream->SealRpcPending = TRUE;
        Stream->Wait = STAGE_WAIT_EXCHANGE;
    }
#else
    NTSTATUS status = SafeUploadStageSeal(Stream->View->OwnerProcessId, &Stream->StageName);
    if (NT_SUCCESS(status)) {
        Stream->Sealed = TRUE;
        Stream->Wait = STAGE_WAIT_NONE;
    } else Stream->Wait = StageWaitFor(status);
#endif
}

/* Caller owns NamespaceResource. The last handle or file object is gone: drain the cache, reopen the backing read-only and
 * send the seal. A drain that waits on handles or file objects ends with an event; any other failure is retried on the timer. */
static VOID StageDrainAndSeal(PSTAGE_STREAM Stream)
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN discard;
    StageAcquire(&Stream->Resource);
    /* No handle remains once the drain succeeds, so the flag cannot change after this read. */
    discard = Stream->DiscardOnClose;
    if (!Stream->ReadOnly) {
        status = StageDrain(Stream);
        if (NT_SUCCESS(status)) {
            StageCloseBacking(Stream);
            Stream->ReadOnly = TRUE; /* Irreversible, even if reopen/notification fails. */
        }
    }
    /* A discarded version keeps its backing closed: the service removes the stage. */
    if (NT_SUCCESS(status) && Stream->BackingObject == NULL && !discard) status = StageOpenBacking(Stream, TRUE);
    StageRelease(&Stream->Resource);
    if (NT_SUCCESS(status)) {
        if (discard) StageDiscardVersion(Stream);
        else StageSealVersion(Stream);
    }
    else Stream->Wait = status == STATUS_DEVICE_BUSY ? STAGE_WAIT_NONE : STAGE_WAIT_DRAIN;
}

/* Caller owns NamespaceResource. A version the service disposed of leaves the namespace once nothing holds it: later opens of
 * the name resolve to the public file (the published bytes, or the pre-save content after a block). While handles remain it
 * stays exactly as before: renames through a handle and follow-up writers need the attached view and the stage file. */
static BOOLEAN StageApplyDisposal(PSTAGE_STREAM Stream)
{
    KIRQL irql;
    BOOLEAN disposed;
    UINT32 outcome;
    StageStreamAcquireSpinLock(&StageListLock, &irql);
    disposed = Stream->Disposed;
    outcome = Stream->DisposeOutcome;
    StageStreamReleaseSpinLock(&StageListLock, irql);
    if (!disposed || !Stream->Sealed || Stream->RenameExchange != NULL ||
        InterlockedCompareExchange(&Stream->FileObjects, 0, 0) != 0) return FALSE;
    if (Stream->View->Current == Stream) Stream->View->Detached = TRUE;
    return outcome == SAFEUPLOAD_STAGE_DISPOSE_RELEASED;
}

/* Caller owns NamespaceResource (StageCreate). Does for the version an open is about to use what the worker would do at its
 * next event: finish a pending rename, resend a seal that failed, retire a version whose stage the service deleted, and detach
 * a version the service disposed of. Returns TRUE when the view left the namespace. */
static BOOLEAN StageSettleCurrent(PSTAGE_VIEW View)
{
    PSTAGE_STREAM stream = View->Current;
    if (stream->RenameExchange != NULL) {
        StageFinishRename(stream);
#if SAFEUPLOAD_STAGING_PROTOTYPE
        StageQueueStream(stream, &StageCounters.WakeInline);
#endif
        if (stream->RenameExchange != NULL) return FALSE;
#if SAFEUPLOAD_STAGING_PROTOTYPE
        return FALSE;
#endif
    }
    if (stream->RenameExchange == NULL && stream->ReadOnly && !stream->Sealed && !stream->DiscardOnClose &&
        stream->BackingObject != NULL) {
        StageSealVersion(stream);
        StageQueueStream(stream, &StageCounters.WakeInline);
    }
    if (stream->RenameExchange == NULL && stream->ReadOnly && !stream->Sealed && stream->DiscardOnClose &&
        stream->BackingObject == NULL)
        StageDiscardVersion(stream);
    if (stream->DiscardOnClose && stream->ReadOnly && !stream->Sealed)
        StageQueueStream(stream, &StageCounters.WakeInline);
    if (stream->Sealed && !stream->Retired) (VOID)StageRetireDeletedStream(stream);
    StageApplyDisposal(stream);
    if (!View->Detached) return FALSE;
    StageQueueStream(stream, &StageCounters.WakeInline);
    return TRUE;
}

/* The service approved and published this version, and nothing holds it: only the driver knows when its handle closes, so it
 * deletes the stage file. The name is opened without following a reparse point and must be the file the backing has open. */
static VOID StageDeleteReleasedStage(PSTAGE_STREAM Stream)
{
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io;
    HANDLE handle = NULL;
    PFILE_OBJECT object = NULL;
    FILE_ID_INFORMATION expected, actual;
    FILE_ATTRIBUTE_TAG_INFORMATION stageAttributes;
    FILE_DISPOSITION_INFORMATION disposition;
    ULONG returned = 0;
    NTSTATUS status;
    if (Stream->BackingObject == NULL) return; /* retired: the service deleted it already */
    status = FltQueryInformationFile(Stream->BackingInstance, Stream->BackingObject, &expected, sizeof(expected),
        FileIdInformation, &returned);
    if (!NT_SUCCESS(status)) goto Exit;
    if (returned != sizeof(expected)) { status = STATUS_INFO_LENGTH_MISMATCH; goto Exit; }
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (!Stream->StageIdentityValid ||
        expected.VolumeSerialNumber != Stream->StageIdentity.VolumeSerialNumber ||
        !RtlEqualMemory(&expected.FileId, &Stream->StageIdentity.FileId, sizeof(expected.FileId))) {
        status = STATUS_OBJECT_NAME_COLLISION;
        goto Exit;
    }
#endif
    InitializeObjectAttributes(&attributes, &Stream->StageName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = FltCreateFileEx2(SafeUploadData.Filter, Stream->BackingInstance, &handle, &object,
        DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attributes, &io, NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0, 0, NULL);
    if (!NT_SUCCESS(status)) goto Exit;
    status = FltQueryInformationFile(Stream->BackingInstance, object, &stageAttributes, sizeof(stageAttributes),
        FileAttributeTagInformation, NULL);
    if (!NT_SUCCESS(status)) goto Exit;
    if (FlagOn(stageAttributes.FileAttributes, FILE_ATTRIBUTE_REPARSE_POINT)) {
        status = STATUS_REPARSE_POINT_ENCOUNTERED;
        goto Exit;
    }
    returned = 0;
    status = FltQueryInformationFile(Stream->BackingInstance, object, &actual, sizeof(actual),
        FileIdInformation, &returned);
    if (!NT_SUCCESS(status)) goto Exit;
    if (returned != sizeof(actual)) { status = STATUS_INFO_LENGTH_MISMATCH; goto Exit; }
    if (actual.VolumeSerialNumber != expected.VolumeSerialNumber ||
        !RtlEqualMemory(&actual.FileId, &expected.FileId, sizeof(actual.FileId))) {
        status = STATUS_OBJECT_NAME_COLLISION;
        goto Exit;
    }
    disposition.DeleteFile = TRUE;
    status = FltSetInformationFile(Stream->BackingInstance, object, &disposition, sizeof(disposition),
        FileDispositionInformation);
Exit:
    if (object != NULL) ObDereferenceObject(object);
    if (handle != NULL) FltClose(handle);
    InterlockedIncrement64((volatile LONG64 *)(NT_SUCCESS(status) ?
        &StageCounters.StageDeletes : &StageCounters.StageDeleteFailures));
}

/* Runs after the worker dropped NamespaceResource: the stream is unreachable (unlinked, no file object, not current of an
 * attached view), so nothing else can touch it. Other filters' stream-context cleanup and the stage delete run here, never under
 * the namespace lock that every staged create takes. */
static VOID StageTeardownReleased(PLIST_ENTRY Released)
{
    while (!IsListEmpty(Released)) {
        PSTAGE_STREAM stream = CONTAINING_RECORD(RemoveHeadList(Released), STAGE_STREAM, Link);
        FsRtlTeardownPerStreamContexts(&stream->Header);
        ExWaitForRundownProtectionRelease(&stream->PagingRundown);
        if (stream->Disposed && stream->DisposeOutcome == SAFEUPLOAD_STAGE_DISPOSE_RELEASED) {
#if SAFEUPLOAD_STAGING_PROTOTYPE
            if (!SafeUploadStageMandatoryTeardownActive()) StageDeleteReleasedStage(stream);
#else
            StageDeleteReleasedStage(stream);
#endif
        }
        StageFreeStream(stream);
        InterlockedIncrement64((volatile LONG64 *)&StageCounters.VersionsReleased);
    }
}

/* Caller owns NamespaceResource. Releases a version nothing can reach any more: sealed, no rename in flight, no handle, file
 * object, section or cache map, and superseded or detached. The final check and the unlink are under StageListLock, which
 * every producer of work for this stream also takes (see the IRP_MJ_CLOSE handler). The unlinked stream goes to Released for
 * StageTeardownReleased. Returns TRUE when the version was released. */
static BOOLEAN StageTryRelease(PSTAGE_STREAM Stream, PLIST_ENTRY Released)
{
    PSTAGE_VIEW view = Stream->View;
    BOOLEAN release;
    KIRQL irql;
    if (!Stream->Sealed || Stream->RenameExchange != NULL) return FALSE;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (InterlockedCompareExchange(&Stream->RpcReferences, 0, 0) != 0 ||
        Stream->PrivateDeleteReserved ||
        Stream->AllocationReceiptPending || Stream->AllocationRecoveryPending ||
        Stream->AllocationRecoveryInFlight || Stream->AllocationReceiptReferences != 0 ||
        Stream->AttachCompletionPending || Stream->HandleReceiptPending ||
        Stream->HandleReceiptInFlight ||
        (Stream->AnyHandleCleanupObserved && !Stream->HandleReceiptAcknowledged) ||
        (Stream->AttachAcknowledged && !Stream->AnyHandleCleanupObserved) ||
        Stream->DiscardRpcPending || Stream->DiscardRpcInFlight ||
        Stream->SealRpcPending || Stream->SealRpcInFlight) return FALSE;
#endif
    if (view->Current == Stream && !view->Detached) return FALSE;
    StageAcquire(&Stream->Resource);
    release = Stream->ShareAccess.OpenCount == 0 && Stream->Sections.SharedCacheMap == NULL &&
        Stream->Sections.DataSectionObject == NULL && Stream->Sections.ImageSectionObject == NULL;
    StageRelease(&Stream->Resource);
    if (!release) return FALSE;
    release = FALSE;
    StageStreamAcquireSpinLock(&StageListLock, &irql);
    if (InterlockedCompareExchange(&Stream->FileObjects, 0, 0) == 0 && !Stream->WorkQueued) {
        RemoveEntryList(&Stream->Link);
        release = TRUE;
    }
    StageStreamReleaseSpinLock(&StageListLock, irql);
    if (!release) return FALSE;
    StageStreamCount--;
    InsertTailList(Released, &Stream->Link); /* Disposed/DisposeOutcome no longer change: nothing can find the stream */
    if (view->Current == Stream) view->Current = NULL; /* only a detached view can lose its current version */
    Stream->View = NULL;
    view->Streams--;
    if (view->Detached && view->Streams == 0) {
        RemoveEntryList(&view->Link);
        StageViewCount--;
        StageFreeView(view);
        InterlockedIncrement64((volatile LONG64 *)&StageCounters.ViewsReleased);
    }
    return TRUE;
}

/* Caller owns NamespaceResource. */
static VOID StageProcessStream(PSTAGE_STREAM Stream, PLIST_ENTRY Released)
{
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (Stream->RenameExchange != NULL) {
        StageFinishRename(Stream);
        return; /* rename fence precedes op19, which needs the committed generation */
    }
#endif
#if SAFEUPLOAD_STAGING_PROTOTYPE
    /* Never seal or publish an allocation whose CREATE did not attach its
     * returned file object. The owner's next CREATE drives exact attachment
     * replay on the attach worker; this maintenance worker cannot invent a
     * caller/file object. Exact terminal tuples use the service cleanup queue. */
    if (Stream->AttachCompletionPending || Stream->AttachCompletionFence || Stream->AttachRetirePending) {
        /* Keep the drain's held diagnostic. SERVICE does not arm the retry
         * timer; only a live owner CREATE can replay this attachment. */
        Stream->Wait = STAGE_WAIT_SERVICE;
        return;
    }
#endif
    Stream->Wait = STAGE_WAIT_NONE;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (Stream->AttachAcknowledged && !Stream->AnyHandleCleanupObserved) return;
    if (Stream->HandleReceiptPending || Stream->HandleReceiptInFlight ||
        (Stream->AnyHandleCleanupObserved && !Stream->HandleReceiptAcknowledged)) {
        Stream->Wait = Stream->HandleReceiptWait == STAGE_WAIT_SERVICE ? STAGE_WAIT_SERVICE : STAGE_WAIT_EXCHANGE;
        return;
    }
    if (Stream->AllocationReceiptPending) {
        /* Kind-5 is never authority to resolve a possibly permitted op15. */
        if (Stream->AttachCompletionMayExist || Stream->AttachCompletionKnown) {
            Stream->Wait = STAGE_WAIT_SERVICE;
            return;
        }
        if (Stream->AllocationRecoveryPending || Stream->AllocationRecoveryInFlight) {
            Stream->Wait = Stream->AllocationRecoveryWait == STAGE_WAIT_SERVICE ? STAGE_WAIT_SERVICE : STAGE_WAIT_EXCHANGE;
            return;
        }
        /* A kind-5 receipt may be issued only after the failed synthetic
         * CREATE has unwound its exact FILE_OBJECT/share/cache binding and
         * the native backing handle is closed. This prevents the service
         * delete worker from racing rollback or treating an open stage as
         * confirmed absent. */
        StageAcquire(&Stream->Resource);
        if (InterlockedCompareExchange(&Stream->FileObjects, 0, 0) == 0 &&
            Stream->ShareAccess.OpenCount == 0 && Stream->Sections.SharedCacheMap == NULL &&
            Stream->Sections.DataSectionObject == NULL && Stream->Sections.ImageSectionObject == NULL) {
            StageCloseBacking(Stream);
        }
        if (InterlockedCompareExchange(&Stream->FileObjects, 0, 0) != 0 ||
            Stream->ShareAccess.OpenCount != 0 || Stream->Sections.SharedCacheMap != NULL ||
            Stream->Sections.DataSectionObject != NULL || Stream->Sections.ImageSectionObject != NULL ||
            Stream->BackingObject != NULL) {
            StageRelease(&Stream->Resource);
            Stream->Wait = STAGE_WAIT_DRAIN;
            return;
        }
        StageRelease(&Stream->Resource);
        if (Stream->AllocationTupleKnown && !Stream->DiscardRpcInFlight) {
            Stream->DiscardRpcKind = SAFEUPLOAD_STAGE_DISCARD_KIND_UNATTACHED_ALLOCATION;
            Stream->DiscardRpcPending = TRUE;
        }
        Stream->Wait = STAGE_WAIT_EXCHANGE;
        return;
    }
    /* A private deletion keeps the name pending only while its last
     * cleanup has not detached it. Exact retirement remains independent of
     * any later ordinary name allocation. */
    if (Stream->PrivateDeleteReserved && Stream->View != NULL &&
        Stream->View->Current == Stream && !Stream->OwnerExited && !StageUnloadPrepareWork) {
        Stream->Wait = STAGE_WAIT_NONE;
        return;
    }
#endif
    if (Stream->RenameExchange != NULL) {
        StageFinishRename(Stream);
#if SAFEUPLOAD_STAGING_PROTOTYPE
        return; /* the namespace stays frozen until the unlocked service reply is applied */
#else
        if (Stream->RenameExchange != NULL) return;
#endif
    }
    if (!Stream->Sealed) {
        StageDrainAndSeal(Stream);
        if (!Stream->Sealed) return;
    } else if (!Stream->Retired) {
        (VOID)StageRetireDeletedStream(Stream);
    }
    (VOID)StageApplyDisposal(Stream);
    (VOID)StageTryRelease(Stream, Released);
}

#if SAFEUPLOAD_STAGING_PROTOTYPE
/* Caller owns NamespaceResource. A rename exchange remains attached to its
 * stream, but only the worker may collect and send it after dropping the
 * namespace lock. The exchange itself and stream are pinned by RpcReferences. */
static VOID StageCollectRenameRpcs(PLIST_ENTRY Rpcs)
{
    PLIST_ENTRY link;
    for (link = StageStreams.Flink; link != &StageStreams; link = link->Flink) {
        PSTAGE_STREAM stream = CONTAINING_RECORD(link, STAGE_STREAM, Link);
        if (!stream->RenameRpcPending || stream->RenameRpcInFlight ||
            stream->RenameExchange == NULL || stream->View == NULL || stream->RenameWait == STAGE_WAIT_SERVICE ||
            (stream->RenameRetryAfter != 0 && KeQueryInterruptTime() < stream->RenameRetryAfter)) continue;
        stream->RenameRpcPending = FALSE;
        stream->RenameRpcInFlight = TRUE;
        stream->RenameWait = STAGE_WAIT_EXCHANGE;
        stream->Wait = STAGE_WAIT_EXCHANGE;
        stream->RpcRenameExchangeSnapshot = stream->RenameExchange;
        stream->RpcProcessIdSnapshot = stream->View->OwnerProcessId;
        stream->RpcViewGenerationSnapshot = stream->View->Generation;
        stream->RpcTransferIdSnapshot = stream->TransferId;
        stream->RpcGenerationSnapshot = stream->DestinationGeneration;
        stream->RpcIdentitySnapshot = stream->StageIdentity;
        InterlockedIncrement(&stream->RpcReferences);
        InsertTailList(Rpcs, &stream->RpcLink);
    }
}

/* Caller owns NamespaceResource. */
static VOID StageCollectSealRpcs(PLIST_ENTRY Rpcs)
{
    PLIST_ENTRY link;
    for (link = StageStreams.Flink; link != &StageStreams; link = link->Flink) {
        PSTAGE_STREAM stream = CONTAINING_RECORD(link, STAGE_STREAM, Link);
        if (!StageBoundSeedReady(stream) || !stream->SealRpcPending || stream->SealRpcInFlight || stream->View == NULL ||
            stream->RenameExchange != NULL || stream->DiscardRpcInFlight ||
            stream->PrivateDeleteReserved ||
            !stream->StageIdentityValid || !stream->HasTransferId ||
            stream->DestinationGeneration == 0) continue;
        stream->SealRpcPending = FALSE;
        stream->SealRpcInFlight = TRUE;
        stream->RpcProcessIdSnapshot = stream->View->OwnerProcessId;
        stream->RpcViewGenerationSnapshot = stream->View->Generation;
        stream->RpcTransferIdSnapshot = stream->TransferId;
        stream->RpcGenerationSnapshot = stream->DestinationGeneration;
        stream->RpcIdentitySnapshot = stream->StageIdentity;
        InterlockedIncrement(&stream->RpcReferences);
        InsertTailList(Rpcs, &stream->RpcLink);
    }
}

/* Caller owns NamespaceResource. Snapshots bind the out-of-lock RPC to the
 * exact stream generation even if a successor becomes current meanwhile. */
static VOID StageCollectDiscardRpcs(PLIST_ENTRY Rpcs)
{
    PLIST_ENTRY link;
    for (link = StageStreams.Flink; link != &StageStreams; link = link->Flink) {
        PSTAGE_STREAM stream = CONTAINING_RECORD(link, STAGE_STREAM, Link);
        BOOLEAN unattachedReady = TRUE;
        if (stream->DiscardRpcKind == SAFEUPLOAD_STAGE_DISCARD_KIND_UNATTACHED_ALLOCATION) {
            /* Also gate collection: a retained pending cleanup flag cannot
             * turn ambiguous attachment permission into a kind-5 send. */
            if (stream->AttachCompletionPending || stream->AttachCompletionMayExist ||
                stream->AttachCompletionKnown || stream->AttachCompletionFence ||
                stream->AttachRetirePending || stream->AttachLifecycleInFlight) continue;
            StageAcquire(&stream->Resource);
            unattachedReady = InterlockedCompareExchange(&stream->FileObjects, 0, 0) == 0 &&
                stream->ShareAccess.OpenCount == 0 && stream->Sections.SharedCacheMap == NULL &&
                stream->Sections.DataSectionObject == NULL && stream->Sections.ImageSectionObject == NULL &&
                stream->BackingObject == NULL;
            StageRelease(&stream->Resource);
        }
        if (!stream->DiscardRpcPending || stream->DiscardRpcInFlight ||
            (stream->DiscardRpcKind != SAFEUPLOAD_STAGE_DISCARD_KIND_PRIVATE_VERSION &&
                stream->DiscardRpcKind != SAFEUPLOAD_STAGE_DISCARD_KIND_UNATTACHED_ALLOCATION) ||
            stream->SealRpcInFlight || stream->RenameRpcInFlight ||
            stream->RenameExchange != NULL ||
            !unattachedReady ||
            (stream->AnyHandleCleanupObserved && !stream->HandleReceiptAcknowledged) ||
            !stream->StageIdentityValid || !stream->HasTransferId || stream->View == NULL ||
            stream->DestinationGeneration == 0) continue;
        stream->DiscardRpcPending = FALSE;
        stream->DiscardRpcInFlight = TRUE;
        stream->RpcKindSnapshot = stream->DiscardRpcKind;
        stream->RpcProcessIdSnapshot = stream->View->OwnerProcessId;
        stream->RpcGenerationSnapshot = stream->DestinationGeneration;
        stream->RpcIdentitySnapshot = stream->StageIdentity;
        stream->RpcTransferIdSnapshot = stream->TransferId;
        if (stream->RpcKindSnapshot == SAFEUPLOAD_STAGE_DISCARD_KIND_PRIVATE_VERSION) {
            stream->RpcReservationSnapshot = stream->PrivateDeleteReserved ?
                stream->DeleteReservationId : stream->TransferId;
        } else {
            stream->RpcReservationSnapshot = stream->TransferId;
        }
        InterlockedIncrement(&stream->RpcReferences);
        InsertTailList(Rpcs, &stream->RpcLink);
    }
}

/* Caller owns NamespaceResource. The exact original request is retained in
 * the receipt so a lost ALLOCATE reply can resolve the same
 * manifest after service reconnect or owner exit. */
static VOID StageCollectAllocationRecoveryRpcs(PLIST_ENTRY Rpcs)
{
    PLIST_ENTRY link;
    for (link = StageStreams.Flink; link != &StageStreams; link = link->Flink) {
        PSTAGE_STREAM stream = CONTAINING_RECORD(link, STAGE_STREAM, Link);
        if (!stream->AllocationReceiptPending || !stream->AllocationRecoveryPending ||
            stream->AllocationRecoveryInFlight || stream->View == NULL ||
            stream->AllocationRecoveryWait == STAGE_WAIT_SERVICE ||
            (stream->AllocationRecoveryRetryAfter != 0 && KeQueryInterruptTime() < stream->AllocationRecoveryRetryAfter) ||
            stream->AllocationRequest.RequestId == 0 || !stream->HasTransferId) continue;
        stream->AllocationRecoveryPending = FALSE;
        stream->AllocationRecoveryInFlight = TRUE;
        stream->AllocationRecoveryWait = STAGE_WAIT_EXCHANGE;
        stream->Wait = STAGE_WAIT_EXCHANGE;
        InterlockedIncrement(&stream->RpcReferences);
        InsertTailList(Rpcs, &stream->RecoveryLink);
    }
}

/* NamespaceResource held; invoked only for the validated byte-exact terminal
 * receipt and its still-current shell. No generic refusal can enter here. */
static VOID StageResolveUncommittedAllocation(PSTAGE_STREAM Stream)
{
    PSTAGE_STREAM parent = Stream->AllocationReceiptParent;
    Stream->AllocationReceiptPending = FALSE;
    Stream->AllocationRecoveryPending = FALSE;
    Stream->AllocationRecoveryInFlight = FALSE;
    Stream->AllocationRecoveryWait = STAGE_WAIT_NONE;
    Stream->AllocationRecoveryRetryAfter = 0;
    Stream->DiscardRpcPending = FALSE;
    Stream->AllocationTupleKnown = FALSE;
    Stream->Discarded = TRUE;
    Stream->Sealed = TRUE;
    Stream->Retired = TRUE; /* receipt shell; no committed stage object exists */
    Stream->Wait = STAGE_WAIT_NONE;
    if (Stream->ReservationLinked) StageRemoveAllocationNameReservation(Stream);
    StageClearPrivateDelete(Stream);
    RtlZeroMemory(&Stream->AllocationIntent, sizeof(Stream->AllocationIntent));
    RtlZeroMemory(&Stream->AllocationRequest, sizeof(Stream->AllocationRequest));
    if (parent != NULL) {
        NT_ASSERT(parent->AllocationReceiptReferences > 0);
        --parent->AllocationReceiptReferences;
        Stream->AllocationReceiptParent = NULL;
        StageQueueStream(parent, &StageCounters.WakeInline);
    }
    if (Stream->View != NULL && Stream->View->Current == Stream) Stream->View->Detached = TRUE;
    StageQueueStream(Stream, &StageCounters.WakeInline);
}

static VOID StagePerformAllocationRecoveryRpcs(PLIST_ENTRY Rpcs)
{
    while (!IsListEmpty(Rpcs)) {
        PSTAGE_STREAM stream = CONTAINING_RECORD(RemoveHeadList(Rpcs), STAGE_STREAM, RecoveryLink);
        WCHAR basename[SAFEUPLOAD_MAX_STAGE_NAME_CHARS];
        USHORT basenameLength = 0;
        UINT64 generation = 0;
        SAFEUPLOAD_STAGE_IDENTITY_V19 identity;
        GUID expectedId = stream->TransferId;
        UINT64 requestId = stream->AllocationRequest.RequestId;
        LONG serviceGeneration = InterlockedCompareExchange(&StageServiceGeneration, 0, 0);
        BOOLEAN noAllocationCommitted = FALSE;
        PSAFEUPLOAD_STAGE_WRITER_LEASE releaseLease = NULL;
        NTSTATUS status;
        InitializeListHead(&stream->RecoveryLink);
        RtlZeroMemory(&identity, sizeof(identity));
        if (SafeUploadStageMandatoryTeardownActive()) status = STATUS_PORT_DISCONNECTED;
        else if (stream->BoundAllocation && stream->AllocationWriterLease == NULL)
            status = STATUS_INVALID_DEVICE_STATE; /* retained lease required; park this exact receipt */
        else if (stream->BoundAllocation)
            status = SafeUploadStageReplayAllocationBoundV23(stream->AllocationWriterLease, &stream->AllocationRequest,
                basename, &basenameLength, &generation, &identity);
        else status = SafeUploadStageReplayAllocationV19(&stream->AllocationRequest,
                basename, &basenameLength, &generation, &identity, &noAllocationCommitted);

        StageAcquire(&StageNamespaceResource);
        if (stream->Listed && stream->AllocationReceiptPending && stream->AllocationRecoveryInFlight &&
            StageServiceAvailable && serviceGeneration == InterlockedCompareExchange(&StageServiceGeneration, 0, 0) &&
            !InterlockedCompareExchange(&StageReconcileNeeded, 0, 0) && SafeUploadStageProtocolIsReady() &&
            stream->AllocationRequest.RequestId == requestId &&
            RtlEqualMemory(&stream->TransferId, &expectedId, sizeof(GUID)) &&
            RtlEqualMemory(&stream->AllocationIntent.AllocationReservationId, &expectedId, sizeof(GUID))) {
            stream->AllocationRecoveryInFlight = FALSE;
            if (NT_SUCCESS(status) && noAllocationCommitted && !stream->BoundAllocation &&
                !stream->AllocationTupleKnown && !stream->AttachCompletionMayExist && !stream->AttachCompletionKnown &&
                !stream->AttachLifecycleInFlight && !stream->DiscardRpcInFlight && stream->BackingObject == NULL &&
                InterlockedCompareExchange(&stream->FileObjects, 0, 0) == 0 && stream->ShareAccess.OpenCount == 0 &&
                stream->Sections.SharedCacheMap == NULL && stream->Sections.DataSectionObject == NULL &&
                stream->Sections.ImageSectionObject == NULL) {
                StageResolveUncommittedAllocation(stream);
            } else if (noAllocationCommitted) {
                stream->AllocationRecoveryPending = TRUE;
                stream->AllocationRecoveryWait = STAGE_WAIT_SERVICE;
                stream->Wait = STAGE_WAIT_SERVICE;
            } else {
                if (NT_SUCCESS(status)) status = StageSetStreamStageName(stream, basename, basenameLength);
                if (NT_SUCCESS(status) && generation != 0 &&
                    RtlEqualMemory(&stream->TransferId, &expectedId, sizeof(GUID))) {
                    stream->DestinationGeneration = generation;
                    stream->StageIdentity = identity;
                    stream->StageIdentityValid = TRUE;
                    stream->ExpectedStageIdentity = identity;
                    stream->ExpectedStageIdentityValid = TRUE;
                    stream->AllocationTupleKnown = TRUE;
                    stream->AllocationRecoveryPending = FALSE;
                    stream->AllocationRecoveryWait = STAGE_WAIT_NONE;
                    stream->AllocationRecoveryRetryAfter = 0;
                    releaseLease = stream->AllocationWriterLease;
                    stream->AllocationWriterLease = NULL;
                    stream->DiscardRpcKind = SAFEUPLOAD_STAGE_DISCARD_KIND_UNATTACHED_ALLOCATION;
                    stream->DiscardRpcPending = TRUE;
                    stream->Wait = STAGE_WAIT_EXCHANGE;
                    StageQueueStream(stream, &StageCounters.WakeInline); /* resolved tuple enables exact cleanup */
                } else {
                    stream->AllocationRecoveryPending = TRUE;
                    stream->AllocationRecoveryWait = status == STATUS_INVALID_DEVICE_STATE ?
                        STAGE_WAIT_SERVICE : StageWaitFor(status);
                    stream->Wait = stream->AllocationRecoveryWait;
                }
            }
        } else {
            stream->AllocationRecoveryInFlight = FALSE;
            stream->AllocationRecoveryPending = TRUE;
            stream->AllocationRecoveryWait = STAGE_WAIT_SERVICE;
            stream->Wait = STAGE_WAIT_SERVICE;
        }
        InterlockedDecrement(&stream->RpcReferences);
        StageUpdateRetryTimer();
        if (stream->AllocationRecoveryPending && stream->AllocationRecoveryWait == STAGE_WAIT_EXCHANGE)
            stream->AllocationRecoveryRetryAfter = StageAllocationRetryDeadline();
        StageRelease(&StageNamespaceResource);
        SafeUploadStagePublicReleaseWriter(releaseLease);
    }
}

/* Caller owns NamespaceResource. CLEANUP is a sticky per-version fact, but
 * the service receipt is sent only after the first attachment transaction
 * is complete and no path/identity-changing exchange is in flight. */
static VOID StageCollectHandleReceiptRpcs(PLIST_ENTRY Rpcs)
{
    PLIST_ENTRY link;
    for (link = StageStreams.Flink; link != &StageStreams; link = link->Flink) {
        PSTAGE_STREAM stream = CONTAINING_RECORD(link, STAGE_STREAM, Link);
        if (stream->HandleReceiptWait == STAGE_WAIT_SERVICE ||
            (stream->HandleReceiptRetryAfter != 0 && KeQueryInterruptTime() < stream->HandleReceiptRetryAfter) ||
            !stream->HandleReceiptPending || stream->HandleReceiptInFlight ||
            stream->HandleReceiptAcknowledged || !stream->AnyHandleCleanupObserved ||
            !stream->AttachAcknowledged || stream->AttachCompletionPending ||
            stream->AttachCompletionFence || stream->AttachTerminalPending ||
            stream->AttachRetirePending || stream->RenameExchange != NULL ||
            stream->RenameRpcPending || stream->RenameRpcInFlight ||
            stream->SealRpcPending || stream->SealRpcInFlight ||
            stream->DiscardRpcPending || stream->DiscardRpcInFlight ||
            !stream->StageIdentityValid || !stream->HasTransferId ||
            stream->DestinationGeneration == 0 || stream->View == NULL) continue;
        stream->HandleReceiptPending = FALSE;
        stream->HandleReceiptInFlight = TRUE;
        stream->HandleReceiptWait = STAGE_WAIT_EXCHANGE;
        stream->Wait = STAGE_WAIT_EXCHANGE;
        stream->RpcProcessIdSnapshot = stream->View->OwnerProcessId;
        stream->RpcVolumeKindSnapshot = StageVolumeKind(stream->OriginalInstance);
        stream->RpcViewGenerationSnapshot = stream->View->Generation;
        stream->RpcTransferIdSnapshot = stream->TransferId;
        stream->RpcGenerationSnapshot = stream->DestinationGeneration;
        stream->RpcIdentitySnapshot = stream->StageIdentity;
        InterlockedIncrement(&stream->RpcReferences);
        InsertTailList(Rpcs, &stream->RpcLink);
    }
}

static VOID StagePerformHandleReceiptRpcs(PLIST_ENTRY Rpcs)
{
    while (!IsListEmpty(Rpcs)) {
        PSTAGE_STREAM stream = CONTAINING_RECORD(RemoveHeadList(Rpcs), STAGE_STREAM, RpcLink);
        UINT32 result = 0;
        BOOLEAN requestMayExist = FALSE;
        NTSTATUS status;
        InitializeListHead(&stream->RpcLink);
        status = SafeUploadStageMandatoryTeardownActive() ? STATUS_PORT_DISCONNECTED :
            SafeUploadStageAttachmentExchangeV20(stream->RpcProcessIdSnapshot,
            &stream->Name, stream->RpcVolumeKindSnapshot,
            SAFEUPLOAD_OPERATION_STAGE_ATTACH_HANDLE_OBSERVED, &stream->RpcTransferIdSnapshot,
            stream->RpcGenerationSnapshot, &stream->RpcIdentitySnapshot,
            &stream->DriverInstanceId, &stream->AllocationParentDirectoryIdentity,
            &stream->HandleReceiptRequest, &result, &requestMayExist);

        StageAcquire(&StageNamespaceResource);
        if (stream->Listed && stream->HandleReceiptInFlight &&
            stream->View != NULL &&
            stream->View->Generation == stream->RpcViewGenerationSnapshot &&
            stream->View->OwnerProcessId == stream->RpcProcessIdSnapshot &&
            RtlEqualMemory(&stream->TransferId, &stream->RpcTransferIdSnapshot, sizeof(GUID)) &&
            stream->DestinationGeneration == stream->RpcGenerationSnapshot &&
            StageV19IdentityEqual(&stream->StageIdentity, &stream->RpcIdentitySnapshot) &&
            RtlEqualMemory(&stream->DriverInstanceId, &StageDriverInstanceId, sizeof(GUID))) {
            stream->HandleReceiptInFlight = FALSE;
            if (NT_SUCCESS(status) && result == SAFEUPLOAD_STAGE_RESULT_HANDLE_OBSERVED) {
                stream->HandleReceiptAcknowledged = TRUE;
                stream->HandleReceiptPending = FALSE;
                stream->HandleReceiptRequestValid = stream->HandleReceiptRequest.RequestId != 0;
                stream->HandleReceiptWait = STAGE_WAIT_NONE;
                stream->HandleReceiptRetryAfter = 0;
                stream->Wait = STAGE_WAIT_NONE;

                StageQueueStream(stream, &StageCounters.WakeInline);
            } else {
                stream->HandleReceiptPending = TRUE;
                stream->HandleReceiptWait = StageWaitFor(status);
                stream->Wait = stream->HandleReceiptWait;
                if (requestMayExist) stream->HandleReceiptRequestValid = TRUE;
            }
        } else {
            stream->HandleReceiptInFlight = FALSE;
            stream->HandleReceiptPending = TRUE;
            stream->HandleReceiptWait = STAGE_WAIT_SERVICE;
            stream->Wait = STAGE_WAIT_SERVICE;
        }
        InterlockedDecrement(&stream->RpcReferences);
        StageUpdateRetryTimer();
        if (stream->HandleReceiptPending && stream->HandleReceiptWait == STAGE_WAIT_EXCHANGE)
            stream->HandleReceiptRetryAfter = StageRetryDueTime;
        StageRelease(&StageNamespaceResource);
    }
}

/* The worker performs these calls only after releasing NamespaceResource.
 * RpcReferences pins the stream through the reply and exact-generation
 * revalidation; a stale V2 ACK cannot detach a newly attached V3. */
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageAbortUnattachedAllocation(_Inout_ PSTAGE_STREAM Stream);
#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, StageAbortUnattachedAllocation)
#endif

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageAbortUnattachedAllocation(_Inout_ PSTAGE_STREAM Stream)
{
    UINT32 result = 0;
    BOOLEAN requestMayExist = FALSE;
    NTSTATUS status;
    PAGED_CODE();
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (!Stream->AttachPrepareMayExist || Stream->AttachPrepareKnown) return STATUS_SUCCESS;
    /* This worker can cancel only pre-Commit uncertainty. Neither a generic
     * denial nor AlreadyCommitted is authority to delete a possibly exposed
     * version. Collection pins the exact tuple and excludes live attachment. */
    if (Stream->AttachCommitMayExist || Stream->AttachCommitKnown ||
        Stream->AttachCompletionMayExist || Stream->AttachCompletionKnown)
        return STATUS_INVALID_DEVICE_STATE;
    status = SafeUploadStageAttachmentExchangeV20(Stream->RpcProcessIdSnapshot,
        &Stream->Name, StageVolumeKind(Stream->OriginalInstance),
        SAFEUPLOAD_OPERATION_STAGE_ATTACH_ABORT, &Stream->RpcTransferIdSnapshot,
        Stream->RpcGenerationSnapshot, &Stream->RpcIdentitySnapshot,
        &Stream->DriverInstanceId, &Stream->AllocationParentDirectoryIdentity,
        &Stream->AttachAbortRequest, &result, &requestMayExist);
    if (!NT_SUCCESS(status)) return status;
    return result == SAFEUPLOAD_STAGE_RESULT_ATTACH_ABORTED ? STATUS_SUCCESS : STATUS_INVALID_DEVICE_STATE;
}

static VOID StagePerformDiscardRpcs(PLIST_ENTRY Rpcs)
{
    while (!IsListEmpty(Rpcs)) {
        PSTAGE_STREAM stream = CONTAINING_RECORD(RemoveHeadList(Rpcs), STAGE_STREAM, RpcLink);
        UINT32 result = 0;
        UINT32 kind = stream->RpcKindSnapshot;
        const GUID *currentReservation;
        BOOLEAN requestCurrent;
        LONG serviceGeneration = InterlockedCompareExchange(&StageServiceGeneration, 0, 0);
        NTSTATUS status;
        InitializeListHead(&stream->RpcLink);
        status = SafeUploadStageMandatoryTeardownActive() ? STATUS_PORT_DISCONNECTED :
            (kind == SAFEUPLOAD_STAGE_DISCARD_KIND_UNATTACHED_ALLOCATION ?
                StageAbortUnattachedAllocation(stream) : STATUS_SUCCESS);
        if (NT_SUCCESS(status))
            status = SafeUploadStageMandatoryTeardownActive() ? STATUS_PORT_DISCONNECTED :
                SafeUploadStageDiscardVersionV19(stream->RpcProcessIdSnapshot,
                &stream->StageName, &stream->RpcReservationSnapshot,
                &stream->RpcIdentitySnapshot, stream->RpcGenerationSnapshot, kind, &result);

        StageAcquire(&StageNamespaceResource);
        currentReservation = kind == SAFEUPLOAD_STAGE_DISCARD_KIND_PRIVATE_VERSION && stream->PrivateDeleteReserved ?
            &stream->DeleteReservationId : &stream->TransferId;
        requestCurrent = (kind == SAFEUPLOAD_STAGE_DISCARD_KIND_PRIVATE_VERSION ||
            kind == SAFEUPLOAD_STAGE_DISCARD_KIND_UNATTACHED_ALLOCATION) &&
            stream->DiscardRpcInFlight && stream->RpcKindSnapshot == kind && stream->DiscardRpcKind == kind &&
            RtlEqualMemory(currentReservation, &stream->RpcReservationSnapshot, sizeof(GUID));
        if (requestCurrent &&
            StageServiceAvailable && serviceGeneration == InterlockedCompareExchange(&StageServiceGeneration, 0, 0) &&
            !InterlockedCompareExchange(&StageReconcileNeeded, 0, 0) && SafeUploadStageProtocolIsReady() &&
            RtlEqualMemory(&stream->TransferId, &stream->RpcTransferIdSnapshot, sizeof(GUID)) &&
            stream->DestinationGeneration == stream->RpcGenerationSnapshot &&
            StageV19IdentityEqual(&stream->StageIdentity, &stream->RpcIdentitySnapshot)) {
            stream->DiscardRpcInFlight = FALSE;
            if (NT_SUCCESS(status) && result == SAFEUPLOAD_STAGE_REPLY_DISCARD_ACKNOWLEDGED) {
                stream->DiscardRpcPending = FALSE;
                stream->Wait = STAGE_WAIT_NONE;
                stream->Discarded = TRUE;
                stream->Sealed = TRUE;
                stream->Retired = TRUE; /* exact service ACK includes removal of this identity */
                if (kind == SAFEUPLOAD_STAGE_DISCARD_KIND_UNATTACHED_ALLOCATION) {
                    PSTAGE_STREAM parent = stream->AllocationReceiptParent;
                    stream->AttachTerminalPending = FALSE;
                    stream->AllocationReceiptPending = FALSE;
                    stream->AllocationRecoveryPending = FALSE;
                    stream->AllocationRecoveryInFlight = FALSE;
                    stream->AllocationTupleKnown = FALSE;
                    if (stream->ReservationLinked) StageRemoveAllocationNameReservation(stream);
                    RtlZeroMemory(&stream->AllocationIntent, sizeof(stream->AllocationIntent));
                    RtlZeroMemory(&stream->AllocationRequest, sizeof(stream->AllocationRequest));
                    if (parent != NULL) {
                        NT_ASSERT(parent->AllocationReceiptReferences > 0);
                        --parent->AllocationReceiptReferences;
                        stream->AllocationReceiptParent = NULL;
                        StageQueueStream(parent, &StageCounters.WakeInline);
                    }
                }
                StageClearPrivateDelete(stream);
                if (stream->View != NULL && stream->View->Current == stream) stream->View->Detached = TRUE;
                StageQueueStream(stream, &StageCounters.WakeInline);
            } else {
                stream->DiscardRpcPending = TRUE;
                stream->Wait = status == STATUS_PORT_DISCONNECTED ? STAGE_WAIT_SERVICE : STAGE_WAIT_EXCHANGE;
            }
        } else {
            /* An old exact ACK cannot detach or retire a later generation. */
            stream->DiscardRpcInFlight = FALSE;
            stream->DiscardRpcPending = TRUE;
            stream->Wait = STAGE_WAIT_SERVICE;
        }
        InterlockedDecrement(&stream->RpcReferences);
        StageUpdateRetryTimer();
        StageRelease(&StageNamespaceResource);
    }
}


/* These port calls run without NamespaceResource or the stream resource. Each
 * captured exact tuple is checked again before its result changes the view. */
static VOID StagePerformSealRpcs(PLIST_ENTRY Rpcs)
{
    while (!IsListEmpty(Rpcs)) {
        PSTAGE_STREAM stream = CONTAINING_RECORD(RemoveHeadList(Rpcs), STAGE_STREAM, RpcLink);
        NTSTATUS status;
        InitializeListHead(&stream->RpcLink);
        status = SafeUploadStageMandatoryTeardownActive() ? STATUS_PORT_DISCONNECTED : StageCaptureSealBasic(stream);
        if (status == STATUS_SUCCESS) status = SafeUploadStageSealVersionV19(stream->RpcProcessIdSnapshot,
            &stream->StageName, &stream->RpcIdentitySnapshot,
            stream->RpcGenerationSnapshot, &stream->SealBasic);

        StageAcquire(&StageNamespaceResource);
        if (stream->View != NULL && stream->View->OwnerProcessId == stream->RpcProcessIdSnapshot &&
            stream->View->Generation == stream->RpcViewGenerationSnapshot &&
            RtlEqualMemory(&stream->TransferId, &stream->RpcTransferIdSnapshot, sizeof(GUID)) &&
            stream->DestinationGeneration == stream->RpcGenerationSnapshot &&
            StageV19IdentityEqual(&stream->StageIdentity, &stream->RpcIdentitySnapshot)) {
            stream->SealRpcInFlight = FALSE;
            if (NT_SUCCESS(status)) {
                stream->Sealed = TRUE;
                stream->Wait = STAGE_WAIT_NONE;
                StageQueueStream(stream, &StageCounters.WakeInline);
            } else {
                stream->SealRpcPending = TRUE;
                stream->Wait = StageWaitFor(status);
            }
        } else {
            /* An ACK for a view that no longer matches is not applied. Keep
             * the exact sealed identity pinned until service reconciliation. */
            stream->SealRpcInFlight = FALSE;
            stream->SealRpcPending = TRUE;
            stream->Wait = STAGE_WAIT_SERVICE;
        }
        InterlockedDecrement(&stream->RpcReferences);
        StageUpdateRetryTimer();
        StageRelease(&StageNamespaceResource);
    }
}

static VOID StagePerformRenameRpcs(PLIST_ENTRY Rpcs)
{
    while (!IsListEmpty(Rpcs)) {
        PSTAGE_STREAM stream = CONTAINING_RECORD(RemoveHeadList(Rpcs), STAGE_STREAM, RpcLink);
        PSAFEUPLOAD_EXCHANGE exchange = stream->RpcRenameExchangeSnapshot;
        NTSTATUS status;
        InitializeListHead(&stream->RpcLink);
        status = SafeUploadStageMandatoryTeardownActive() ? STATUS_PORT_DISCONNECTED :
            StageExchangeStatus(exchange);

        StageAcquire(&StageNamespaceResource);
        if (stream->View != NULL && stream->RenameExchange == exchange &&
            stream->View->OwnerProcessId == stream->RpcProcessIdSnapshot &&
            stream->View->Generation == stream->RpcViewGenerationSnapshot &&
            RtlEqualMemory(&stream->TransferId, &stream->RpcTransferIdSnapshot, sizeof(GUID)) &&
            stream->DestinationGeneration == stream->RpcGenerationSnapshot &&
            StageV19IdentityEqual(&stream->StageIdentity, &stream->RpcIdentitySnapshot) &&
            RtlEqualMemory(&stream->DriverInstanceId, &StageDriverInstanceId, sizeof(GUID))) {
            stream->RenameRpcInFlight = FALSE;
            stream->RpcRenameExchangeSnapshot = NULL;
            if (SafeUploadStageMandatoryTeardownActive() && !NT_SUCCESS(status))
                stream->RenameRpcPending = TRUE;
            StageApplyRenameReply(stream, exchange, status);
        } else {
            /* Never apply an ACK to a new view/transfer. The retained request
             * ID is replayed until its journal side can be reconciled. */
            stream->RenameRpcInFlight = FALSE;
            stream->RpcRenameExchangeSnapshot = NULL;
            stream->RenameRpcPending = TRUE;
            stream->RenameWait = STAGE_WAIT_SERVICE;
            stream->Wait = STAGE_WAIT_SERVICE;
        }
        InterlockedDecrement(&stream->RpcReferences);
        StageUpdateRetryTimer();
        if (stream->RenameExchange != NULL && stream->RenameWait == STAGE_WAIT_EXCHANGE)
            stream->RenameRetryAfter = StageRetryDueTime;
        StageRelease(&StageNamespaceResource);
    }
}
#endif

static BOOLEAN StageOwnerExited(PEPROCESS Owner, PEPROCESS const *Exited, ULONG Count, BOOLEAN Overflow)
{
    ULONG index;
    LARGE_INTEGER zero;
    for (index = 0; index < Count; ++index) if (Exited[index] == Owner) return TRUE;
    if (!Overflow) return FALSE;
    /* The ring overflowed: ask the process object itself. A process not signalled yet is caught by a later exit. */
    zero.QuadPart = 0;
    return KeWaitForSingleObject(Owner, Executive, KernelMode, FALSE, &zero) == STATUS_SUCCESS;
}

/* Caller owns NamespaceResource. Views and tombstones are matched by their referenced EPROCESS, never by PID. */
static VOID StageOwnersExited(PEPROCESS const *Exited, ULONG Count, BOOLEAN Overflow)
{
    PLIST_ENTRY link, next;
    for (link = StageViews.Flink; link != &StageViews; link = link->Flink) {
        PSTAGE_VIEW view = CONTAINING_RECORD(link, STAGE_VIEW, Link);
        PLIST_ENTRY streamLink;
        if (!StageOwnerExited(view->Owner, Exited, Count, Overflow)) continue;
        view->Detached = TRUE;
        for (streamLink = StageStreams.Flink; streamLink != &StageStreams; streamLink = streamLink->Flink) {
            PSTAGE_STREAM stream = CONTAINING_RECORD(streamLink, STAGE_STREAM, Link);
            if (stream->View != view) continue;
#if SAFEUPLOAD_STAGING_PROTOTYPE
            stream->OwnerExited = TRUE;
            if (stream->PrivateDeleteReserved) StageClearPrivateDelete(stream);
#endif
            StageQueueStream(stream, NULL);
        }
    }
    for (link = StageTombstones.Flink; link != &StageTombstones; link = next) {
        PSTAGE_TOMBSTONE tombstone = CONTAINING_RECORD(link, STAGE_TOMBSTONE, Link);
        next = link->Flink;
        if (StageOwnerExited(tombstone->Owner, Exited, Count, Overflow)) StageFreeTombstone(tombstone);
    }
}

/* Caller owns NamespaceResource. The timer is armed only while some version waits on something Windows does not signal (owner
 * decision 2026-10-10): a drain or backing reopen that could not finish (a user-mapped view or a section after the last handle)
 * or a request the service did not answer; and while a process-exit overflow sweep is still owed (at most 1 s apart, until a sweep
 * runs 1 s after the last overflow). It backs off from 250 ms to 1 s (drain) or 8 s (exchange only), and is cancelled when
 * nothing waits, so it never fires on an idle system. */
static VOID StageUpdateRetryTimer(VOID)
{
    PLIST_ENTRY link;
    ULONG waiting = 0, cap;
    BOOLEAN drain = FALSE;
    KIRQL irql;
    LARGE_INTEGER due;
    if (SafeUploadStageMandatoryTeardownActive()) return;
    StageStreamAcquireSpinLock(&StageListLock, &irql);
    for (link = StageStreams.Flink; link != &StageStreams; link = link->Flink) {
        PSTAGE_STREAM stream = CONTAINING_RECORD(link, STAGE_STREAM, Link);
        if (stream->Wait == STAGE_WAIT_DRAIN) { drain = TRUE; ++waiting; }
        else if (
#if SAFEUPLOAD_STAGING_PROTOTYPE
            StageServiceAvailable &&
#endif
            (stream->Wait == STAGE_WAIT_EXCHANGE
#if SAFEUPLOAD_STAGING_PROTOTYPE
            || stream->HandleReceiptInFlight || stream->RenameRpcInFlight || stream->AllocationRecoveryInFlight
#endif
            )) ++waiting;
    }
    StageStreamReleaseSpinLock(&StageListLock, irql);
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (StageServiceAvailable && InterlockedCompareExchange(&StageReconcileNeeded, 0, 0) &&
        StageReconcileWait == STAGE_WAIT_EXCHANGE) ++waiting;
#endif
    StageCounters.WaitingVersions = waiting;
    if (StageExitSweepPending) {
        /* An owed overflow sweep must not wait behind a long exchange backoff: fire within 1 s (re-arming an armed timer
         * only moves its due time; frequent passes sweep on their own). */
        due.QuadPart = -(LONGLONG)STAGE_RETRY_DRAIN_MAX_MS * 10000LL;
        StageRetryArmed = TRUE;
        StageRetryDueTime = KeQueryInterruptTime() + (ULONGLONG)(-due.QuadPart);
        (VOID)KeSetTimer(&StageRetryTimer, due, &StageRetryDpc);
        InterlockedIncrement64((volatile LONG64 *)&StageCounters.TimerArms);
        return;
    }
    if (waiting == 0) {
        if (StageRetryArmed) (VOID)KeCancelTimer(&StageRetryTimer);
        StageRetryArmed = FALSE;
        StageRetryMs = 0;
        StageRetryDueTime = 0;
        return;
    }
    /* StageRetryArmed means set and not cancelled; the kernel says whether that arm has expired (KeSetTimer resets this
     * notification timer to not-signaled). An expiry flag cannot be attributed to an arm: the worker skips its pass while
     * reconciling, and a delayed DPC can follow a later arm, so deriving the armed state from it left the reconcile
     * unretried (m2t5boot11/12) or a later arm unknown and uncancelled. */
    if (StageRetryArmed && !KeReadStateTimer(&StageRetryTimer)) return;
    cap = drain ? STAGE_RETRY_DRAIN_MAX_MS : STAGE_RETRY_EXCHANGE_MAX_MS;
    StageRetryMs = StageRetryMs == 0 ? STAGE_RETRY_FIRST_MS : StageRetryMs * 2;
    if (StageRetryMs > cap) StageRetryMs = cap;
    due.QuadPart = -(LONGLONG)StageRetryMs * 10000LL;
    StageRetryArmed = TRUE;
    StageRetryDueTime = KeQueryInterruptTime() + (ULONGLONG)(-due.QuadPart);
    (VOID)KeSetTimer(&StageRetryTimer, due, &StageRetryDpc);
    InterlockedIncrement64((volatile LONG64 *)&StageCounters.TimerArms);
}

static KDEFERRED_ROUTINE StageRetryDpcRoutine;
static VOID StageRetryDpcRoutine(PKDPC Dpc, PVOID Context, PVOID Argument1, PVOID Argument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Argument1);
    UNREFERENCED_PARAMETER(Argument2);
    InterlockedExchange(&StageRetryFired, 1);
    KeSetEvent(&StageWorkEvent, IO_NO_INCREMENT, FALSE);
}

/* Caller owns NamespaceResource. Released versions are handed back for teardown after the resource is dropped. */
static VOID StageWorkerPass(PLIST_ENTRY Released, PLIST_ENTRY Rpcs,
    PLIST_ENTRY SealRpcs, PLIST_ENTRY RenameRpcs, PLIST_ENTRY RecoveryRpcs,
    PLIST_ENTRY HandleRpcs)
{
    PEPROCESS exited[STAGE_EXIT_RING];
    ULONG exitCount, index;
    BOOLEAN sweep, overflow, fired;
    PLIST_ENTRY link;
    KIRQL irql;
    InterlockedIncrement64((volatile LONG64 *)&StageCounters.WorkerPasses);
    /* The expiry only asks for stream retries; StageUpdateRetryTimer reads the timer's own state for arming. */
    fired = InterlockedExchange(&StageRetryFired, 0) != 0;
    if (fired) InterlockedIncrement64((volatile LONG64 *)&StageCounters.WakeTimer);
    StageStreamAcquireSpinLock(&StageListLock, &irql);
    sweep = StageSweepRequested;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    /* A disconnected pass only drains local work. Keep a queued reconnect
     * sweep until its channel has reconciled; it alone may unpark receipts. */
    if (!StageServiceAvailable || InterlockedCompareExchange(&StageReconcileNeeded, 0, 0)) sweep = FALSE;
#endif
    if (sweep) StageSweepRequested = FALSE;
    overflow = StageExitOverflow;
    StageExitOverflow = FALSE;
    exitCount = StageExitCount;
    StageExitCount = 0;
    RtlCopyMemory(exited, StageExitRing, exitCount * sizeof(PEPROCESS));
    /* A service connect rechecks every version (renames, seals and deletions the service may have answered or done meanwhile);
     * a timer fire rechecks the versions it covers. */
    if (sweep || fired) for (link = StageStreams.Flink; link != &StageStreams; link = link->Flink) {
        PSTAGE_STREAM stream = CONTAINING_RECORD(link, STAGE_STREAM, Link);
#if SAFEUPLOAD_STAGING_PROTOTYPE
        if (sweep) {
            stream->HandleReceiptRetryAfter = 0;
            stream->RenameRetryAfter = 0;
            if (stream->HandleReceiptWait == STAGE_WAIT_SERVICE) stream->HandleReceiptWait = STAGE_WAIT_EXCHANGE;
            if (stream->RenameWait == STAGE_WAIT_SERVICE) stream->RenameWait = STAGE_WAIT_EXCHANGE;
            stream->AllocationRecoveryRetryAfter = 0;
            if (stream->AllocationRecoveryWait == STAGE_WAIT_SERVICE) stream->AllocationRecoveryWait = STAGE_WAIT_EXCHANGE;
        }
#endif
        if (sweep || stream->Wait == STAGE_WAIT_DRAIN || stream->Wait == STAGE_WAIT_EXCHANGE) (VOID)StageQueueLocked(stream);
    }
    StageStreamReleaseSpinLock(&StageListLock, irql);
    /* After an overflow the sweep asks each owner's process object, which an exiting process signals only after its exit
     * notification. The sweep stays owed until one starts at least 1 s after the last overflow, whenever the worker gets to it,
     * so an owner caught in that gap is swept again (Luna T4 re-review P1). */
    {
        ULONGLONG now = KeQueryInterruptTime();
        if (overflow) { StageExitSweepPending = TRUE; StageExitOverflowTime = now; }
        overflow = StageExitSweepPending;
        if (overflow && now - StageExitOverflowTime >= STAGE_EXIT_SETTLE_100NS) StageExitSweepPending = FALSE;
    }
    if (exitCount != 0 || overflow) StageOwnersExited(exited, exitCount, overflow);
    for (index = 0; index < exitCount; ++index) ObDereferenceObject(exited[index]);
    for (;;) {
        PSTAGE_STREAM stream;
        if (SafeUploadStageMandatoryTeardownActive()) break;
        StageStreamAcquireSpinLock(&StageListLock, &irql);
        if (IsListEmpty(&StageWorkQueue)) {
            StageStreamReleaseSpinLock(&StageListLock, irql);
            break;
        }
        stream = CONTAINING_RECORD(RemoveHeadList(&StageWorkQueue), STAGE_STREAM, WorkLink);
        stream->WorkQueued = FALSE;
        StageStreamReleaseSpinLock(&StageListLock, irql);
        StageProcessStream(stream, Released); /* may release the stream */
    }
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (StageServiceAvailable && !InterlockedCompareExchange(&StageReconcileNeeded, 0, 0) &&
        SafeUploadStageProtocolIsReady()) {
        StageCollectHandleReceiptRpcs(HandleRpcs);
        StageCollectRenameRpcs(RenameRpcs);
        StageCollectSealRpcs(SealRpcs);
        StageCollectDiscardRpcs(Rpcs);
        StageCollectAllocationRecoveryRpcs(RecoveryRpcs);
    }
#endif
    StageUpdateRetryTimer();
}

static KSTART_ROUTINE StageWorker;
static VOID StagePublicOpenFlushFacts(VOID)
{
#if SAFEUPLOAD_STAGING_PROTOTYPE
    static UINT64 attemptedRevision, attemptedAuthority;
    static LONG attemptedChannel;
    PSAFEUPLOAD_STAGE_NATIVE_SNAPSHOT rows;
    UINT64 revision = 0, authority = SafeUploadStageProtocolNativeAuthority();
    ULONG offset = 0, count = 0, index;
    BOOLEAN complete = FALSE;
    LONG channel = SafeUploadStageProtocolChannelGeneration();
    NTSTATUS status;
    if (SafeUploadStageMandatoryTeardownActive() ||
        !SafeUploadStageProtocolNativeForwardAllowed(0, authority)) return;
    /* NativeLock readers and confirmations touch these rows: nonpaged. A failed
     * allocation returns before the attempt marker, so the next event retries. */
    rows = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*rows) * SAFEUPLOAD_NATIVE_REPLAY_PAGE_ROWS, STAGE_TAG);
    if (rows == NULL) return;
    do {
        UINT64 current;
        status = SafeUploadStagePublicOpenReadPage(revision, offset, rows, SAFEUPLOAD_NATIVE_REPLAY_PAGE_ROWS,
            &count, &current, &complete);
        if (!NT_SUCCESS(status)) break;
        if (offset == 0) {
            revision = current;
            if (revision == attemptedRevision && authority == attemptedAuthority && channel == attemptedChannel) break;
            attemptedRevision = revision; attemptedAuthority = authority; attemptedChannel = channel;
        }
        for (index = 0; index < count; ++index) {
            SAFEUPLOAD_PUBLIC_RELAY_REPLY reply;
            UINT64 replyAuthority;
            if (SafeUploadStageMandatoryTeardownActive()) goto Exit;
            if (rows[index].PublicOperation.Sequence != 0) {
                if (!FlagOn(rows[index].PublicOperation.Facts, SAFEUPLOAD_PUBLIC_OPERATION_RESULT_KNOWN |
                    SAFEUPLOAD_PUBLIC_OPERATION_NOT_FORWARDED | SAFEUPLOAD_PUBLIC_OPERATION_COVERAGE_LOST)) continue;
                status = SafeUploadStagePublicOpenExchange(&rows[index], revision, SAFEUPLOAD_PUBLIC_DISPOSITION_FACTS,
                    &reply, &replyAuthority);
                if (status == STATUS_SUCCESS && reply.Result == SAFEUPLOAD_PUBLIC_RELAY_RECORDED) {
                    status = SafeUploadStagePublicDispositionConfirm(&rows[index], &reply, replyAuthority);
                    if (NT_SUCCESS(status)) goto Exit;
                }
                continue;
            }
            if (rows[index].PublicOpenConfirmed && !rows[index].PublicCleanupOutstanding && !rows[index].LastHandleCleanedUp &&
                !rows[index].CancelledBeforeHandle && !rows[index].CancelledCloseObserved &&
                !rows[index].CleanupCoverageLost) continue;
            if (!rows[index].CreateOutcomeKnown && !rows[index].CancelledBeforeHandle &&
                !rows[index].CancelledCloseObserved && !rows[index].CleanupCoverageLost) continue;
            status = SafeUploadStagePublicOpenExchange(&rows[index], revision, SAFEUPLOAD_PUBLIC_OPEN_FACTS,
                &reply, &replyAuthority);
            if (status == STATUS_SUCCESS && reply.Result == SAFEUPLOAD_PUBLIC_RELAY_RECORDED) {
                status = SafeUploadStagePublicOpenConfirm(&rows[index].Binding, revision, replyAuthority);
                if (NT_SUCCESS(status)) {
                    UINT64 afterRevision;
                    if (rows[index].PublicCleanupOutstanding &&
                        NT_SUCCESS(SafeUploadStageNativeReadRevision(&afterRevision)))
                        (VOID)SafeUploadStagePublicOpenExchange(&rows[index], afterRevision,
                            SAFEUPLOAD_PUBLIC_OPEN_FACTS, &reply, NULL);
                    goto Exit; /* Map/pagination may have changed; its event resumes. */
                }
            }
        }
        offset += count;
    } while (!complete && count != 0 && offset < SAFEUPLOAD_NATIVE_REPLAY_MAX_RECORDS);
Exit:
    ExFreePoolWithTag(rows, STAGE_TAG);
#endif
}

static VOID StageNativeFlushFacts(VOID)
{
#if SAFEUPLOAD_STAGING_PROTOTYPE
    static UINT64 attemptedRevision;
    static LONG attemptedChannel;
    static UINT64 attemptedAuthority;
    PSAFEUPLOAD_STAGE_NATIVE_SNAPSHOT rows;
    UINT64 revision = 0;
    ULONG offset = 0, count = 0, index;
    BOOLEAN complete = FALSE;
    LONG channel = SafeUploadStageProtocolChannelGeneration();
    UINT64 authority = SafeUploadStageProtocolNativeAuthority();
    NTSTATUS status;
    if (SafeUploadStageMandatoryTeardownActive() ||
        !SafeUploadStageProtocolNativeForwardAllowed(0, authority)) return;
    /* NativeLock readers and acknowledgment touch these rows: nonpaged. A failed
     * allocation returns before the attempt marker, so the next event retries. */
    rows = ExAllocatePool2(POOL_FLAG_NON_PAGED,
        sizeof(*rows) * SAFEUPLOAD_NATIVE_REPLAY_PAGE_ROWS, STAGE_TAG);
    if (rows == NULL) return;
    do {
        UINT64 currentRevision;
        status = SafeUploadStageNativeReadPage(revision, offset, rows, SAFEUPLOAD_NATIVE_REPLAY_PAGE_ROWS,
            &count, &currentRevision, &complete);
        if (!NT_SUCCESS(status)) break;
        if (offset == 0) {
            revision = currentRevision;
            if (revision == attemptedRevision && channel == attemptedChannel && authority == attemptedAuthority) break;
            attemptedRevision = revision;
            attemptedChannel = channel;
            attemptedAuthority = authority;
        }
        for (index = 0; index < count; ++index) {
            SAFEUPLOAD_NATIVE_LIFECYCLE_REPLY reply;
            UINT64 replyAuthority;
            if (SafeUploadStageMandatoryTeardownActive()) goto Exit;
            /* Lower cancellation can conceal CREATE acceptance. Its exact
             * canceled-CLOSE or coverage-loss facts still need reconciliation
             * against the durable pre-CREATE intent, never a fabricated failed
             * CREATE receipt. Do not strand it behind CreateOutcomeKnown. */
            if (!rows[index].CreateOutcomeKnown && !rows[index].CancelledBeforeHandle &&
                !rows[index].CancelledCloseObserved && !rows[index].LastHandleCleanedUp &&
                !rows[index].CleanupCoverageLost) continue;
            status = SafeUploadStageNativeExchange(&rows[index], revision, SAFEUPLOAD_NATIVE_FACTS_CHANGED, &reply, &replyAuthority);
            if (!NT_SUCCESS(status)) continue; // A later map/channel event retries; no idle timer.
            if (reply.Result == SAFEUPLOAD_NATIVE_TERMINAL &&
                SafeUploadStageProtocolNativeForwardAllowed(0, replyAuthority) &&
                (rows[index].JournalGeneration == 0 || rows[index].JournalGeneration == reply.JournalGeneration)) {
                status = SafeUploadStageNativeAcknowledge(&rows[index].Binding);
                if (NT_SUCCESS(status)) {
                    UINT64 afterRevision;
                    /* Confirmation cannot erase the durable receipt unless
                     * authenticated replay proves this exact record is gone. */
                    status = SafeUploadStageNativeReadRevision(&afterRevision);
                    if (NT_SUCCESS(status)) (VOID)SafeUploadStageNativeExchange(&rows[index], afterRevision,
                        SAFEUPLOAD_NATIVE_FACTS_CHANGED, &reply, NULL);
                    /* Removal changed pagination; its event restarts the pass. */
                    goto Exit;
                }
            }
        }
        offset += count;
    } while (!complete && count != 0 && offset < SAFEUPLOAD_NATIVE_REPLAY_MAX_RECORDS);
Exit:
    ExFreePoolWithTag(rows, STAGE_TAG);
#endif
}

static VOID StageWorker(PVOID Context)
{
    PVOID objects[2];
#if SAFEUPLOAD_STAGING_PROTOTYPE
    KIRQL irql;
    LONG reconcileServiceGeneration = 0;
    LONG reconcileProtocolGeneration = 0;
    BOOLEAN reconcileAgain = FALSE;
    BOOLEAN reconcileCurrent = FALSE;
#endif
    UNREFERENCED_PARAMETER(Context);
    objects[0] = &StageWorkerStop;
    objects[1] = &StageWorkEvent;
    for (;;) {
        LIST_ENTRY released;
        LIST_ENTRY rpcs;
        LIST_ENTRY sealRpcs;
        LIST_ENTRY renameRpcs;
        LIST_ENTRY recoveryRpcs;
        LIST_ENTRY handleRpcs;
        NTSTATUS wait = KeWaitForMultipleObjects(2, objects, WaitAny, Executive, KernelMode, FALSE, NULL, NULL);
        if (wait != STATUS_WAIT_1) break;
        InitializeListHead(&released);
        InitializeListHead(&rpcs);
        InitializeListHead(&sealRpcs);
        InitializeListHead(&renameRpcs);
        InitializeListHead(&recoveryRpcs);
        InitializeListHead(&handleRpcs);
#if SAFEUPLOAD_STAGING_PROTOTYPE
        reconcileAgain = FALSE;
#endif
        StageAcquire(&StageNamespaceResource);
        if (StageServiceAvailable && !SafeUploadStageMandatoryTeardownActive() && (!StageStopping || StageUnloadPrepareWork) &&
            InterlockedCompareExchange(&StageReconcileNeeded, 0, 0) &&
            !InterlockedCompareExchange(&StageReconcileInFlight, 0, 0)) {
            InterlockedExchange(&StageReconcileInFlight, 1);
            StageReconcileWait = STAGE_WAIT_EXCHANGE;
            reconcileServiceGeneration = InterlockedCompareExchange(&StageServiceGeneration, 0, 0);
            reconcileProtocolGeneration = SafeUploadStageProtocolChannelGeneration();
        } else if (!SafeUploadStageMandatoryTeardownActive() && (!StageStopping || StageUnloadPrepareWork) &&
            (!StageServiceAvailable || !InterlockedCompareExchange(&StageReconcileNeeded, 0, 0))) {
            /* Disconnect cannot strand a local drain or exit-overflow sweep.
             * StageWorkerPass retains the reconnect sweep and collects no RPCs
             * until the current service channel has reconciled. */
            StageWorkerPass(&released, &rpcs, &sealRpcs, &renameRpcs, &recoveryRpcs,
                &handleRpcs);
        }
        StageRelease(&StageNamespaceResource);
        StageNativeFlushFacts(); /* No namespace/native lock spans FilterPort I/O. */
        StagePublicOpenFlushFacts();
#if SAFEUPLOAD_STAGING_PROTOTYPE
        if (InterlockedCompareExchange(&StageReconcileInFlight, 0, 0)) {
            const SAFEUPLOAD_REQUEST *drainReplay = StageEpochDrainRequestValid &&
                StageEpochDrainRequest.RequestId != 0 ? &StageEpochDrainRequest : NULL;
            NTSTATUS reconcileStatus = SafeUploadStageMandatoryTeardownActive() ? STATUS_PORT_DISCONNECTED :
                SafeUploadStageReconcileV20(&StageDriverInstanceId,
                reconcileProtocolGeneration, drainReplay);
            StageAcquire(&StageNamespaceResource);
            InterlockedExchange(&StageReconcileInFlight, 0);
            reconcileCurrent = reconcileServiceGeneration ==
                InterlockedCompareExchange(&StageServiceGeneration, 0, 0);
            if (!reconcileCurrent) {
                /* A connect or disconnect after this request owns the reconcile state and its wake (a reconnect signals
                 * the worker itself): a stale reply must not turn its SERVICE wait into a timed EXCHANGE retry. */
            } else if (NT_SUCCESS(reconcileStatus) ||
                (reconcileStatus == STATUS_DEVICE_BUSY && SafeUploadStageProtocolIsDrainReplayOnly())) {
                InterlockedExchange(&StageReconcileNeeded, 0);
                StageReconcileWait = STAGE_WAIT_NONE;
                if (NT_SUCCESS(reconcileStatus)) {
                    StageStreamAcquireSpinLock(&StageListLock, &irql);
                    StageSweepRequested = TRUE;
                    StageStreamReleaseSpinLock(&StageListLock, irql);
                }
                /* Either acceptance ends the skipped passes: run one for owed local work (an expiry, the exit ring).
                 * Only success requests the full sweep; drain-only acceptance grants no protocol authority. */
                reconcileAgain = TRUE;
            } else {
                StageReconcileWait = StageWaitFor(reconcileStatus);
            }
            StageUpdateRetryTimer();
            StageRelease(&StageNamespaceResource);
            if (reconcileAgain)
                KeSetEvent(&StageWorkEvent, IO_NO_INCREMENT, FALSE);
            continue;
        }
        StagePerformAllocationRecoveryRpcs(&recoveryRpcs);
        StagePerformHandleReceiptRpcs(&handleRpcs);
        StagePerformRenameRpcs(&renameRpcs);
        StagePerformSealRpcs(&sealRpcs);
        StagePerformDiscardRpcs(&rpcs);
#endif
        StageTeardownReleased(&released);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS SafeUploadStageDispose(_In_ PSAFEUPLOAD_STAGE_DISPOSE_MESSAGE Message, _Out_ PUINT32 Held)
{
    PLIST_ENTRY link;
    KIRQL irql;
    BOOLEAN held = FALSE, accepted = FALSE, stale = FALSE, deferred = FALSE;
    *Held = 0;
    if (Message->Control.Version != SAFEUPLOAD_PROTOCOL_VERSION || Message->Control.StructSize != sizeof(*Message) ||
        Message->Control.Reserved != 0 ||
        (Message->Outcome != SAFEUPLOAD_STAGE_DISPOSE_RELEASED && Message->Outcome != SAFEUPLOAD_STAGE_DISPOSE_CLEANED_UP))
        return STATUS_INVALID_PARAMETER;
    if (!StageInitialized) return STATUS_DEVICE_NOT_READY;
    /* Never NamespaceResource here: the worker holds it while it waits for a reply from this same service. */
    StageStreamAcquireSpinLock(&StageListLock, &irql);
    for (link = StageStreams.Flink; link != &StageStreams; link = link->Flink) {
        PSTAGE_STREAM stream = CONTAINING_RECORD(link, STAGE_STREAM, Link);
        if (!stream->HasTransferId || !RtlEqualMemory(&stream->TransferId, &Message->TransferId, sizeof(GUID))) continue;
        held = TRUE;
        if (Message->CommittedRenames != stream->RenameCommits) {
            stale = TRUE;        /* a rename committed since: the service inspects the moved version again */
        } else if (stream->RenameExchange != NULL) {
            deferred = TRUE;     /* decided by how the exchange ends (StageFinishRename) */
            stream->DisposeDeferred = TRUE;
            stream->DeferredOutcome = Message->Outcome;
        } else {
            accepted = TRUE;
            stream->Disposed = TRUE;
            stream->DisposeOutcome = Message->Outcome;
            (VOID)StageQueueLocked(stream);
        }
        break;
    }
    StageStreamReleaseSpinLock(&StageListLock, irql);
    if (accepted) {
        InterlockedIncrement64((volatile LONG64 *)&StageCounters.DisposeHeld);
        InterlockedIncrement64((volatile LONG64 *)&StageCounters.WakeDispose);
        KeSetEvent(&StageWorkEvent, IO_NO_INCREMENT, FALSE);
    } else if (stale) InterlockedIncrement64((volatile LONG64 *)&StageCounters.DisposeStale);
    else if (deferred) InterlockedIncrement64((volatile LONG64 *)&StageCounters.DisposeDeferred);
    else InterlockedIncrement64((volatile LONG64 *)&StageCounters.DisposeNotHeld);
    *Held = held ? 1 : 0;
    return STATUS_SUCCESS;
}

VOID SafeUploadStageServiceConnected(_In_ PVOID ConnectionCookie)
{
    KIRQL irql;
    if (!StageInitialized) return;
    SafeUploadStageProtocolAuthenticationChanged(ConnectionCookie);
    StageAcquire(&StageNamespaceResource);
    /* Disconnect resets the channel cookie before taking this lock to clear availability. A notification for a connection
     * already reset must not publish availability, a generation or a reconcile after it. */
    if (!SafeUploadStageProtocolConnectionCurrent(ConnectionCookie)) {
        StageRelease(&StageNamespaceResource);
        return;
    }
    StageServiceAvailable = TRUE;
    InterlockedIncrement(&StageServiceGeneration);
    InterlockedExchange(&StageReconcileNeeded, 1);
    StageReconcileWait = STAGE_WAIT_EXCHANGE;
    StageRelease(&StageNamespaceResource);
    StageStreamAcquireSpinLock(&StageListLock, &irql);
    StageSweepRequested = TRUE;
    StageStreamReleaseSpinLock(&StageListLock, irql);
    InterlockedIncrement64((volatile LONG64 *)&StageCounters.WakeConnect);
    KeSetEvent(&StageWorkEvent, IO_NO_INCREMENT, FALSE);
}

VOID SafeUploadStageServiceDisconnected(_In_ PVOID ConnectionCookie)
{
    PLIST_ENTRY link;
    KIRQL irql;
    if (!StageInitialized) return;
    SafeUploadStageProtocolConnectionReset(ConnectionCookie);
    StageAcquire(&StageNamespaceResource);
    StageServiceAvailable = FALSE;
    InterlockedIncrement(&StageServiceGeneration);
    InterlockedExchange(&StageReconcileNeeded, 1);
    StageReconcileWait = STAGE_WAIT_SERVICE;
    StageStreamAcquireSpinLock(&StageListLock, &irql);
    for (link = StageStreams.Flink; link != &StageStreams; link = link->Flink) {
        PSTAGE_STREAM stream = CONTAINING_RECORD(link, STAGE_STREAM, Link);
        if (stream->HandleReceiptWait == STAGE_WAIT_EXCHANGE) stream->HandleReceiptWait = STAGE_WAIT_SERVICE;
        if (stream->RenameWait == STAGE_WAIT_EXCHANGE) stream->RenameWait = STAGE_WAIT_SERVICE;
        if (stream->AllocationRecoveryWait == STAGE_WAIT_EXCHANGE) stream->AllocationRecoveryWait = STAGE_WAIT_SERVICE;
        if (stream->Wait == STAGE_WAIT_EXCHANGE) stream->Wait = STAGE_WAIT_SERVICE;
    }
    StageStreamReleaseSpinLock(&StageListLock, irql);
    /* Retain pending/in-flight requests and their exact tuples. Reconnect's
     * reconciled sweep unparks them. The census also excludes a late RPC reply
     * that restores EXCHANGE while disconnected; genuine drain/overflow waits
     * remain eligible. No disconnected exchange needs timer polling. */
    StageUpdateRetryTimer();
    StageRelease(&StageNamespaceResource);
}

VOID SafeUploadStageProcessExited(_In_ HANDLE ProcessId)
{
    PEPROCESS process = NULL;
    KIRQL irql;
    BOOLEAN queued = FALSE;
    if (!StageInitialized) return;
    /* Nothing names an owner: no view or tombstone can match (an exiting process has no thread left to create one). */
    if (StageViewCount == 0 && StageTombstoneCount == 0) return;
    /* The ring keeps the process object referenced, so its PID cannot be reused before the worker matches it. */
    if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &process))) process = NULL;
    StageStreamAcquireSpinLock(&StageListLock, &irql);
    /* Checked again under the lock: SafeUploadStageFree clears it under the same lock before draining the ring. */
    if (StageInitialized) {
        if (process != NULL && StageExitCount < STAGE_EXIT_RING) { StageExitRing[StageExitCount++] = process; process = NULL; }
        else StageExitOverflow = TRUE;
        queued = TRUE;
    }
    StageStreamReleaseSpinLock(&StageListLock, irql);
    if (process != NULL) ObDereferenceObject(process);
    if (!queued) return;
    InterlockedIncrement64((volatile LONG64 *)&StageCounters.WakeExit);
    KeSetEvent(&StageWorkEvent, IO_NO_INCREMENT, FALSE);
}

VOID SafeUploadStageGetLifetimeCounters(_Out_ PSAFEUPLOAD_STAGE_LIFETIME_COUNTERS Counters)
{
    *Counters = StageCounters;
    Counters->LiveVersions = StageStreamCount;
    Counters->LiveViews = StageViewCount;
    Counters->Tombstones = StageTombstoneCount;
}

/* Phase 3 admission no longer consumes StageFence's directory scan, scan-built SOP fence,
 * quarantine/retry table, or policy refresh mutex. The bounded writer registry and active SOP map
 * replace enumeration and scan-built paging/read denial; targeted file-ID probes replace broad
 * scans; attach trust plus per-instance/file Unknown replaces quarantine; policy epochs and the
 * service's durable two-phase commit replace scan/swap serialization; cleanup, section/transaction
 * completion, and targeted reclaim replace retry timers; registry/epoch pages replace fence
 * counters. StageFence remains buildable only for explicit diagnostic refresh/status and setup/
 * unload coordination; no boot-policy, SET_POLICY, or file-I/O admission path calls it. */
NTSTATUS SafeUploadStageInitialize(VOID)
{
    NTSTATUS status;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    static const GUID emptyDriverId = {0};
    InterlockedExchange(&StageFilteringReady, 0);
    InterlockedExchange(&StageUnloadAdmissionClosed, 0);
    InterlockedExchange(&StageUnloadQuarantined, 0);
    InterlockedExchange(&StageMandatoryTeardown, 0);
    ExInitializeRundownProtection(&StageOwnedCallbackBodies);
    StageMandatoryLocalDrained = FALSE;
    SafeUploadStagePublicInitialize();
    StageUnloadPrepareWork = FALSE;
    status = ExUuidCreate(&StageDriverInstanceId);
    if (!NT_SUCCESS(status)) return status;
    if (RtlEqualMemory(&StageDriverInstanceId, &emptyDriverId, sizeof(GUID)))
        return STATUS_UNSUCCESSFUL;
    InterlockedExchange(&StageReconcileNeeded, 1);
    InterlockedExchange(&StageReconcileInFlight, 0);
    InterlockedExchange(&StageServiceGeneration, 0);
    StageServiceAvailable = FALSE;
    StageReconcileWait = STAGE_WAIT_SERVICE;
    RtlZeroMemory(&StageEpochDrainRequest, sizeof(StageEpochDrainRequest));
    StageEpochDrainNonce = 0;
    StageEpochDrainRequestValid = FALSE;
#endif
    StageStopping = FALSE;
    InitializeListHead(&StageStreams);
    InitializeListHead(&StageViews);
    InitializeListHead(&StageWorkQueue);
    InitializeListHead(&StageTombstones);
    InitializeListHead(&StageAllocationReservations);
    KeInitializeSpinLock(&StageListLock);
    KeInitializeEvent(&StageWorkerStop, NotificationEvent, FALSE);
    KeInitializeEvent(&StageWorkEvent, SynchronizationEvent, FALSE);
#if SAFEUPLOAD_STAGING_PROTOTYPE
    KeInitializeSpinLock(&StageAttachLock);
    InitializeListHead(&StageAttachLookup);
    InitializeListHead(&StageAttachTearingDownInstances);
    InitializeListHead(&StageAttachQueue);
    KeInitializeEvent(&StageAttachDrained, NotificationEvent, TRUE);
    KeInitializeEvent(&StageAttachChanged, NotificationEvent, FALSE);
    KeInitializeEvent(&StageAttachQueueEvent, SynchronizationEvent, FALSE);
    KeInitializeEvent(&StageAttachThreadStop, NotificationEvent, FALSE);
    StageAttachActiveCount = 0;
    RtlZeroMemory((PVOID)StageAttachCaptures, sizeof(StageAttachCaptures));
    StageAttachCaptureCount = 0;
    StageAttachStopping = FALSE;
    StageAttachAccepting = TRUE;
    StageAttachThreadRunning = FALSE;
    StageAttachThreadHandle = NULL;
#endif
    KeInitializeTimer(&StageRetryTimer);
    KeInitializeDpc(&StageRetryDpc, StageRetryDpcRoutine, NULL);
    SafeUploadStageInitializeProtocol();
    status = ExInitializeResourceLite(&StageNamespaceResource);
    if (NT_SUCCESS(status)) {
#if SAFEUPLOAD_STAGING_PROTOTYPE
        /* A failed DriverEntry gets no unload callback and StageFree returns
         * early while StageInitialized is FALSE: each failure here releases,
         * in reverse order, everything this function already acquired. */
        SafeUploadStageWritersInitialize();
        status = SafeUploadStageFenceInitialize();
        if (!NT_SUCCESS(status)) {
            SafeUploadStageWritersUninitialize();
            ExDeleteResourceLite(&StageNamespaceResource);
            return status;
        }
        SafeUploadStageNativeInitialize(&StageDriverInstanceId, SharedUserData->BootId, &StageWorkEvent);
        status = SafeUploadBoundPublicationInitialize(&StageDriverInstanceId, SharedUserData->BootId);
        if (!NT_SUCCESS(status)) {
            SafeUploadStageNativeUninitialize();
            SafeUploadStageFenceFree();
            SafeUploadStageWritersUninitialize();
            ExDeleteResourceLite(&StageNamespaceResource);
            return status;
        }
        ExInitializeFastMutex(&AdmissionTraceControlMutex);
        ExInitializeRundownProtection(&AdmissionTraceRundown);
        AdmissionTraceRundownClosed = FALSE;
        InterlockedExchange(&SafeUploadAdmissionTraceControlState, 0);
        InterlockedExchange(&SafeUploadAdmissionTraceSectionEvents, 0);
        InterlockedExchange(&AdmissionTraceLifetimeEvents, 0);
        StageAdmissionTraceReset();
#endif
        StageInitialized = TRUE;
    }
    return status;
}

#if SAFEUPLOAD_STAGING_PROTOTYPE
VOID SafeUploadStageSetFilteringReady(VOID)
{
    /* DriverEntry calls this only after FltStartFiltering succeeds. */
    InterlockedExchange(&StageFilteringReady, 1);
}
#endif

NTSTATUS SafeUploadStageStartWorker(VOID)
{
    OBJECT_ATTRIBUTES attributes;
    NTSTATUS status;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    status = SafeUploadStageAdmissionStartWorker();
    if (!NT_SUCCESS(status)) return status;
#endif
    InitializeObjectAttributes(&attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
#if SAFEUPLOAD_STAGING_PROTOTYPE
    status = PsCreateSystemThread(&StageAttachThreadHandle, SYNCHRONIZE, &attributes,
        NULL, NULL, StageAttachWorkerThread, &StageAttachThreadStop);
    if (!NT_SUCCESS(status)) {
        SafeUploadStageAdmissionStopWorker();
        return status;
    }
    StageAttachThreadRunning = TRUE;
#endif
    status = PsCreateSystemThread(&StageWorkerHandle, SYNCHRONIZE, &attributes, NULL, NULL, StageWorker, NULL);
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (!NT_SUCCESS(status)) {
        KeSetEvent(&StageAttachThreadStop, IO_NO_INCREMENT, FALSE);
        KeSetEvent(&StageAttachQueueEvent, IO_NO_INCREMENT, FALSE);
        if (StageAttachThreadHandle != NULL) {
            (VOID)ZwWaitForSingleObject(StageAttachThreadHandle, FALSE, NULL);
            ZwClose(StageAttachThreadHandle);
            StageAttachThreadHandle = NULL;
        }
        StageAttachThreadRunning = FALSE;
        SafeUploadStageAdmissionStopWorker();
        return status;
    }
#endif
    return status;
}

VOID SafeUploadStageStopWorker(VOID)
{
#if SAFEUPLOAD_STAGING_PROTOTYPE
    KIRQL irql;
    PLIST_ENTRY link;
    StageStreamAcquireSpinLock(&StageAttachLock, &irql);
    StageAttachStopping = TRUE;
    StageAttachAccepting = FALSE;
    for (link = StageAttachLookup.Flink; link != &StageAttachLookup; link = link->Flink) {
        PSTAGE_ATTACH_TRANSACTION tx = CONTAINING_RECORD(link, STAGE_ATTACH_TRANSACTION, LookupLink);
        InterlockedExchange(&tx->TeardownRequested, 1);
        InterlockedExchange(&tx->CancelRequested, 1);
    }
    StageStreamReleaseSpinLock(&StageAttachLock, irql);
    KeSetEvent(&StageAttachQueueEvent, IO_NO_INCREMENT, FALSE);
    if (SafeUploadStageMandatoryTeardownActive()) {
        StageAcquire(&StageNamespaceResource);
        StageStopping = TRUE;
        StageUnloadPrepareWork = FALSE;
        StageRelease(&StageNamespaceResource);
    }
    /* Deferred attachment callbacks are bounded by StageAttachActiveCount.
     * They observe stopping at every service boundary and complete their
     * pended CREATE exactly once before the filter begins unregistering. */
    for (;;) {
        BOOLEAN drained;
        StageStreamAcquireSpinLock(&StageAttachLock, &irql);
        drained = StageAttachActiveCount == 0 && StageAttachCaptureCount == 0;
        if (!drained) KeClearEvent(&StageAttachDrained);
        StageStreamReleaseSpinLock(&StageAttachLock, irql);
        if (drained) break;
        (VOID)KeWaitForSingleObject(&StageAttachDrained, Executive, KernelMode, FALSE, NULL);
    }
    if (StageAttachThreadRunning) {
        KeSetEvent(&StageAttachThreadStop, IO_NO_INCREMENT, FALSE);
        KeSetEvent(&StageAttachQueueEvent, IO_NO_INCREMENT, FALSE);
        if (StageAttachThreadHandle != NULL) {
            (VOID)ZwWaitForSingleObject(StageAttachThreadHandle, FALSE, NULL);
            ZwClose(StageAttachThreadHandle);
            StageAttachThreadHandle = NULL;
        }
        StageAttachThreadRunning = FALSE;
    }
#endif
    if (StageWorkerHandle != NULL) {
        KeSetEvent(&StageWorkerStop, IO_NO_INCREMENT, FALSE);
        (VOID)ZwWaitForSingleObject(StageWorkerHandle, FALSE, NULL);
        ZwClose(StageWorkerHandle); StageWorkerHandle = NULL;
        /* The worker armed the retry timer; no DPC of this image may run after unload. */
        (VOID)KeCancelTimer(&StageRetryTimer);
        KeFlushQueuedDpcs();
        StageRetryArmed = FALSE;
    }
#if SAFEUPLOAD_STAGING_PROTOTYPE
    SafeUploadStageAdmissionStopWorker();
#endif
}

BOOLEAN SafeUploadStageCanDetach(VOID)
{
#if SAFEUPLOAD_STAGING_PROTOTYPE
    KIRQL irql;
    BOOLEAN attachIdle;
    /* One lock hold: a capture converting to an active transaction is never
     * observed as neither. */
    StageStreamAcquireSpinLock(&StageAttachLock, &irql);
    attachIdle = StageAttachActiveCount == 0 && StageAttachCaptureCount == 0;
    StageStreamReleaseSpinLock(&StageAttachLock, irql);
    return StageStreamCount == 0 && StageReservedStreamCount == 0 && attachIdle;
#else
    return StageStreamCount == 0 && StageReservedStreamCount == 0;
#endif
}

VOID SafeUploadStageRecordUnloadVeto(_In_ UINT32 Reason, _In_ NTSTATUS Status)
{
    (VOID)InterlockedExchange64(&StageLastUnloadVeto, (LONG64)(((UINT64)Reason << 32) | (UINT32)Status));
}

VOID SafeUploadStageGetUnloadStatus(_Out_ PUINT32 Streams, _Out_ PUINT32 FileObjects,
    _Out_ PUINT32 Reason, _Out_ PUINT32 Status)
{
    UINT64 veto = (UINT64)InterlockedCompareExchange64(&StageLastUnloadVeto, 0, 0);
    *Streams = StageStreamCount;
    *FileObjects = (UINT32)InterlockedCompareExchange(&StageFileObjects, 0, 0);
    *Reason = (UINT32)(veto >> 32);
    *Status = (UINT32)veto;
}

#if SAFEUPLOAD_STAGING_PROTOTYPE
BOOLEAN SafeUploadStageUnloadIsQuarantined(VOID)
{
    return InterlockedCompareExchange(&StageUnloadQuarantined, 0, 0) != 0;
}
#endif

#if SAFEUPLOAD_STAGING_PROTOTYPE
_Use_decl_annotations_
BOOLEAN SafeUploadStageMandatoryTeardownActive(VOID)
{
    /* Permanent local teardown, irrespective of the unload caller. The
     * voluntary caller sets it only AFTER PrepareUnload commits P/Q. */
    return InterlockedCompareExchange(&StageMandatoryTeardown, 0, 0) != 0;
}

_Use_decl_annotations_
VOID SafeUploadStageBeginMandatoryTeardown(VOID)
{
    KIRQL irql;
    PLIST_ENTRY link;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    /* Publish without acquiring NamespaceResource: a pre-fence user may
     * still own it across an old exchange. Close the port before joining it. */
    StageStreamAcquireSpinLock(&StageAttachLock, &irql);
    InterlockedExchange(&StageMandatoryTeardown, 1);
    InterlockedExchange(&StageUnloadAdmissionClosed, 1);
    StageAttachStopping = TRUE;
    StageAttachAccepting = FALSE;
    for (link = StageAttachLookup.Flink; link != &StageAttachLookup; link = link->Flink) {
        PSTAGE_ATTACH_TRANSACTION tx = CONTAINING_RECORD(link, STAGE_ATTACH_TRANSACTION, LookupLink);
        InterlockedExchange(&tx->TeardownRequested, 1);
        InterlockedExchange(&tx->CancelRequested, 1);
    }
    StageStreamReleaseSpinLock(&StageAttachLock, irql);
    SafeUploadStageNativeCloseAdmission();
    SafeUploadBoundPublicationCloseAdmission();
    SafeUploadStagePublicCloseAdmission();
    KeSetEvent(&StageAttachQueueEvent, IO_NO_INCREMENT, FALSE);
    KeSetEvent(&StageWorkerStop, IO_NO_INCREMENT, FALSE);
}

_Use_decl_annotations_
VOID SafeUploadStageDrainMandatoryTeardown(VOID)
{
    PLIST_ENTRY link;
    LARGE_INTEGER retry;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    NT_ASSERT(SafeUploadStageMandatoryTeardownActive());
    NT_ASSERT(StageWorkerHandle == NULL && !StageAttachThreadRunning);
    SafeUploadStageFenceDrainLocal();
    SafeUploadBoundPublicationDrainLocal(); /* Drops version pins before the stage RPC-reference wait. */
    for (;;) {
        PSTAGE_ATTACH_INSTANCE_TOMBSTONE tombstone = NULL;
        KIRQL irql;
        StageStreamAcquireSpinLock(&StageAttachLock, &irql);
        if (!IsListEmpty(&StageAttachTearingDownInstances))
            tombstone = CONTAINING_RECORD(RemoveHeadList(&StageAttachTearingDownInstances),
                STAGE_ATTACH_INSTANCE_TOMBSTONE, Link);
        StageStreamReleaseSpinLock(&StageAttachLock, irql);
        if (tombstone == NULL) break;
        /* The permanent global gate now supplies this admission key. This
         * does not retire native coverage-loss evidence or certify last close. */
        FltObjectDereference(tombstone->Instance);
        ExFreePoolWithTag(tombstone, STAGE_TAG);
    }
    /* Communication and workers have drained. The list now owns every
     * remaining stream; no producer can allocate/unlink one. Do not use
     * StageDrain: it is a sealing helper called with resources held. */
    retry.QuadPart = -250LL * 10 * 1000;
    for (link = StageStreams.Flink; link != &StageStreams; link = link->Flink) {
        PSTAGE_STREAM stream = CONTAINING_RECORD(link, STAGE_STREAM, Link);
        for (;;) {
            BOOLEAN handles, drained;
            NTSTATUS status = STATUS_SUCCESS;
            StageAcquire(&stream->Resource);
            handles = stream->ShareAccess.OpenCount != 0;
            StageRelease(&stream->Resource);
            if (!handles && MmCanFileBeTruncated(&stream->Sections, NULL)) {
                /* No new CREATE; cleaned upper objects cannot start ordinary
                 * writes. Cache/paging callbacks remain admitted. All flush,
                 * purge and subsequent CLOSE callbacks run without our locks. */
                if (stream->BackingObject != NULL) status = StageFlush(stream);
                if (NT_SUCCESS(status))
                    (VOID)CcPurgeCacheSection(&stream->Sections, NULL, 0, TRUE);
            }
            StageAcquire(&stream->Resource);
            drained = NT_SUCCESS(status) && stream->ShareAccess.OpenCount == 0 &&
                InterlockedCompareExchange(&stream->FileObjects, 0, 0) == 0 &&
                stream->Sections.SharedCacheMap == NULL && stream->Sections.DataSectionObject == NULL &&
                stream->Sections.ImageSectionObject == NULL &&
                InterlockedCompareExchange(&stream->RpcReferences, 0, 0) == 0;
            StageRelease(&stream->Resource);
            if (drained) break;
            /* Unmap has no callback. This only paces a new lifetime check;
             * elapsed time never grants permission to release anything. */
            (VOID)KeDelayExecutionThread(KernelMode, FALSE, &retry);
        }
    }
    ExWaitForRundownProtectionRelease(&StageOwnedCallbackBodies);
    for (link = StageStreams.Flink; link != &StageStreams; link = link->Flink) {
        PSTAGE_STREAM stream = CONTAINING_RECORD(link, STAGE_STREAM, Link);
        PSAFEUPLOAD_STAGE_WRITER_LEASE lease = stream->AllocationWriterLease;
        stream->AllocationWriterLease = NULL;
        SafeUploadStagePublicReleaseWriter(lease); /* Local close, never allocation replay/ACK. */
        lease = stream->PublicationWriterLease;
        stream->PublicationWriterLease = NULL;
        SafeUploadStagePublicReleaseWriter(lease);
    }
    SafeUploadStageNativeDrainLocal();
    /* Destroy owning records before testing their aggregate counts. Neither
     * a service ACK nor RegistryLifetimeOwners == 0 is a drain prerequisite. */
    SafeUploadStagePublicDrainBackends();
    NT_ASSERT(SafeUploadStageWritersOwnerCount() == 0);
    StageMandatoryLocalDrained = TRUE;
}
#endif

/* Roll back only the unload-owned admission gates after a voluntary veto
 * that happened before any service cleanup could commit. Fence admission is
 * reopened first; StageStopping is then cleared under NamespaceResource; the
 * separate attach gate opens last under StageAttachLock. Sticky attach
 * allocation failure/stopping state is never modified here. */
#if SAFEUPLOAD_STAGING_PROTOTYPE
static VOID StageRollbackUnloadPreparation(VOID)
{
    SafeUploadStageFenceCancelUnload();
    StageAcquire(&StageNamespaceResource);
    StageStopping = FALSE;
    StageUnloadPrepareWork = FALSE;
    StageRelease(&StageNamespaceResource);
    StageSetUnloadAdmissionClosed(FALSE);
    SafeUploadStageNativeReopenAdmission();
    SafeUploadBoundPublicationReopenAdmission();
    SafeUploadStagePublicReopenAdmission();
    KeSetEvent(&StageWorkEvent, IO_NO_INCREMENT, FALSE);
}
#endif

NTSTATUS SafeUploadStagePrepareUnload(_In_ BOOLEAN Mandatory)
{
    PLIST_ENTRY link;
    BOOLEAN quarantined = FALSE;
    BOOLEAN cleanupRequired = FALSE;
    BOOLEAN renamePending = FALSE;
    BOOLEAN discardPending = FALSE;
    BOOLEAN objectPending = FALSE;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    static const GUID emptyDrainGuid = {0};
    BOOLEAN drainReplayOnly = FALSE;
    BOOLEAN drainRequestExists = FALSE;
    UINT32 drainResult = 0;
    GUID drainGuid;
#endif
    NTSTATUS status = STATUS_SUCCESS;
#if !SAFEUPLOAD_STAGING_PROTOTYPE
    UNREFERENCED_PARAMETER(Mandatory);
#endif
#if SAFEUPLOAD_STAGING_PROTOTYPE
    quarantined = SafeUploadStageUnloadIsQuarantined();
    SafeUploadStageRecordUnloadVeto(SAFEUPLOAD_UNLOAD_VETO_NONE, STATUS_SUCCESS);

    /* Feature registration rejects mandatory service-stop requests before
     * this callback. Never unregister while a native fallback/receipt still
     * exists, especially after instance teardown hid its CLEANUP callback. */
    if (!SafeUploadBoundPublicationTryCloseAdmission()) {
        SafeUploadStageRecordUnloadVeto(SAFEUPLOAD_UNLOAD_VETO_STAGE_DRAIN, STATUS_DEVICE_BUSY);
        return STATUS_FLT_DO_NOT_DETACH;
    }
    if (!SafeUploadStageNativeTryCloseAdmission()) {
        SafeUploadBoundPublicationReopenAdmission();
        SafeUploadStageRecordUnloadVeto(SAFEUPLOAD_UNLOAD_VETO_STAGE_DRAIN, STATUS_DEVICE_BUSY);
        return STATUS_FLT_DO_NOT_DETACH;
    }
    if (!SafeUploadStagePublicTryCloseAdmission()) {
        SafeUploadBoundPublicationReopenAdmission();
        SafeUploadStageNativeReopenAdmission();
        SafeUploadStageRecordUnloadVeto(SAFEUPLOAD_UNLOAD_VETO_STAGE_OBJECTS, STATUS_DEVICE_BUSY);
        return STATUS_FLT_DO_NOT_DETACH;
    }

    /* Close CREATE/attach admission before the fence scan. The attach gate is
     * serialized against active-count publication. Mandatory unload and an
     * already-quarantined retry keep the worker eligible; a reversible
     * voluntary preflight pauses new worker passes until it either rolls back
     * or crosses into exact cleanup/epoch commit. */
    StageSetUnloadAdmissionClosed(TRUE);
    StageAcquire(&StageNamespaceResource);
    StageStopping = TRUE;
    StageUnloadPrepareWork = Mandatory || quarantined;
    StageRelease(&StageNamespaceResource);

    /* Stop new Connect/Message callback bodies while retaining the exact
     * outbound service-use path needed for cleanup replies and epoch drain.
     * The helper waits with no namespace, Exchange, or spin lock held. Its
     * successful gate close precedes the stage/RPC/queue scan below; a
     * precommit failure reopens only this callback gate. Disconnect cleanup
     * remains admitted and cookie-scoped. */
    status = SafeUploadTryStageCallbackUnloadPreflight();
    if (!NT_SUCCESS(status)) {
        SafeUploadStageRecordUnloadVeto(SAFEUPLOAD_UNLOAD_VETO_STAGE_DRAIN, status);
        if (!Mandatory && !quarantined) {
            StageRollbackUnloadPreparation();
            SafeUploadOpenStageCallbackUnloadAdmission();
        } else {
            StageAcquire(&StageNamespaceResource);
            StageUnloadPrepareWork = TRUE;
            StageRelease(&StageNamespaceResource);
            SafeUploadOpenStageCallbackUnloadAdmission();
            KeSetEvent(&StageWorkEvent, IO_NO_INCREMENT, FALSE);
        }
        return STATUS_FLT_DO_NOT_DETACH;
    }

    status = SafeUploadStageFencePrepareUnload();
    if (!NT_SUCCESS(status)) {
        SafeUploadStageRecordUnloadVeto(SAFEUPLOAD_UNLOAD_VETO_FENCE, status);
        if (!Mandatory && !quarantined) {
            StageRollbackUnloadPreparation();
            SafeUploadOpenStageCallbackUnloadAdmission();
        } else {
            StageAcquire(&StageNamespaceResource);
            StageUnloadPrepareWork = TRUE;
            StageRelease(&StageNamespaceResource);
            SafeUploadOpenStageCallbackUnloadAdmission();
            KeSetEvent(&StageWorkEvent, IO_NO_INCREMENT, FALSE);
        }
        return STATUS_FLT_DO_NOT_DETACH;
    }
#endif
    StageAcquire(&StageNamespaceResource);
    StageStopping = TRUE;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    StageUnloadPrepareWork = Mandatory || quarantined;
    drainReplayOnly = SafeUploadStageProtocolIsDrainReplayOnly();
    drainRequestExists = StageEpochDrainRequestValid && StageEpochDrainRequest.RequestId != 0 &&
        StageEpochDrainNonce != 0;
    if (InterlockedCompareExchange(&StageReconcileNeeded, 0, 0) ||
        InterlockedCompareExchange(&StageReconcileInFlight, 0, 0) ||
        (!SafeUploadStageProtocolIsReady() && !drainReplayOnly) ||
        (drainReplayOnly && !drainRequestExists)) {
        discardPending = TRUE;
        status = STATUS_DEVICE_BUSY;
        KeSetEvent(&StageWorkEvent, IO_NO_INCREMENT, FALSE);
        goto Veto;
    }
    if (!SafeUploadPolicyPublicationQuiescent() || !SafeUploadStageWritersUnloadReady() ||
        InterlockedCompareExchange(&StageAttachActiveCount, 0, 0) != 0 ||
        InterlockedCompareExchange(&StageAttachCaptureCount, 0, 0) != 0) {
        objectPending = TRUE;
        status = STATUS_DEVICE_BUSY;
        goto Veto;
    }
#endif
    if (StageReservedStreamCount != 0) {
        objectPending = TRUE;
        status = STATUS_DEVICE_BUSY;
        goto Veto;
    }
    /* This count cannot increase after StageStopping is set. Check it before
     * queueing any unload-specific delete so a late FILE_OBJECT causes a
     * clean, reversible veto with no new empty-stage deletion. */
    if (InterlockedCompareExchange(&StageFileObjects, 0, 0) != 0) {
        objectPending = TRUE;
        status = STATUS_DEVICE_BUSY;
        goto Veto;
    }
#if SAFEUPLOAD_STAGING_PROTOTYPE
    /* Scan every attachment before classifying allocation receipts as cleanup.
     * An op15 ambiguity (or late completion fence/op16 retry) needs its owner
     * CREATE route. Veto while preparation is reversible, before quarantine
     * or any unload-specific cleanup is queued. NamespaceResource serializes
     * this scan with attachment state; admission and active captures are shut. */
    for (link = StageStreams.Flink; link != &StageStreams; link = link->Flink) {
        PSTAGE_STREAM stream = CONTAINING_RECORD(link, STAGE_STREAM, Link);
        if (stream->AttachCompletionPending || stream->AttachCompletionFence ||
            stream->AttachRetirePending || stream->AttachLifecycleInFlight ||
            (stream->AllocationReceiptPending &&
             (stream->AttachCompletionMayExist || stream->AttachCompletionKnown))) {
            objectPending = TRUE;
            status = STATUS_DEVICE_BUSY;
            goto Veto;
        }
    }
#endif
    for (link = StageStreams.Flink; link != &StageStreams; link = link->Flink) {
        PSTAGE_STREAM stream = CONTAINING_RECORD(link, STAGE_STREAM, Link);
        if (stream->RenameExchange != NULL || stream->RenameRpcPending || stream->RenameRpcInFlight) {
            renamePending = TRUE;
            status = STATUS_DEVICE_BUSY;
            StageQueueStream(stream, NULL);
            break;
        }
#if SAFEUPLOAD_STAGING_PROTOTYPE
        if (InterlockedCompareExchange(&stream->FileObjects, 0, 0) != 0) {
            objectPending = TRUE;
            status = STATUS_DEVICE_BUSY;
            break;
        }
        if (stream->DiscardRpcPending || stream->DiscardRpcInFlight) {
            if (stream->DiscardRpcKind == SAFEUPLOAD_STAGE_DISCARD_KIND_UNATTACHED_ALLOCATION)
                cleanupRequired = TRUE;
            else {
                discardPending = TRUE;
                status = STATUS_DEVICE_BUSY;
                StageQueueStream(stream, NULL);
                break;
            }
        }
        if (stream->HandleReceiptPending || stream->HandleReceiptInFlight ||
            stream->SealRpcPending || stream->SealRpcInFlight ||
            stream->AllocationRecoveryPending || stream->AllocationRecoveryInFlight ||
            stream->AllocationRpcInFlight || stream->AllocationReceiptReferences != 0 ||
            InterlockedCompareExchange(&stream->RpcReferences, 0, 0) != 0) {
            discardPending = TRUE;
            status = STATUS_DEVICE_BUSY;
            StageQueueStream(stream, NULL);
            break;
        }
        if (stream->AllocationReceiptPending) {
            cleanupRequired = TRUE;
            StageQueueStream(stream, NULL);
            continue; /* replay/cleanup uses the exact retained allocation receipt */
        }
        if (!stream->Sealed || (stream->DiscardOnClose && !stream->Discarded) ||
            stream->PrivateDeleteReserved) {
            StageQueueStream(stream, NULL);
            discardPending = TRUE;
            status = STATUS_DEVICE_BUSY;
            break;
        }
#endif
        /* A discard keeps private bytes and the retry state until the service confirms the journal transition and stage removal. */
        if (stream->DiscardOnClose && !stream->Discarded) {
            discardPending = TRUE;
            status = STATUS_DEVICE_BUSY;
            StageQueueStream(stream, NULL);
            break;
        }
        if (stream->Sealed && stream->Retired) continue;
        if (stream->BackingObject == NULL) {
            if (stream->Discarded || stream->Retired) continue;
            discardPending = TRUE;
            status = STATUS_DEVICE_BUSY;
            StageQueueStream(stream, NULL);
            break;
        }
        StageAcquire(&stream->Resource);
        status = StageDrain(stream);
        StageRelease(&stream->Resource);
        if (!NT_SUCCESS(status)) {
            discardPending = TRUE;
            StageQueueStream(stream, NULL);
            break;
        }
    }

    /* All unrelated blockers and file objects were checked before this
     * commit. From here, any exact cleanup may reach the service, so a veto
     * retains StageStopping and the fence gate instead of reopening admission. */
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (NT_SUCCESS(status) && cleanupRequired) {
        if (!quarantined) {
            InterlockedExchange(&StageUnloadQuarantined, 1);
            quarantined = TRUE;
        }
        StageUnloadPrepareWork = TRUE;
        for (link = StageStreams.Flink; link != &StageStreams; link = link->Flink) {
            PSTAGE_STREAM stream = CONTAINING_RECORD(link, STAGE_STREAM, Link);
            if (stream->AllocationReceiptPending) {
                StageQueueStream(stream, NULL);
                continue;
            }
            StageQueueStream(stream, NULL);
        }
        discardPending = TRUE;
        status = STATUS_DEVICE_BUSY;
        goto Veto;
    }
#endif
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (NT_SUCCESS(status) && StageWorkerHasPendingWork()) {
        discardPending = TRUE;
        status = STATUS_DEVICE_BUSY;
        KeSetEvent(&StageWorkEvent, IO_NO_INCREMENT, FALSE);
        goto Veto;
    }
    if (NT_SUCCESS(status)) {
        /* This is the final local-state recheck after Connect/Message body
         * admission drained. Keep any already-running worker pass serialized
         * by NamespaceResource, but prevent a new pass from starting while
         * the exact service epoch drain and fence commit run. A failed commit
         * re-enables cleanup/replay work below; a successful one leaves it
         * stopped until Filter.c joins it after channel drain. */
        StageUnloadPrepareWork = FALSE;
    }
#endif
    if (!NT_SUCCESS(status) || InterlockedCompareExchange(&StageFileObjects, 0, 0) != 0) {
        SafeUploadStageRecordUnloadVeto(renamePending ? SAFEUPLOAD_UNLOAD_VETO_STAGE_RENAME :
            discardPending ? SAFEUPLOAD_UNLOAD_VETO_STAGE_DISCARD :
            !NT_SUCCESS(status) ? SAFEUPLOAD_UNLOAD_VETO_STAGE_DRAIN :
            objectPending ? SAFEUPLOAD_UNLOAD_VETO_STAGE_OBJECTS : SAFEUPLOAD_UNLOAD_VETO_STAGE_DRAIN,
            !NT_SUCCESS(status) ? status : STATUS_DEVICE_BUSY);
        goto Veto;
    }
    StageRelease(&StageNamespaceResource);
#if SAFEUPLOAD_STAGING_PROTOTYPE
    /* The service drain is irreversible. Keep StageStopping latched before
     * the first send and replay this exact RequestId/nonce after any lost
     * reply or service reconnect. */
    if (!StageEpochDrainRequestValid) {
        RtlZeroMemory(&drainGuid, sizeof(drainGuid));
        status = ExUuidCreate(&drainGuid);
        if (!NT_SUCCESS(status) || RtlEqualMemory(&drainGuid, &emptyDrainGuid, sizeof(GUID))) {
            SafeUploadStageRecordUnloadVeto(SAFEUPLOAD_UNLOAD_VETO_STAGE_DRAIN,
                NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status);
            InterlockedExchange(&StageUnloadQuarantined, 1);
            StageAcquire(&StageNamespaceResource);
            StageUnloadPrepareWork = TRUE;
            StageRelease(&StageNamespaceResource);
            SafeUploadOpenStageCallbackUnloadAdmission();
            KeSetEvent(&StageWorkEvent, IO_NO_INCREMENT, FALSE);
            return STATUS_FLT_DO_NOT_DETACH;
        }
        RtlCopyMemory(&StageEpochDrainNonce, &drainGuid, sizeof(StageEpochDrainNonce));
        if (StageEpochDrainNonce == 0) StageEpochDrainNonce = 1;
        RtlZeroMemory(&StageEpochDrainRequest, sizeof(StageEpochDrainRequest));
        StageEpochDrainRequestValid = TRUE;
    }
    status = SafeUploadStageEpochDrainV20(&StageDriverInstanceId, StageEpochDrainNonce,
        &StageEpochDrainRequest, &drainResult);
    if (!NT_SUCCESS(status) || drainResult != SAFEUPLOAD_STAGE_RESULT_EPOCH_DRAINED) {
        SafeUploadStageRecordUnloadVeto(SAFEUPLOAD_UNLOAD_VETO_STAGE_DRAIN,
            NT_SUCCESS(status) ? STATUS_DEVICE_BUSY : status);
        InterlockedExchange(&StageUnloadQuarantined, 1);
        StageAcquire(&StageNamespaceResource);
        StageUnloadPrepareWork = TRUE;
        StageRelease(&StageNamespaceResource);
        SafeUploadOpenStageCallbackUnloadAdmission();
        KeSetEvent(&StageWorkEvent, IO_NO_INCREMENT, FALSE);
        return STATUS_FLT_DO_NOT_DETACH;
    }
    /* StageSendV19Exchange accepts the reply only after rechecking the exact
     * cookie/generation. A disconnect before that check fails this attempt
     * and returns through the retry path. A later disconnect can revoke the
     * acknowledged channel and record reconciliation state, but cannot admit
     * a replacement Connect or Message body: StageStopping, the attach gate,
     * and StageUnloadPrepareWork remain closed. No worker pass starts after
     * the final local-state scan; Filter.c joins any already-collected local
     * batch after channel drain before releasing its instance references. */
    InterlockedExchange(&StageUnloadQuarantined, 1);
    /* No destructive cleanup remains outstanding. Fence commit is the final
     * gate; a failure after quarantine remains latched for a later retry. */
    /* The authenticated service retained its existing private bookkeeping
     * CREATE path during the epoch exchange. Recheck its completed local
     * ownership too; a drained journal epoch is not an SOP lifetime receipt. */
    if (!SafeUploadPolicyPublicationQuiescent() || !SafeUploadStageWritersUnloadReady()) {
        SafeUploadStageRecordUnloadVeto(SAFEUPLOAD_UNLOAD_VETO_STAGE_OBJECTS, STATUS_DEVICE_BUSY);
        StageAcquire(&StageNamespaceResource);
        StageUnloadPrepareWork = TRUE;
        StageRelease(&StageNamespaceResource);
        SafeUploadOpenStageCallbackUnloadAdmission();
        KeSetEvent(&StageWorkEvent, IO_NO_INCREMENT, FALSE);
        return STATUS_FLT_DO_NOT_DETACH;
    }
    if (!SafeUploadStageFenceTryCommitUnload()) {
        SafeUploadStageRecordUnloadVeto(SAFEUPLOAD_UNLOAD_VETO_FENCE_COMMIT, STATUS_DEVICE_BUSY);
        StageAcquire(&StageNamespaceResource);
        StageUnloadPrepareWork = TRUE;
        StageRelease(&StageNamespaceResource);
        SafeUploadOpenStageCallbackUnloadAdmission();
        KeSetEvent(&StageWorkEvent, IO_NO_INCREMENT, FALSE);
        return STATUS_FLT_DO_NOT_DETACH;
    }
#endif
    /* Successful preparation commits stage admission, the exact service
     * epoch drain, and the fence. The worker and its instance references
     * stay resident until communication callbacks/channel uses are drained;
     * Filter.c stops the workers and calls the release helper before
     * FltUnregisterFilter. */
    return STATUS_SUCCESS;

Veto:
    SafeUploadStageRecordUnloadVeto(renamePending ? SAFEUPLOAD_UNLOAD_VETO_STAGE_RENAME :
        discardPending ? SAFEUPLOAD_UNLOAD_VETO_STAGE_DISCARD :
        objectPending ? SAFEUPLOAD_UNLOAD_VETO_STAGE_OBJECTS : SAFEUPLOAD_UNLOAD_VETO_STAGE_DRAIN,
        !NT_SUCCESS(status) ? status : STATUS_DEVICE_BUSY);
#if !SAFEUPLOAD_STAGING_PROTOTYPE
    if (!quarantined) StageStopping = FALSE;
#endif
    StageRelease(&StageNamespaceResource);
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (!Mandatory && !quarantined) {
        StageRollbackUnloadPreparation();
        SafeUploadOpenStageCallbackUnloadAdmission();
    } else {
        StageAcquire(&StageNamespaceResource);
        StageUnloadPrepareWork = TRUE;
        StageRelease(&StageNamespaceResource);
        SafeUploadOpenStageCallbackUnloadAdmission();
        KeSetEvent(&StageWorkEvent, IO_NO_INCREMENT, FALSE); /* keep cleanup/retry progress eligible */
    }
#else
    KeSetEvent(&StageWorkEvent, IO_NO_INCREMENT, FALSE);
#endif
    return STATUS_FLT_DO_NOT_DETACH;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadStageReleaseInstanceReferences(VOID)
{
    PLIST_ENTRY link;

    PAGED_CODE();
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    /* Filter.c first drains communication/channel work and joins both stage
     * workers, including any work already collected into a local batch.
     * Voluntary PrepareUnload proves no upper objects/RPCs; mandatory teardown
     * instead proves actual local lifetimes without requiring durable ACKs.
     * Drop instance references before FltUnregisterFilter so teardown cannot
     * wait on references this callback would otherwise release afterward. */
    NT_ASSERT(!SafeUploadStageMandatoryTeardownActive() || StageMandatoryLocalDrained);
    for (link = StageStreams.Flink; link != &StageStreams; link = link->Flink) {
        PSTAGE_STREAM stream = CONTAINING_RECORD(link, STAGE_STREAM, Link);
        ExWaitForRundownProtectionRelease(&stream->PagingRundown);
        StageCloseBacking(stream);
        if (stream->BackingInstance != NULL) FltObjectDereference(stream->BackingInstance);
        stream->BackingInstance = NULL;
        if (stream->OriginalInstance != NULL) FltObjectDereference(stream->OriginalInstance);
        stream->OriginalInstance = NULL;
    }
}

VOID SafeUploadStageFree(VOID)
{
    PEPROCESS exited[STAGE_EXIT_RING];
    ULONG exitCount;
    KIRQL irql;
    if (!StageInitialized) return;
    NT_ASSERT(!SafeUploadStageMandatoryTeardownActive() || StageMandatoryLocalDrained);
    /* A late process-exit notification only returns: it checks the flag again under this lock before using the ring. */
    StageStreamAcquireSpinLock(&StageListLock, &irql);
    StageInitialized = FALSE;
    exitCount = StageExitCount;
    StageExitCount = 0;
    RtlCopyMemory(exited, StageExitRing, exitCount * sizeof(PEPROCESS));
    StageStreamReleaseSpinLock(&StageListLock, irql);
    while (exitCount != 0) ObDereferenceObject(exited[--exitCount]);
#if SAFEUPLOAD_STAGING_PROTOTYPE
    StageAdmissionTraceShutdown();
    SafeUploadBoundPublicationUninitialize();
    SafeUploadStageNativeUninitialize();
    SafeUploadStageFenceFree();
#endif
    while (!IsListEmpty(&StageStreams)) {
        PSTAGE_STREAM stream = CONTAINING_RECORD(RemoveHeadList(&StageStreams), STAGE_STREAM, Link);
        FsRtlTeardownPerStreamContexts(&stream->Header);
        StageFreeStream(stream);
    }
    while (!IsListEmpty(&StageViews)) StageFreeView(CONTAINING_RECORD(RemoveHeadList(&StageViews), STAGE_VIEW, Link));
    while (!IsListEmpty(&StageTombstones))
        StageFreeTombstone(CONTAINING_RECORD(StageTombstones.Flink, STAGE_TOMBSTONE, Link));
    InitializeListHead(&StageWorkQueue); /* the queue links lived in the streams freed above */
#if SAFEUPLOAD_STAGING_PROTOTYPE
    SafeUploadStageWritersUninitialize();
#endif
    ExDeleteResourceLite(&StageNamespaceResource);
}

static SAFEUPLOAD_VOLUME_KIND StageVolumeKind(PFLT_INSTANCE Instance)
{
    PSAFEUPLOAD_INSTANCE_CONTEXT context = NULL;
    SAFEUPLOAD_VOLUME_KIND kind = SafeUploadVolumeUnknown;
    if (NT_SUCCESS(FltGetInstanceContext(Instance, (PFLT_CONTEXT *)&context))) {
        kind = context->VolumeKind;
        FltReleaseContext(context);
    }
    return kind;
}

#if SAFEUPLOAD_STAGING_PROTOTYPE
typedef struct _STAGE_NAMESPACE_BINDINGS {
    FILE_ID_INFORMATION Source, Parent, Target;
    BOOLEAN TargetExists;
} STAGE_NAMESPACE_BINDINGS, *PSTAGE_NAMESPACE_BINDINGS;

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageNamespaceCaptureBindings(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _In_ PFLT_FILE_NAME_INFORMATION Source,
    _In_opt_ PFLT_FILE_NAME_INFORMATION Target, _Out_ PSTAGE_NAMESPACE_BINDINGS Bindings);
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageNamespaceRevalidateBindings(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _In_ PFLT_FILE_NAME_INFORMATION Source,
    _In_opt_ PFLT_FILE_NAME_INFORMATION Target, _In_ const STAGE_NAMESPACE_BINDINGS *Bindings);
#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, StageNamespaceCaptureBindings)
#pragma alloc_text(PAGE, StageNamespaceRevalidateBindings)
#endif

/* Current-provider queries only, outside every resource. The common mutation
 * owner excludes file/folder moves and publication through lower completion.
 * Query by object AND by name: a normalized cached spelling is not authority. */
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageNamespaceCaptureBindings(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _In_ PFLT_FILE_NAME_INFORMATION Source,
    _In_opt_ PFLT_FILE_NAME_INFORMATION Target, _Out_ PSTAGE_NAMESPACE_BINDINGS Bindings)
{
    PFLT_FILE_NAME_INFORMATION current = NULL, destination = NULL;
    FILE_ID_INFORMATION objectIdentity;
    ULONG returned = 0;
    BOOLEAN directory = FALSE;
    UNICODE_STRING parent;
    USHORT chars;
    NTSTATUS status;
    PAGED_CODE();
    RtlZeroMemory(Bindings, sizeof(*Bindings));
    if (Data->Iopb->MajorFunction != IRP_MJ_CREATE) {
        status = FltIsDirectory(Objects->FileObject, Objects->Instance, &directory);
        if (!NT_SUCCESS(status)) goto Exit;
        status = FltGetFileNameInformationUnsafe(Objects->FileObject, Objects->Instance,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY |
                FLT_FILE_NAME_REQUEST_FROM_CURRENT_PROVIDER, &current);
        if (!NT_SUCCESS(status)) goto Exit;
        if (!RtlEqualUnicodeString(&current->Name, &Source->Name, TRUE)) {
            status = STATUS_SHARING_VIOLATION; goto Exit;
        }
        status = FltQueryInformationFile(Objects->Instance, Objects->FileObject, &objectIdentity,
            sizeof(objectIdentity), FileIdInformation, &returned);
        if (!NT_SUCCESS(status)) goto Exit;
        if (returned != sizeof(objectIdentity)) { status = STATUS_INVALID_BUFFER_SIZE; goto Exit; }
    }
    status = SafeUploadStageQueryIdentity(Objects->Instance, &Source->Name, directory, &Bindings->Source);
    if (!NT_SUCCESS(status)) goto Exit;
    if (Data->Iopb->MajorFunction != IRP_MJ_CREATE &&
        !RtlEqualMemory(&objectIdentity, &Bindings->Source, sizeof(objectIdentity))) {
        status = STATUS_SHARING_VIOLATION; goto Exit;
    }
    if (Target == NULL) goto Exit;
    {
        PFILE_RENAME_INFORMATION rename = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        status = FltGetDestinationFileNameInformation(Objects->Instance, Objects->FileObject,
            rename->RootDirectory, rename->FileName, rename->FileNameLength,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY |
                FLT_FILE_NAME_REQUEST_FROM_CURRENT_PROVIDER, &destination);
        if (!NT_SUCCESS(status)) goto Exit;
        if (!RtlEqualUnicodeString(&destination->Name, &Target->Name, TRUE)) {
            status = STATUS_SHARING_VIOLATION; goto Exit;
        }
    }
    parent = Target->Name;
    chars = parent.Length / sizeof(WCHAR);
    while (chars != 0 && parent.Buffer[chars - 1] != L'\\') --chars;
    if (chars == 0) { status = STATUS_OBJECT_PATH_INVALID; goto Exit; }
    parent.Length = parent.MaximumLength = (USHORT)((chars - 1) * sizeof(WCHAR));
    status = SafeUploadStageQueryIdentity(Objects->Instance, &parent, TRUE, &Bindings->Parent);
    if (!NT_SUCCESS(status)) goto Exit;
    status = SafeUploadStageQueryIdentity(Objects->Instance, &Target->Name, directory, &Bindings->Target);
    if (status == STATUS_OBJECT_NAME_NOT_FOUND) status = STATUS_SUCCESS;
    else if (NT_SUCCESS(status)) Bindings->TargetExists = TRUE;
Exit:
    if (destination != NULL) FltReleaseFileNameInformation(destination);
    if (current != NULL) FltReleaseFileNameInformation(current);
    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageNamespaceRevalidateBindings(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _In_ PFLT_FILE_NAME_INFORMATION Source,
    _In_opt_ PFLT_FILE_NAME_INFORMATION Target, _In_ const STAGE_NAMESPACE_BINDINGS *Bindings)
{
    STAGE_NAMESPACE_BINDINGS current;
    NTSTATUS status;
    PAGED_CODE();
    status = StageNamespaceCaptureBindings(Data, Objects, Source, Target, &current);
    if (!NT_SUCCESS(status)) return status;
    if (!RtlEqualMemory(&current.Source, &Bindings->Source, sizeof(current.Source)) ||
        (Target != NULL && (!RtlEqualMemory(&current.Parent, &Bindings->Parent, sizeof(current.Parent)) ||
            current.TargetExists != Bindings->TargetExists ||
            (current.TargetExists && !RtlEqualMemory(&current.Target, &Bindings->Target, sizeof(current.Target))))))
        return STATUS_SHARING_VIOLATION;
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageNamespaceBeginMutation(_Inout_ PSTAGE_ADMISSION_TOKEN_SLOT Slot);
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN StageDirectoryContains(_In_ PCUNICODE_STRING Directory, _In_ PCUNICODE_STRING Name);
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN StageDirectoryStreamPending(_In_ PSTAGE_STREAM Stream, _In_ PCUNICODE_STRING Directory);
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN StageDirectoryPendingLocked(_In_ PCUNICODE_STRING Directory);
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageDirectoryBeginMutation(_In_ PCUNICODE_STRING Source,
    _In_opt_ PCUNICODE_STRING Destination, _Inout_ PSTAGE_ADMISSION_TOKEN_SLOT Slot);
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN StageDirectoryPlainPath(_In_ PCUNICODE_STRING Opened);
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN StageDirectoryPlainName(_In_ PFLT_FILE_NAME_INFORMATION Name, _In_ PFILE_OBJECT Object);
_IRQL_requires_(PASSIVE_LEVEL)
static FLT_PREOP_CALLBACK_STATUS StageAdmitDirectoryMutation(
    _Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS Objects,
    _In_ BOOLEAN CanHoldCollision, _Out_ PHANDLE CollisionHold);
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN StageExistingDirectory(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _In_ PFLT_FILE_NAME_INFORMATION Name);
_IRQL_requires_(PASSIVE_LEVEL)
static FLT_PREOP_CALLBACK_STATUS StageNativeDirectoryInformation(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _Inout_ PSTAGE_ADMISSION_TOKEN_SLOT Slot, _Out_ PBOOLEAN Handled);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, StageNamespaceBeginMutation)
#pragma alloc_text(PAGE, StageDirectoryContains)
#pragma alloc_text(PAGE, StageDirectoryStreamPending)
#pragma alloc_text(PAGE, StageDirectoryPendingLocked)
#pragma alloc_text(PAGE, StageDirectoryBeginMutation)
#pragma alloc_text(PAGE, StageDirectoryPlainPath)
#pragma alloc_text(PAGE, StageDirectoryPlainName)
#pragma alloc_text(PAGE, StageAdmitDirectoryMutation)
#pragma alloc_text(PAGE, StageExistingDirectory)
#pragma alloc_text(PAGE, StageNativeDirectoryInformation)
#endif

/* Both file and folder mutations use this epoch-owned exclusion. A lookup
 * which crossed even a completed mutation must be retried from dispatch. */
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageNamespaceBeginMutation(_Inout_ PSTAGE_ADMISSION_TOKEN_SLOT Slot)
{
    NTSTATUS status = STATUS_SHARING_VIOLATION;
    PAGED_CODE();
    if (Slot->Token == NULL) return STATUS_DEVICE_NOT_READY;
    StageAcquire(&StageNamespaceResource);
    if (!StageStopping && !Slot->DirectoryMutation &&
        Slot->DirectorySequence == InterlockedCompareExchange64(&StageDirectorySequence, 0, 0) &&
        InterlockedCompareExchange(&StageDirectoryMutationActive, 1, 0) == 0) {
        Slot->DirectorySequence = InterlockedIncrement64(&StageDirectorySequence);
        Slot->DirectoryMutation = TRUE;
        status = STATUS_SUCCESS;
    }
    StageRelease(&StageNamespaceResource);
    return status;
}

/* A bounded walk of the existing private namespace, under NamespaceResource.
 * Include superseded/sealed versions until retirement: a seal is not a public
 * mutation receipt, and detached versions can still own cleanup/recovery. */
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN StageDirectoryContains(_In_ PCUNICODE_STRING Directory, _In_ PCUNICODE_STRING Name)
{
    USHORT chars = Directory->Length / sizeof(WCHAR);
    PAGED_CODE();
    return chars != 0 && RtlPrefixUnicodeString(Directory, Name, TRUE) &&
        (Directory->Length == Name->Length || Directory->Buffer[chars - 1] == L'\\' || Name->Buffer[chars] == L'\\');
}

_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN StageDirectoryStreamPending(_In_ PSTAGE_STREAM Stream, _In_ PCUNICODE_STRING Directory)
{
    UNICODE_STRING target;
    PAGED_CODE();
    if (StageDirectoryContains(Directory, &Stream->Name) ||
        (Stream->View != NULL && StageDirectoryContains(Directory, &Stream->View->Name))) return TRUE;
    if (Stream->RenameExchange == NULL) return FALSE;
    target.Buffer = Stream->RenameExchange->Request.Path;
    target.Length = target.MaximumLength = (USHORT)Stream->RenameExchange->Request.PathLength;
    return StageDirectoryContains(Directory, &target);
}

_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN StageDirectoryPendingLocked(_In_ PCUNICODE_STRING Directory)
{
    PLIST_ENTRY link;
    PAGED_CODE();
    for (link = StageStreams.Flink; link != &StageStreams; link = link->Flink)
        if (StageDirectoryStreamPending(CONTAINING_RECORD(link, STAGE_STREAM, Link), Directory)) return TRUE;
    for (link = StageAllocationReservations.Flink; link != &StageAllocationReservations; link = link->Flink)
        if (StageDirectoryStreamPending(CONTAINING_RECORD(link, STAGE_STREAM, ReservationLink), Directory)) return TRUE;
    return FALSE;
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageDirectoryBeginMutation(_In_ PCUNICODE_STRING Source,
    _In_opt_ PCUNICODE_STRING Destination, _Inout_ PSTAGE_ADMISSION_TOKEN_SLOT Slot)
{
    NTSTATUS status = STATUS_SHARING_VIOLATION;
    PAGED_CODE();
    if (Slot->Token == NULL) return STATUS_DEVICE_NOT_READY;
    StageAcquire(&StageNamespaceResource);
    if (!StageStopping &&
        (Slot->DirectoryMutation || InterlockedCompareExchange(&StageDirectoryMutationActive, 0, 0) == 0) &&
        Slot->DirectorySequence == InterlockedCompareExchange64(&StageDirectorySequence, 0, 0) &&
        !StageDirectoryPendingLocked(Source) &&
        (Destination == NULL || !StageDirectoryPendingLocked(Destination))) {
        if (!Slot->DirectoryMutation) {
            InterlockedExchange(&StageDirectoryMutationActive, 1);
            Slot->DirectorySequence = InterlockedIncrement64(&StageDirectorySequence);
            Slot->DirectoryMutation = TRUE;
        }
        status = STATUS_SUCCESS;
    }
    StageRelease(&StageNamespaceResource);
    return status;
}

/* Resident: ordinary and draining postoperation can run at DISPATCH_LEVEL.
 * No resource, name query, wait, allocation or stored FILE_OBJECT reference. */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID StageDirectoryEndMutation(_In_ BOOLEAN CoverageLost)
{
    InterlockedIncrement64(&StageDirectorySequence);
    /* An unknown lower outcome must not reopen name-based admission. Keep
     * this fence latched until reboot, like existing writer coverage loss. */
    if (!CoverageLost) InterlockedExchange(&StageDirectoryMutationActive, 0);
}

/* Directory selectors can name NTFS index/data attributes, even with the
 * directory type flag on Windows 10. Reject them before native forwarding.
 * The only colons permitted in an opened spelling are drive designators. */
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN StageDirectoryPlainPath(_In_ PCUNICODE_STRING Opened)
{
    USHORT i, chars = Opened->Length / sizeof(WCHAR);
    PAGED_CODE();
    if ((Opened->Length & 1) || (Opened->Length != 0 && Opened->Buffer == NULL)) return FALSE;
    for (i = 0; i < chars; ++i) {
        if (Opened->Buffer[i] != L':') continue;
        if (i + 1 < chars && Opened->Buffer[i + 1] == L'\\' &&
            (i == 1 || (i == 5 && Opened->Buffer[0] == L'\\' &&
            Opened->Buffer[1] == L'?' && Opened->Buffer[2] == L'?' && Opened->Buffer[3] == L'\\')) &&
            ((Opened->Buffer[i - 1] >= L'A' && Opened->Buffer[i - 1] <= L'Z') ||
             (Opened->Buffer[i - 1] >= L'a' && Opened->Buffer[i - 1] <= L'z'))) continue;
        return FALSE;
    }
    return TRUE;
}

_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN StageDirectoryPlainName(_In_ PFLT_FILE_NAME_INFORMATION Name, _In_ PFILE_OBJECT Object)
{
    PAGED_CODE();
    return Name->Stream.Length == 0 && StageDirectoryPlainPath(&Object->FileName);
}

static BOOLEAN StageDirectoryCreateCanMutate(_In_ PFLT_CALLBACK_DATA Data)
{
    PIO_SECURITY_CONTEXT security = Data->Iopb->Parameters.Create.SecurityContext;
    ULONG disposition = Data->Iopb->Parameters.Create.Options >> 24;
    ULONG options = Data->Iopb->Parameters.Create.Options & 0x00ffffff;
    if (Data->Iopb->Parameters.Create.EaLength != 0 || Data->Iopb->Parameters.Create.EaBuffer != NULL) return TRUE;
    if ((options & FILE_DELETE_ON_CLOSE) != 0 || disposition == FILE_CREATE ||
        disposition == FILE_OPEN_IF || disposition == FILE_SUPERSEDE ||
        disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF) return TRUE;
    if (security == NULL) return TRUE; /* A malformed/unresolvable create still needs an epoch. */
    /* T10: WRITE_DAC and WRITE_OWNER are not writer access. A permission or owner change adds no content; such an open reaches the
     * real file or folder and Windows' own access check decides who may change it (a staged handle still never gets them). */
    return (security->DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
        FILE_WRITE_ATTRIBUTES | FILE_DELETE_CHILD | DELETE |
        GENERIC_WRITE | GENERIC_ALL | MAXIMUM_ALLOWED)) != 0;
}

/* A normalized-name lookup that fails because the path does not exist proves the request cannot touch an existing protected
 * object: the file system will answer not-found itself, or the create can only succeed one component at a time under a parent
 * that does exist (and then the lookup resolves). Refusing these made every multi-level create on a volume that hosts a scope
 * fail with ACCESS_DENIED instead of PATH_NOT_FOUND, so Windows could not build a new user's profile tree (it creates the
 * deepest folder first and its parents on PATH_NOT_FOUND). Any other lookup failure stays "the whole volume may be in scope". */
static BOOLEAN StageNameLookupProvesAbsent(_In_ NTSTATUS Status)
{
    return SafeUploadNameLookupProvesAbsent(Status);
}

_IRQL_requires_(PASSIVE_LEVEL)
static VOID StageDirectoryCollisionComplete(_In_ HANDLE Handle)
{
    PAGED_CODE();
    FltClose(Handle);
    InterlockedDecrement(&StageDirectoryCollisionHolds);
}

/* Empty directories carry no content. Forward the original CREATE; NTFS
 * decides the caller's grants, sharing, collisions and inherited security.
 * Scope-root/ancestor FILE_CREATE probes remain collision-only, with a pin
 * through lower completion. Descendant content creates still use staging. */
_IRQL_requires_(PASSIVE_LEVEL)
static FLT_PREOP_CALLBACK_STATUS StageAdmitDirectoryMutation(
    _Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS Objects,
    _In_ BOOLEAN CanHoldCollision, _Out_ PHANDLE CollisionHold)
{
    PFLT_FILE_NAME_INFORMATION name = NULL;
    SAFEUPLOAD_VOLUME_KIND kind = StageVolumeKind(Objects->Instance);
    FLT_FILESYSTEM_TYPE fs;
    ULONG disposition = Data->Iopb->Parameters.Create.Options >> 24;
    NTSTATUS status, lookup = STATUS_SUCCESS;
    BOOLEAN deny = FALSE;
    UINT32 reason = SAFEUPLOAD_DENY_REASON_PROTECTED_NAMESPACE;
    PAGED_CODE();
    *CollisionHold = NULL;
    if (!StageDirectoryCreateCanMutate(Data)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name);
    if (NT_SUCCESS(status)) status = FltParseFileNameInformation(name);
    if (!NT_SUCCESS(status)) {
        deny = !StageNameLookupProvesAbsent(status) && SafeUploadPolicyMayMatchInstanceVolume(Objects->Instance);
        reason = SAFEUPLOAD_DENY_REASON_NAME_UNRESOLVED;
        lookup = status;
    } else if (SafeUploadStageTouchesProtectedNamespace(name, kind)) {
        deny = kind != SafeUploadVolumeFixed ||
            !NT_SUCCESS(FltGetFileSystemType(Objects->Instance, &fs)) || fs != FLT_FSTYPE_NTFS ||
            !StageDirectoryPlainName(name, Objects->FileObject) ||
            Data->Iopb->Parameters.Create.EaLength != 0 || Data->Iopb->Parameters.Create.EaBuffer != NULL ||
            FlagOn(Data->Iopb->Parameters.Create.FileAttributes,
                FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_ENCRYPTED | FILE_ATTRIBUTE_OFFLINE) ||
            FlagOn(Data->Iopb->Parameters.Create.Options, FILE_OPEN_BY_FILE_ID | FILE_DELETE_ON_CLOSE) ||
            (disposition != FILE_CREATE && disposition != FILE_OPEN_IF && disposition != FILE_OPEN);
    }
    /* The exception applies only to a plain supported create at an anchor.
     * Unsupported EA/stream/attribute/options requests cannot acquire it. */
    if (!deny && name != NULL && NT_SUCCESS(status) && disposition == FILE_CREATE &&
        SafeUploadPolicyDirectoryIsScopeAnchor(&name->Name)) {
        OBJECT_ATTRIBUTES attributes;
        IO_STATUS_BLOCK io = {0};
        PFILE_OBJECT object = NULL;
        FILE_ATTRIBUTE_TAG_INFORMATION tag;
        ULONG returned = 0;
        deny = TRUE;
        if (!CanHoldCollision || FlagOn(Data->Iopb->OperationFlags, SL_CASE_SENSITIVE) ||
            Objects->Transaction != NULL || IoGetTopLevelIrp() != NULL || kind != SafeUploadVolumeFixed)
            goto Decision;
        if (InterlockedIncrement(&StageDirectoryCollisionHolds) > STAGE_DIRECTORY_COLLISION_LIMIT) {
            InterlockedDecrement(&StageDirectoryCollisionHolds);
            goto Decision;
        }
        /* FILE_CREATE of an existing directory cannot alter it. Keep a native
         * no-share-delete handle through the original CREATE's completion so a
         * delete/rename cannot turn this exception into an anchor creation.
         * Existing DELETE handles conflict; no sharing check is bypassed. */
        status = FltGetFileSystemType(Objects->Instance, &fs);
        if (status == STATUS_SUCCESS && fs == FLT_FSTYPE_NTFS) {
            InitializeObjectAttributes(&attributes, &name->Name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
            status = FltCreateFileEx2(SafeUploadData.Filter, Objects->Instance, CollisionHold, &object,
                FILE_READ_ATTRIBUTES, &attributes, &io, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
                FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_COMPLETE_IF_OPLOCKED, NULL, 0, 0, NULL);
        } else status = STATUS_NOT_SUPPORTED;
        if (status == STATUS_SUCCESS) {
            status = FltQueryInformationFile(Objects->Instance, object, &tag, sizeof(tag),
                FileAttributeTagInformation, &returned);
            if (status == STATUS_SUCCESS && returned == sizeof(tag) &&
                FlagOn(tag.FileAttributes, FILE_ATTRIBUTE_DIRECTORY) &&
                !FlagOn(tag.FileAttributes, FILE_ATTRIBUTE_REPARSE_POINT)) deny = FALSE;
        }
        if (object != NULL) ObDereferenceObject(object);
        if (deny) {
            if (*CollisionHold != NULL) { FltClose(*CollisionHold); *CollisionHold = NULL; }
            InterlockedDecrement(&StageDirectoryCollisionHolds);
        }
    }
Decision:
    if (deny) SafeUploadDenyDetail(Data, reason, lookup, name != NULL ? &name->Name : NULL);
    if (name != NULL) FltReleaseFileNameInformation(name);
    if (!deny) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

/* CreateFile's BACKUP_SEMANTICS opens often omit both type flags. Probe only
 * an existing directory, with metadata access/share-all and no create effects.
 * Force DIRECTORY on the original request after proof, so a file substituted
 * between probe and forwarding cannot receive unstaged data access. */
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN StageExistingDirectory(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _In_ PFLT_FILE_NAME_INFORMATION Name)
{
    HANDLE handle = NULL;
    PFILE_OBJECT object = NULL;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io = {0};
    FILE_STANDARD_INFORMATION standard;
    NTSTATUS status;
    BOOLEAN directory = FALSE;
    PAGED_CODE();
    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE |
        FILE_OPEN_BY_FILE_ID) || !StageDirectoryPlainName(Name, Objects->FileObject)) return FALSE;
    InitializeObjectAttributes(&attributes, &Name->Name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = FltCreateFileEx(SafeUploadData.Filter, Objects->Instance, &handle, &object,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attributes, &io, NULL, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT | FILE_COMPLETE_IF_OPLOCKED,
        NULL, 0, 0);
    if (status == STATUS_SUCCESS) {
        status = FltQueryInformationFile(Objects->Instance, object, &standard, sizeof(standard),
            FileStandardInformation, NULL);
        directory = status == STATUS_SUCCESS && standard.Directory;
    }
    if (object != NULL) ObDereferenceObject(object);
    if (handle != NULL) FltClose(handle);
    if (directory) {
        Data->Iopb->Parameters.Create.Options |= FILE_DIRECTORY_FILE;
        FltSetCallbackDataDirty(Data);
    }
    return directory;
}

/* Only ordinary directory disposition and basic metadata use this native
 * route. Content, EA, reparse, index and file mutation gates are unchanged. */
_IRQL_requires_(PASSIVE_LEVEL)
static FLT_PREOP_CALLBACK_STATUS StageNativeDirectoryInformation(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _Inout_ PSTAGE_ADMISSION_TOKEN_SLOT Slot, _Out_ PBOOLEAN Handled)
{
    PFLT_FILE_NAME_INFORMATION name = NULL;
    FILE_INFORMATION_CLASS cls = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    SAFEUPLOAD_VOLUME_KIND kind = StageVolumeKind(Objects->Instance);
    FLT_FILESYSTEM_TYPE fs;
    BOOLEAN directory = FALSE;
    NTSTATUS status = STATUS_ACCESS_DENIED;
    STAGE_NAMESPACE_BINDINGS bindings;
    PAGED_CODE();
    *Handled = FALSE;
    if (cls != FileDispositionInformation && cls != FileDispositionInformationEx && cls != FileBasicInformation)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!SafeUploadPolicyMayMatchInstanceVolume(Objects->Instance)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || IoGetTopLevelIrp() != NULL ||
        !NT_SUCCESS(FltIsDirectory(Objects->FileObject, Objects->Instance, &directory)) || !directory)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    *Handled = TRUE;
    if (!NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY |
            FLT_FILE_NAME_REQUEST_FROM_CURRENT_PROVIDER, &name)) ||
        !NT_SUCCESS(FltParseFileNameInformation(name))) goto Exit;
    if (!SafeUploadStageTouchesProtectedNamespace(name, kind)) {
        *Handled = FALSE;
        status = STATUS_SUCCESS;
        goto Exit;
    }
    if (kind != SafeUploadVolumeFixed ||
        !NT_SUCCESS(FltGetFileSystemType(Objects->Instance, &fs)) || fs != FLT_FSTYPE_NTFS) goto Exit;
    if (!StageDirectoryPlainName(name, Objects->FileObject)) goto Exit;
    if (cls == FileBasicInformation) {
        status = STATUS_SUCCESS;
    } else if (Data->Iopb->Parameters.SetFileInformation.InfoBuffer == NULL ||
        Data->Iopb->Parameters.SetFileInformation.Length <
            (cls == FileDispositionInformation ? sizeof(FILE_DISPOSITION_INFORMATION) : sizeof(ULONG))) {
        status = STATUS_INVALID_PARAMETER;
    } else if ((cls == FileDispositionInformation &&
        !((PFILE_DISPOSITION_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer)->DeleteFile) ||
        (cls == FileDispositionInformationEx &&
         !FlagOn(*(PULONG)Data->Iopb->Parameters.SetFileInformation.InfoBuffer, FILE_DISPOSITION_DELETE))) {
        status = STATUS_SUCCESS; /* Clearing disposition adds no pending delete. */
    } else if (SafeUploadPolicyDirectoryIsScopeAnchor(&name->Name)) {
        status = STATUS_ACCESS_DENIED;
    } else if (cls == FileDispositionInformationEx &&
        (Data->Iopb->Parameters.SetFileInformation.InfoBuffer == NULL ||
         Data->Iopb->Parameters.SetFileInformation.Length < sizeof(ULONG) ||
         FlagOn(*(PULONG)Data->Iopb->Parameters.SetFileInformation.InfoBuffer, FILE_DISPOSITION_ON_CLOSE))) {
        status = STATUS_NOT_SUPPORTED;
    } else if (SafeUploadPolicyMayMatchInstanceVolume(Objects->Instance)) {
        status = StageDirectoryBeginMutation(&name->Name, NULL, Slot);
        if (NT_SUCCESS(status)) status = StageNamespaceCaptureBindings(Data, Objects, name, NULL, &bindings);
    } else status = STATUS_SUCCESS;
Exit:
    if (name != NULL) FltReleaseFileNameInformation(name);
    if (status == STATUS_SUCCESS) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    Data->IoStatus.Status = status;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}


#endif

#if SAFEUPLOAD_STAGING_PROTOTYPE
_IRQL_requires_max_(APC_LEVEL)
static BOOLEAN StageMvpNamespaceOpen(_In_ PFLT_CALLBACK_DATA Data);
#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, StageMvpNamespaceOpen)
#endif
_IRQL_requires_max_(APC_LEVEL)
_Use_decl_annotations_
static BOOLEAN StageMvpNamespaceOpen(PFLT_CALLBACK_DATA Data)
{
    PIO_SECURITY_CONTEXT security = Data->Iopb->Parameters.Create.SecurityContext;
    ULONG disposition = Data->Iopb->Parameters.Create.Options >> 24;
    PAGED_CODE();
    return security != NULL && (disposition == FILE_OPEN || disposition == FILE_OPEN_IF) &&
        !FlagOn(security->DesiredAccess, FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
            GENERIC_WRITE | GENERIC_ALL | MAXIMUM_ALLOWED);
}
#endif

static FLT_PREOP_CALLBACK_STATUS StageAdmit(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, PSAFEUPLOAD_CREATE_ALIAS_PROOF AliasProof,
    PSTAGE_ADMISSION_TOKEN_SLOT AdmissionSlot, PHANDLE DirectoryCollisionHold)
{
    PFLT_FILE_NAME_INFORMATION name = NULL;
    PFLT_FILE_NAME_INFORMATION privateName = NULL;
    PSTAGE_VIEW expectedView = NULL;   /* valid only while NamespaceResource is held: compare generations afterwards */
#if SAFEUPLOAD_STAGING_PROTOTYPE
    PSTAGE_STREAM deleteReservation = NULL;
#endif
    LONG64 expectedGeneration = 0;
    ULONG readmits = 0;
    PIO_SECURITY_CONTEXT security = Data->Iopb->Parameters.Create.SecurityContext;
    ULONG disposition = Data->Iopb->Parameters.Create.Options >> 24;
    ULONG pid = FltGetRequestorProcessId(Data);
    BOOLEAN service = SafeUploadIsAuthenticatedClient() && pid == SafeUploadData.InspectorProcessId;
    BOOLEAN writer, writerAccess, handled = TRUE, privateNamespace = FALSE;
    UNICODE_STRING relative;
    UNICODE_STRING privatePrefix = RTL_CONSTANT_STRING(L"\\ProgramData\\SafeUpload\\staging\\");
    ULONGLONG zeroId = 0;
    SAFEUPLOAD_VOLUME_KIND kind;
    NTSTATUS status = STATUS_SUCCESS;
    UINT32 denyReason = SAFEUPLOAD_DENY_REASON_NONE;   /* recorded in the deny ring when the create is refused */
    NTSTATUS denyAux = STATUS_SUCCESS;
    *DirectoryCollisionHold = NULL;
    UNREFERENCED_PARAMETER(AliasProof);   /* only the prototype's writer registry consumes it */
    /* StageAdmit owns the single by-ID classification in the prototype; do
     * not repeat the TxF helper's bounded open before its common by-ID path. */
    if (!FlagOn(Data->Iopb->Parameters.Create.Options, FILE_OPEN_BY_FILE_ID) &&
        SafeUploadStageTxfCreateMustRefuse(Data, Objects)) {
        SafeUploadStageTxfRecordRefused();
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    if (security == NULL || Objects->FileObject == NULL ||
        FlagOn(Data->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY) ||
        (Objects->FileObject->FileName.Length == 0 && Objects->FileObject->RelatedFileObject == NULL))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    /* T10: WRITE_DAC and WRITE_OWNER are not writer access. A permission or owner change adds no content; such an open reaches the
     * real file or folder and Windows' own access check decides who may change it (a staged handle still never gets them). */
    writerAccess = BooleanFlagOn(security->DesiredAccess, FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
        FILE_WRITE_ATTRIBUTES | FILE_DELETE_CHILD | DELETE | GENERIC_WRITE |
        GENERIC_ALL | MAXIMUM_ALLOWED) ||
        FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE);
    writer = writerAccess ||
        disposition == FILE_CREATE || disposition == FILE_OPEN_IF || disposition == FILE_SUPERSEDE ||
        disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF;
    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {
#if SAFEUPLOAD_STAGING_PROTOTYPE
        if (KeGetCurrentIrql() != PASSIVE_LEVEL || IoGetTopLevelIrp() != NULL) {
            if (!SafeUploadPolicyMayMatchInstanceVolume(Objects->Instance)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
            denyReason = SAFEUPLOAD_DENY_REASON_TOP_LEVEL_IRP;
            status = STATUS_ACCESS_DENIED; goto Complete;
        }
        FLT_PREOP_CALLBACK_STATUS directoryResult = StageAdmitDirectoryMutation(Data, Objects,
            AdmissionSlot != NULL && AdmissionSlot->Token != NULL, DirectoryCollisionHold);
        if (directoryResult != FLT_PREOP_SUCCESS_NO_CALLBACK) return directoryResult;
        if (*DirectoryCollisionHold != NULL) return FLT_PREOP_SUCCESS_WITH_CALLBACK;
#endif
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    kind = StageVolumeKind(Objects->Instance);
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (kind == SafeUploadVolumeFixed && disposition == FILE_OPEN && StageMvpNamespaceOpen(Data) &&
        !FlagOn(Data->Iopb->Parameters.Create.Options, FILE_OPEN_BY_FILE_ID) &&
        !SafeUploadStageProtocolNativeForwardAllowed(0, 0)) writer = FALSE;
#endif
    if (!service && FlagOn(Data->Iopb->Parameters.Create.Options, FILE_OPEN_BY_FILE_ID)) {
        UNICODE_STRING id = Objects->FileObject->FileName;
        StageAcquire(&StageNamespaceResource);
        if (!StageStopping) expectedView = StageFindId(FltGetRequestorProcess(Data), Objects->Instance, &id);
        if (expectedView != NULL) {
            expectedGeneration = expectedView->Generation;
            privateName = ExAllocatePool2(POOL_FLAG_NON_PAGED,
                sizeof(*privateName) + expectedView->Name.Length, STAGE_TAG);
            if (privateName != NULL) {
                privateName->Name.Buffer = (PWCH)(privateName + 1);
                privateName->Name.Length = privateName->Name.MaximumLength = expectedView->Name.Length;
                RtlCopyMemory(privateName->Name.Buffer, expectedView->Name.Buffer, expectedView->Name.Length);
                privateName->Volume = privateName->Name;
                privateName->Volume.Length = privateName->Volume.MaximumLength = expectedView->Current->VolumeLength;
            }
        }
        StageRelease(&StageNamespaceResource);
        if (expectedView != NULL) {
            if (privateName == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Complete; }
            if (disposition != FILE_OPEN) { status = STATUS_INVALID_PARAMETER; goto Complete; }
#if SAFEUPLOAD_STAGING_PROTOTYPE
            if (writer) {
                status = StageAttachQueueCreate(Data, Objects, privateName, kind,
                    expectedGeneration, TRUE, TRUE, TRUE, AdmissionSlot);
                if (status == STATUS_PENDING) {
                    privateName = NULL; /* transaction owns the private name snapshot */
                    return FLT_PREOP_PENDING;
                }
                if (!NT_SUCCESS(status)) goto Complete;
            }
#endif
            status = StageCreate(Data, Objects, privateName, kind, writer, expectedGeneration,
                TRUE, TRUE, FALSE, NULL, &handled);
            goto Complete;
        }
#if SAFEUPLOAD_STAGING_PROTOTYPE
        /* D6: volumes outside every current, pending, or boot scope pass all
         * by-ID opens, including IDs whose high half this classifier cannot resolve. */
        if (!SafeUploadPolicyMayMatchInstanceVolume(Objects->Instance)) {
            handled = FALSE;
            goto Complete;
        }
        if (writer) {
            BOOLEAN inScope = TRUE;
            if (id.Length == sizeof(FILE_ID_128) &&
                RtlCompareMemory((PUCHAR)id.Buffer + sizeof(ULONGLONG),
                    &zeroId, sizeof(zeroId)) != sizeof(zeroId)) {
                /* Documented exception: on a possibly scoped volume, an
                 * unresolvable high-half mutating ID is refused. */
                denyReason = SAFEUPLOAD_DENY_REASON_BY_ID_HIGH_HALF;
                status = STATUS_ACCESS_DENIED; goto Complete;
            }
            /* One bounded PASSIVE attempt classifies every hard link through
             * a read-only, share-all, FILE_COMPLETE_IF_OPLOCKED ID open.
             * An undecidable target is refused only on a possibly scoped volume. */
            status = KeGetCurrentIrql() == PASSIVE_LEVEL && IoGetTopLevelIrp() == NULL ?
                SafeUploadStageWritersClassifyById(Objects->Instance, Objects->FileObject, &inScope) :
                STATUS_INVALID_DEVICE_STATE;
            if (NT_SUCCESS(status) && !inScope) {
                handled = FALSE;
                goto Complete;
            }
            if (NT_SUCCESS(status)) {
                denyReason = SAFEUPLOAD_DENY_REASON_POLICY_SCOPE;   /* a by-ID write to a scoped file: refused by design */
            } else {
                denyReason = SAFEUPLOAD_DENY_REASON_BY_ID_UNDECIDABLE;
                denyAux = status;
            }
            status = STATUS_ACCESS_DENIED;
            goto Complete;
        }
#else
        /* Keep the legacy production refusal for unknown mutating or high-half IDs. */
        if (writer || (id.Length == sizeof(FILE_ID_128) &&
            RtlCompareMemory((PUCHAR)id.Buffer + sizeof(ULONGLONG),
                &zeroId, sizeof(zeroId)) != sizeof(zeroId))) {
            status = STATUS_ACCESS_DENIED;
            goto Complete;
        }
#endif
        handled = FALSE; goto Complete;
    }
    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name);
    if (!NT_SUCCESS(status)) {
        /* The path does not exist: nothing protected can be touched, so let the file system answer. */
        if (StageNameLookupProvesAbsent(status)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
#if SAFEUPLOAD_STAGING_PROTOTYPE
        /* A name-resolution failure is relevant only for a request that can mutate.
         * Early boot image/manifest reads must pass even when C: has a boot scope. */
        if (writer && SafeUploadPolicyMayMatchInstanceVolume(Objects->Instance)) {
            denyReason = SAFEUPLOAD_DENY_REASON_NAME_UNRESOLVED;
            denyAux = status;
            status = STATUS_ACCESS_DENIED; goto Complete;
        }
#endif
        if (!writer || service || !SafeUploadPolicyMayMatchInstanceVolume(Objects->Instance)) {
            if (name != NULL) FltReleaseFileNameInformation(name);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        /* The private staging namespace has a separate resolved-name gate;
         * an unresolved out-of-scope volume does not inherit a policy refusal. */
        status = STATUS_ACCESS_DENIED; goto Complete;
    }
    status = FltParseFileNameInformation(name);
    if (!NT_SUCCESS(status)) {
        /* A parser failure is the same unresolved-name case as a query failure. */
        if (!writer || service || !SafeUploadPolicyMayMatchInstanceVolume(Objects->Instance)) {
            FltReleaseFileNameInformation(name);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        denyReason = SAFEUPLOAD_DENY_REASON_NAME_UNRESOLVED;
        denyAux = status;
        goto Complete;
    }
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (writer && KeGetCurrentIrql() == PASSIVE_LEVEL && IoGetTopLevelIrp() == NULL &&
        kind == SafeUploadVolumeFixed && SafeUploadStageTouchesProtectedNamespace(name, kind) &&
        StageExistingDirectory(Data, Objects, name)) {
        FLT_PREOP_CALLBACK_STATUS directoryResult = StageAdmitDirectoryMutation(Data, Objects,
            AdmissionSlot != NULL && AdmissionSlot->Token != NULL, DirectoryCollisionHold);
        FltReleaseFileNameInformation(name);
        if (*DirectoryCollisionHold != NULL) return FLT_PREOP_SUCCESS_WITH_CALLBACK;
        return directoryResult;
    }
    /* A volume no current, pending or boot scope can match has nothing to protect. Without this a name the classifier
     * cannot place on a volume (the redirector's own device, \;LanmanRedirector) read as "protected" and was refused. */
    if (!SafeUploadPolicyMayMatchInstanceVolume(Objects->Instance)) {
        handled = FALSE;
        goto Complete;
    }
#endif
    relative.Buffer = (PWCH)((PUCHAR)name->Name.Buffer + name->Volume.Length);
    relative.Length = name->Name.Length - name->Volume.Length;
    relative.MaximumLength = relative.Length;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (!service && disposition == FILE_OPEN && KeGetCurrentIrql() == PASSIVE_LEVEL &&
        FltGetRequestorProcess(Data) != NULL &&
        !FlagOn(security->DesiredAccess, WRITE_DAC | WRITE_OWNER | ACCESS_SYSTEM_SECURITY)) {
        status = SafeUploadStageNativeOwnerNameStatus(Objects->Instance, &name->Name, FltGetRequestorProcess(Data));
        if (!NT_SUCCESS(status)) goto Complete;
    }
#endif
Readmit:
    if (!service) {
        StageAcquire(&StageNamespaceResource);
#if SAFEUPLOAD_STAGING_PROTOTYPE
        deleteReservation = StageFindPrivateDeleteReservation(&name->Name);
        if (deleteReservation != NULL) {
            expectedView = deleteReservation->View;
            expectedGeneration = expectedView != NULL ? expectedView->Generation : 0;
            privateNamespace = TRUE;
        } else
#endif
        expectedView = StageFindView(FltGetRequestorProcess(Data), &name->Name);
#if SAFEUPLOAD_STAGING_PROTOTYPE
        if (deleteReservation == NULL) {
#endif
        expectedGeneration = expectedView != NULL ? expectedView->Generation : 0;
        privateNamespace = expectedView != NULL || StageHiddenName(FltGetRequestorProcess(Data), &name->Name);
#if SAFEUPLOAD_STAGING_PROTOTYPE
        }
#endif
        StageRelease(&StageNamespaceResource);
        expectedView = NULL;
    }
#if SAFEUPLOAD_STAGING_PROTOTYPE
    /* The gate protects a name that may be inside a scope while its entry is classified. A name outside every current and
     * pending scope is decided below by the create's own alias check (a link inside a scope is refused there), and
     * refusing it here only broke unrelated writers during the classification window (FontCache, the licensing store). */
    if (writer && !privateNamespace && SafeUploadStageProtectedName(name, kind) &&
        SafeUploadStageWritersNameActivating(Objects->Instance, &name->Name)) {
        if (KeGetCurrentIrql() == PASSIVE_LEVEL && IoGetTopLevelIrp() == NULL)
            SafeUploadStageWritersAwaitNameActivation(Objects->Instance, &name->Name);
        /* Waiting only requests observation. Re-read the current name gate;
         * success still proceeds through trust/security/private allocation. */
        if (SafeUploadStageWritersNameActivating(Objects->Instance, &name->Name)) {
            denyReason = SAFEUPLOAD_DENY_REASON_ACTIVATING_NAME;
            status = STATUS_ACCESS_DENIED; goto Complete;
        }
    }
#endif
    if (RtlPrefixUnicodeString(&privatePrefix, &relative, TRUE)) {
        if (!service) { denyReason = SAFEUPLOAD_DENY_REASON_PRIVATE_NAMESPACE; status = STATUS_ACCESS_DENIED; goto Complete; }
        handled = FALSE; goto Complete;
    }
    if (!privateNamespace && writer && SafeUploadStageProtectedName(name, kind) &&
        (!SafeUploadInstanceTrustGateSatisfied(Objects->Instance) || !SafeUploadIsAuthenticatedClient())) {
        /* Canary results describe the primitive only; trust is assigned from
         * the immutable setup flags and can never be upgraded on this mount. */
        denyReason = SAFEUPLOAD_DENY_REASON_TRUST_GATE;
        status = STATUS_ACCESS_DENIED;
        goto Complete;
    }
    if (!privateNamespace && !SafeUploadStageProtectedName(name, kind)) {
        BOOLEAN protectedAlias = FALSE;
        if (writerAccess || disposition == FILE_SUPERSEDE || disposition == FILE_OVERWRITE ||
            disposition == FILE_OVERWRITE_IF) {
            PSAFEUPLOAD_CREATE_ALIAS_PROOF proof = NULL;
            ULONGLONG scopeSequence = 0;
#if SAFEUPLOAD_STAGING_PROTOTYPE
            /* T3d: the writer registry classifies this file OUTSIDE from the check below, but only in the plain case its entry
             * describes (a non-transacted open of the default stream by name); the sequence is read before the check, so a
             * scope published during it cannot validate the result. */
            if (AliasProof != NULL && Objects->Transaction == NULL && name->Stream.Length == 0 &&
                !FlagOn(Data->Iopb->Parameters.Create.Options, FILE_OPEN_BY_FILE_ID)) {
                proof = AliasProof;
                scopeSequence = SafeUploadPolicyScopeSequenceSnapshot();
            }
#endif
            status = KeGetCurrentIrql() == PASSIVE_LEVEL && IoGetTopLevelIrp() == NULL ?
                SafeUploadStageCheckNamedAliases(Data, Objects->Instance, name, kind, &protectedAlias, proof) :
                STATUS_INVALID_DEVICE_STATE;
            if (proof != NULL && proof->Valid) proof->ScopeSequence = scopeSequence;
            if (status == STATUS_DELETE_PENDING) {
                /* The probe found the file deleted-pending: no write can reach it, whatever its other names are, and the file
                 * system refuses the open itself. Refusing here turned that answer into ACCESS_DENIED (servicing opens the
                 * old printer-driver files this way). */
                handled = FALSE; goto Complete;
            }
            if (status != STATUS_SUCCESS || protectedAlias) {
                denyReason = protectedAlias ? SAFEUPLOAD_DENY_REASON_PROTECTED_ALIAS : SAFEUPLOAD_DENY_REASON_ALIAS_CHECK_FAILED;
                denyAux = status;
                status = STATUS_ACCESS_DENIED; goto Complete;
            }
        }
        handled = FALSE; goto Complete;
    }
    if (service) {
#if SAFEUPLOAD_STAGING_PROTOTYPE
        if (writer && SafeUploadStageWritersNameActivating(Objects->Instance, &name->Name)) {
            status = STATUS_ACCESS_DENIED; goto Complete;
        }
#endif
        if (!writer || SafeUploadPublicationCreate(&name->Name, disposition, writer)) handled = FALSE;
        else status = STATUS_ACCESS_DENIED;
        goto Complete;
    }
    if (FLT_IS_IRP_OPERATION(Data) && FltIsIoCanceled(Data)) { status = STATUS_CANCELLED; goto Complete; }
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (privateNamespace && kind == SafeUploadVolumeFixed && StageMvpNamespaceOpen(Data) &&
        !SafeUploadStageProtocolNativeForwardAllowed(0, 0)) {
        PSTAGE_STREAM reopening = NULL;
        StageAcquire(&StageNamespaceResource);
        expectedView = StageFindView(FltGetRequestorProcess(Data), &name->Name);
        if (expectedView != NULL && expectedView->Generation == expectedGeneration) {
            reopening = expectedView->Current;
            InterlockedIncrement(&reopening->RpcReferences);
            StageQueueStream(reopening, &StageCounters.WakeInline);
        }
        StageRelease(&StageNamespaceResource);
        if (reopening != NULL) {
            /* An exact pin keeps the sealed/closing version through the
             * existing bounded receipt wait. No lock spans its seal/RPC. */
            StageWaitHandleReceiptSettled(reopening, TRUE);
            StageAcquire(&StageNamespaceResource);
            InterlockedDecrement(&reopening->RpcReferences);
            StageQueueStream(reopening, &StageCounters.WakeInline);
            StageRelease(&StageNamespaceResource);
        }
        expectedView = NULL;
        writer = FALSE;
    }
    /* T5: FILE_DELETE_ON_CLOSE counts as writer access (writerAccess above), so a protected name opened with it is staged: the
     * version is discarded at its last cleanup and the physical file is never touched (driver/T5-DELETES.md R3). */
#endif
    Data->IoStatus.Information = 0;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (writer) {
        status = StageAttachQueueCreate(Data, Objects, name, kind, expectedGeneration,
            privateNamespace, FALSE, FALSE, AdmissionSlot);
        if (status == STATUS_PENDING) {
            if (name != NULL) FltReleaseFileNameInformation(name);
            if (privateName != NULL) ExFreePoolWithTag(privateName, STAGE_TAG);
            return FLT_PREOP_PENDING;
        }
        if (!NT_SUCCESS(status)) goto Complete;
    }
#endif
    status = StageCreate(Data, Objects, name, kind, writer, expectedGeneration,
        FALSE, privateNamespace, FALSE, NULL, &handled);
    if (status == STAGE_STATUS_READMIT) {
        /* The owner's private namespace changed after the gates above read it (T4: a version leaves it once the service
         * disposed of it and nothing holds it). Run them again on the current state; a namespace that keeps changing under
         * this open fails it like a racing rename would. */
        if (++readmits < 8) { handled = TRUE; goto Readmit; }
        status = STATUS_SHARING_VIOLATION;
    }
Complete:
    if (handled && !NT_SUCCESS(status) && denyReason != SAFEUPLOAD_DENY_REASON_NONE)
        SafeUploadDenyDetail(Data, denyReason, denyAux, name != NULL ? &name->Name : NULL);
    if (name != NULL) FltReleaseFileNameInformation(name);
    if (privateName != NULL) ExFreePoolWithTag(privateName, STAGE_TAG);
    if (!handled) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    Data->IoStatus.Status = status;
    if (!NT_SUCCESS(status)) Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

static FLT_PREOP_CALLBACK_STATUS StagePhysicalMutationEx(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, BOOLEAN IncludeAncestors, BOOLEAN TrackedWriter, PVOID *MutatingIoContext);

/* *MutatingIoContext is the caller's mutating-I/O context (NULL for an untracked file object); a nested operation admitted by its
 * stream's registry entry gets its W count there, and the caller hands it to the post-operation as usual. */
static FLT_PREOP_CALLBACK_STATUS StagePhysicalMutationEx(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, BOOLEAN IncludeAncestors, BOOLEAN TrackedWriter, PVOID *MutatingIoContext)
{
    PFLT_FILE_NAME_INFORMATION name = NULL;
    SAFEUPLOAD_VOLUME_KIND kind = StageVolumeKind(Objects->Instance);
    BOOLEAN protectedAlias = FALSE;
    BOOLEAN unresolved = TRUE;
    BOOLEAN service = SafeUploadIsAuthenticatedClient() &&
        FltGetRequestorProcessId(Data) == SafeUploadData.InspectorProcessId;
    FLT_FILESYSTEM_TYPE fs;
    NTSTATUS status = STATUS_ACCESS_DENIED;
    UINT32 denyReason = SAFEUPLOAD_DENY_REASON_NONE;   /* recorded in the deny ring when the request is refused */
    NTSTATUS denyAux = STATUS_SUCCESS;
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    /* Querying lower metadata is forbidden in fast I/O, paging/section paths
     * or with a top-level IRP. This direct-mutation path never gates paging I/O. */
    if (FLT_IS_FASTIO_OPERATION(Data)) return FLT_PREOP_DISALLOW_FASTIO;
    /* H(F) keeps an admitted writer usable through cleanup. Its mutating IRP
     * was counted before this check and is paired by post-operation. */
    if (TrackedWriter) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || IoGetTopLevelIrp() != NULL) {
#if SAFEUPLOAD_STAGING_PROTOTYPE
        /* The name cannot be queried in this context (a write issued from inside another file-system call, for example a
         * filter above this one compressing a file). A stream whose registry entry is validated and classified outside every
         * scope is decided by that entry; everything else keeps the volume-wide answer below. */
        if (KeGetCurrentIrql() <= APC_LEVEL) {
            ULONG why;
            if (*MutatingIoContext == NULL) {
                why = SafeUploadStageWritersAdmitNestedMutation(Objects->Instance, Objects->FileObject, MutatingIoContext);
            } else {
                /* Already counted by the caller's context. */
                why = SafeUploadStageWritersSopOutsideWhy(Objects->Instance, Objects->FileObject);
            }
            if (why == SAFEUPLOAD_SOP_OUTSIDE_KNOWN) {
                status = STATUS_SUCCESS;
                goto Complete;
            }
            denyAux = (NTSTATUS)(0xE5000000UL | why);   /* the ring shows why the stream was not known outside */
        }
#endif
        denyReason = SAFEUPLOAD_DENY_REASON_TOP_LEVEL_IRP;
        goto Complete;
    }
    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name);
    if (!NT_SUCCESS(status)) {
        denyReason = SAFEUPLOAD_DENY_REASON_NAME_UNRESOLVED;
        denyAux = status;
        goto Complete;
    }
    status = FltParseFileNameInformation(name);
    if (!NT_SUCCESS(status)) {
        denyReason = SAFEUPLOAD_DENY_REASON_NAME_UNRESOLVED;
        denyAux = status;
        goto Complete;
    }
#if SAFEUPLOAD_STAGING_PROTOTYPE
    /* Same rule as the create gate: only a name that may be inside a scope waits for its entry; the policy and alias
     * checks below decide every other name. */
    if ((IncludeAncestors ? SafeUploadStageTouchesProtectedNamespace(name, kind) : SafeUploadStageProtectedName(name, kind)) &&
        SafeUploadStageWritersNameActivating(Objects->Instance, &name->Name)) {
        unresolved = FALSE;
        denyReason = SAFEUPLOAD_DENY_REASON_ACTIVATING_NAME;
        status = STATUS_ACCESS_DENIED;
        goto Complete;
    }
 #endif
    /* The writer registry records existing handles; direct mutators through
     * other handles use the current+pending policy and alias checks. */
    if (SafeUploadPolicyMatchesCurrentOrPendingDestination(kind, &name->Name, IncludeAncestors)) {
        unresolved = FALSE;
        denyReason = SAFEUPLOAD_DENY_REASON_POLICY_SCOPE;
        status = STATUS_ACCESS_DENIED;
        goto Complete;
    }
    if (!service && (IncludeAncestors ? SafeUploadStageTouchesProtectedNamespace(name, kind) :
        SafeUploadStageProtectedName(name, kind))) {
        unresolved = FALSE;
        denyReason = SAFEUPLOAD_DENY_REASON_PROTECTED_NAMESPACE;
        status = STATUS_ACCESS_DENIED;
        goto Complete;
    }
    /* Timestamps/attributes add no bytes and change no names, including through
     * an outside hard link. Keep the resolved protected-name gates above, but
     * don't require alias/traverse authority for this metadata-only operation.
     * All content, EA, size, delete and namespace mutations retain their gates. */
    if (Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION &&
        Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileBasicInformation) {
        unresolved = FALSE;
        status = STATUS_SUCCESS;
        goto Complete;
    }
    status = FltGetFileSystemType(Objects->Instance, &fs);
    if (!NT_SUCCESS(status)) {
        denyReason = SAFEUPLOAD_DENY_REASON_NAME_UNRESOLVED;
        denyAux = status;
        goto Complete;
    }
    if (fs != FLT_FSTYPE_NTFS) {
        status = STATUS_SUCCESS;
        goto Complete;
    }
    status = SafeUploadStageCheckObjectAliases(Data, Objects->Instance, Objects->FileObject,
        &name->Volume, kind, &protectedAlias);
    if (NT_SUCCESS(status)) {
        unresolved = FALSE;
        if (protectedAlias) {
            denyReason = SAFEUPLOAD_DENY_REASON_PROTECTED_ALIAS;
            status = STATUS_ACCESS_DENIED;
        }
    } else {
        denyReason = SAFEUPLOAD_DENY_REASON_ALIAS_CHECK_FAILED;
        denyAux = status;
    }
Complete:
    if (unresolved && !SafeUploadPolicyMayMatchInstanceVolume(Objects->Instance))
        status = STATUS_SUCCESS;
    if (status != STATUS_SUCCESS)
        SafeUploadDenyDetail(Data, denyReason, denyAux, name != NULL ? &name->Name : NULL);
    if (name != NULL) FltReleaseFileNameInformation(name);
    if (status == STATUS_SUCCESS) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static FLT_PREOP_CALLBACK_STATUS StageExternalRename(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _In_ BOOLEAN TrackedWriter,
    _Out_opt_ PVOID *RegistryRenameContext, _Inout_ PSTAGE_ADMISSION_TOKEN_SLOT AdmissionSlot)
{
    FILE_INFORMATION_CLASS cls = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    PFILE_RENAME_INFORMATION rename = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    PFLT_FILE_NAME_INFORMATION source = NULL, destination = NULL;
    SAFEUPLOAD_VOLUME_KIND kind = StageVolumeKind(Objects->Instance);
    BOOLEAN allow = FALSE;
    BOOLEAN quarantineRefused = FALSE;
    BOOLEAN unresolved = TRUE;
    BOOLEAN destinationProtected = FALSE;
    BOOLEAN sourceProtected = TRUE;
    BOOLEAN publication = FALSE;
    BOOLEAN linkOperation = cls == FileLinkInformation || cls == FileLinkInformationEx;
    NTSTATUS status;
    NTSTATUS directoryStatus = STATUS_SUCCESS;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    STAGE_NAMESPACE_BINDINGS bindings;
#endif
    if (RegistryRenameContext != NULL) *RegistryRenameContext = NULL;
    ULONG length = Data->Iopb->Parameters.SetFileInformation.Length;
    if (cls != FileRenameInformation && cls != FileRenameInformationEx && cls != FileLinkInformation && cls != FileLinkInformationEx)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || IoGetTopLevelIrp() != NULL) goto Complete;
    if (rename == NULL || length < (ULONG)FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName) ||
        rename->FileNameLength == 0 || (rename->FileNameLength & 1) ||
        rename->FileNameLength > length - (ULONG)FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName)) goto Complete;
    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY |
            FLT_FILE_NAME_REQUEST_FROM_CURRENT_PROVIDER, &source);
    if (!NT_SUCCESS(status)) goto Complete;
    status = FltParseFileNameInformation(source);
    if (!NT_SUCCESS(status)) goto Complete;
    status = FltGetDestinationFileNameInformation(Objects->Instance, Objects->FileObject,
        rename->RootDirectory, rename->FileName, rename->FileNameLength,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY |
            FLT_FILE_NAME_REQUEST_FROM_CURRENT_PROVIDER, &destination);
    if (!NT_SUCCESS(status)) goto Complete;
    status = FltParseFileNameInformation(destination);
    if (!NT_SUCCESS(status)) goto Complete;
    sourceProtected = SafeUploadStageTouchesProtectedNamespace(source, kind) ||
        SafeUploadPolicyMatchesCurrentOrPendingDestination(kind, &source->Name, TRUE);
    destinationProtected = SafeUploadStageTouchesProtectedNamespace(destination, kind) ||
        SafeUploadPolicyMatchesCurrentOrPendingDestination(kind, &destination->Name, TRUE);
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (kind == SafeUploadVolumeFixed && (sourceProtected || destinationProtected)) {
        /* DirectorySequence was captured BEFORE lookup at dispatch. Never
         * refresh it from these names: a move out/back must force a retry. */
        directoryStatus = StageNamespaceBeginMutation(AdmissionSlot);
        if (!NT_SUCCESS(directoryStatus)) goto Complete;
        directoryStatus = StageNamespaceCaptureBindings(Data, Objects, source, destination, &bindings);
        if (!NT_SUCCESS(directoryStatus)) goto Complete;
    }
    if (!linkOperation) {
        BOOLEAN directory = FALSE;
        FLT_FILESYSTEM_TYPE fs;
        UNICODE_STRING openedDestination;
        status = FltIsDirectory(Objects->FileObject, Objects->Instance, &directory);
        if (NT_SUCCESS(status) && directory && (sourceProtected || destinationProtected)) {
            openedDestination.Buffer = rename->FileName;
            openedDestination.Length = openedDestination.MaximumLength =
                (USHORT)min(rename->FileNameLength, MAXUSHORT);
            /* Incoming trees must never arrive by one native rename. Let the
             * caller's cross-drive fallback copy each file through staging. */
            if (!sourceProtected && destinationProtected) {
                directoryStatus = STATUS_NOT_SAME_DEVICE;
            } else if (kind != SafeUploadVolumeFixed ||
                !NT_SUCCESS(FltGetFileSystemType(Objects->Instance, &fs)) || fs != FLT_FSTYPE_NTFS ||
                !StageDirectoryPlainName(source, Objects->FileObject) || destination->Stream.Length != 0 ||
                rename->FileNameLength > MAXUSHORT || !StageDirectoryPlainPath(&openedDestination) ||
                SafeUploadPolicyDirectoryIsScopeAnchor(&source->Name) ||
                SafeUploadPolicyDirectoryIsScopeAnchor(&destination->Name)) {
                directoryStatus = STATUS_ACCESS_DENIED;
            } else directoryStatus = StageDirectoryBeginMutation(&source->Name, &destination->Name, AdmissionSlot);
            if (directoryStatus != STATUS_SUCCESS) goto Complete;
            allow = TRUE;
            unresolved = FALSE;
            goto PrepareRename;
        }
    }
#else
    UNREFERENCED_PARAMETER(AdmissionSlot);
#endif
    allow = TrackedWriter || (!sourceProtected && !destinationProtected);
    /* A pre-existing tracked handle does not authorize adding a fresh name
     * under a current or pending protected destination. Refuse before the
     * filesystem can publish the new link or rename. */
    if (destinationProtected) {
        allow = FALSE;
        unresolved = FALSE;
    }
    if (!allow) unresolved = FALSE;
    if (allow && !TrackedWriter) {
        BOOLEAN protectedAlias = FALSE;
        status = SafeUploadStageCheckObjectAliases(Data, Objects->Instance, Objects->FileObject,
            &source->Volume, kind, &protectedAlias);
        if (status == STATUS_SUCCESS) {
            unresolved = FALSE;
            allow = !protectedAlias;
        } else {
            allow = FALSE;
        }
    }
    if (!allow && source != NULL && destination != NULL &&
        SafeUploadIsAuthenticatedClient() &&
        FltGetRequestorProcessId(Data) == SafeUploadData.InspectorProcessId &&
        (cls == FileRenameInformation || cls == FileRenameInformationEx)) {
        publication = TRUE;
#if SAFEUPLOAD_STAGING_PROTOTYPE
        if (!AdmissionSlot->DirectoryMutation &&
            InterlockedCompareExchange(&StageDirectoryMutationActive, 0, 0) != 0) {
            quarantineRefused = TRUE;
            goto Complete;
        }
#endif
        allow = SafeUploadPublicationRename(Objects->Volume, &source->Name, &destination->Name,
            &quarantineRefused);
    }
#if SAFEUPLOAD_STAGING_PROTOTYPE
PrepareRename:
    if (allow && AdmissionSlot->DirectoryMutation) {
        directoryStatus = StageNamespaceRevalidateBindings(Data, Objects, source, destination, &bindings);
        if (!NT_SUCCESS(directoryStatus)) { allow = FALSE; goto Complete; }
    }
    if (allow && RegistryRenameContext != NULL) {
        (VOID)SafeUploadStageWritersPrepareRename(Data, Objects, &source->Name, &destination->Name,
            linkOperation, RegistryRenameContext);
    }
#endif
Complete:
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (!allow && AdmissionSlot->DirectoryMutation) {
        StageDirectoryEndMutation(FALSE);
        AdmissionSlot->DirectoryMutation = FALSE;
    }
#endif
    if (directoryStatus != STATUS_SUCCESS) {
        if (source != NULL) FltReleaseFileNameInformation(source);
        if (destination != NULL) FltReleaseFileNameInformation(destination);
        Data->IoStatus.Status = directoryStatus;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    if (TrackedWriter && !allow && !destinationProtected) {
        /* Keep the existing handle live. If the rename target cannot be classified, retain Unknown
         * so the identity cannot be promoted using its stale name. A rename or
         * hard-link whose destination is unresolved on a volume that can hold
         * policy scope must also fail before the filesystem publishes it. */
        SafeUploadStageWritersMutationDraining(Objects->Instance,
            Objects->FileObject != NULL ? Objects->FileObject->SectionObjectPointer : NULL);
        if (unresolved && SafeUploadPolicyMayMatchInstanceVolume(Objects->Instance)) {
            allow = FALSE;
        } else {
            allow = TRUE;
        }
    }
    if (source != NULL) FltReleaseFileNameInformation(source);
    if (destination != NULL) FltReleaseFileNameInformation(destination);
    /* Orchestrator decision P0-1: unresolved rename state refuses only on a volume that can hold policy scope. */
    if (!allow && unresolved && !SafeUploadPolicyMayMatchInstanceVolume(Objects->Instance))
        allow = TRUE;
    if (allow) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    /* T6 (owner decision 2026-10-08): moves into a protected folder are inspected like copies. A rename or hard link
     * from outside every protected scope into one is answered the way Windows answers a move to another volume, so
     * callers that allow that (MoveFileEx with MOVEFILE_COPY_ALLOWED, the Explorer copy engine) copy the file instead,
     * through staging and inspection like any copy. The rename itself still never reaches the file system. */
    Data->IoStatus.Status = quarantineRefused ? STATUS_SHARING_VIOLATION :
        (destinationProtected && !sourceProtected && !publication) ? STATUS_NOT_SAME_DEVICE : STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

/* FSCTL codes that change a file's data, allocation, metadata or namespace position. A handle that predates the
 * filter (or the policy scope) reaches the file system with these and never passes StageAdmit, so each is checked
 * against the protected namespace exactly like a physical SET_INFORMATION. Oplock, query and lock FSCTLs are NOT
 * listed: applications use them constantly and they cannot change protected bytes. Codes missing from the WDK
 * headers are built with CTL_CODE from winioctl.h's function numbers. */
#ifndef FSCTL_SET_ZERO_DATA
#define FSCTL_SET_ZERO_DATA CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 50, METHOD_BUFFERED, FILE_WRITE_DATA)
#endif
#ifndef FSCTL_SET_SPARSE
#define FSCTL_SET_SPARSE CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 49, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#endif
#ifndef FSCTL_SET_COMPRESSION
#define FSCTL_SET_COMPRESSION CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 16, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#endif
#ifndef FSCTL_SET_ENCRYPTION
#define FSCTL_SET_ENCRYPTION CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 53, METHOD_NEITHER, FILE_ANY_ACCESS)
#endif
#ifndef FSCTL_ENCRYPTION_FSCTL_IO
#define FSCTL_ENCRYPTION_FSCTL_IO CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 54, METHOD_NEITHER, FILE_ANY_ACCESS)
#endif
#ifndef FSCTL_SET_OBJECT_ID
#define FSCTL_SET_OBJECT_ID CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 38, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#endif
#ifndef FSCTL_SET_OBJECT_ID_EXTENDED
#define FSCTL_SET_OBJECT_ID_EXTENDED CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 47, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#endif
#ifndef FSCTL_CREATE_OR_GET_OBJECT_ID
#define FSCTL_CREATE_OR_GET_OBJECT_ID CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 48, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#ifndef FSCTL_DELETE_OBJECT_ID
#define FSCTL_DELETE_OBJECT_ID CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 40, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#endif
#ifndef FSCTL_SET_REPARSE_POINT
#define FSCTL_SET_REPARSE_POINT CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 41, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#endif
#ifndef FSCTL_DELETE_REPARSE_POINT
#define FSCTL_DELETE_REPARSE_POINT CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 43, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#endif
#ifndef FSCTL_SET_INTEGRITY_INFORMATION
#define FSCTL_SET_INTEGRITY_INFORMATION CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 160, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#endif
#ifndef FSCTL_DUPLICATE_EXTENTS_TO_FILE
#define FSCTL_DUPLICATE_EXTENTS_TO_FILE CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 209, METHOD_BUFFERED, FILE_WRITE_DATA)
#endif
#ifndef FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX
#define FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 250, METHOD_BUFFERED, FILE_WRITE_DATA)
#endif
#ifndef FSCTL_FILE_LEVEL_TRIM
#define FSCTL_FILE_LEVEL_TRIM CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 130, METHOD_BUFFERED, FILE_WRITE_DATA)
#endif
#ifndef FSCTL_OFFLOAD_WRITE
#define FSCTL_OFFLOAD_WRITE CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 154, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#endif
#ifndef FSCTL_SET_EXTERNAL_BACKING
#define FSCTL_SET_EXTERNAL_BACKING CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 195, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#endif
#ifndef FSCTL_WRITE_RAW_ENCRYPTED
#define FSCTL_WRITE_RAW_ENCRYPTED CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 55, METHOD_NEITHER, FILE_SPECIAL_ACCESS)
#endif

#ifndef FSCTL_SET_ZERO_ON_DEALLOCATION
#define FSCTL_SET_ZERO_ON_DEALLOCATION CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 101, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#endif
#ifndef FSCTL_DELETE_EXTERNAL_BACKING
#define FSCTL_DELETE_EXTERNAL_BACKING CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 197, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#endif
/* Whatever defines these symbols (the WDK or the fallbacks above), the numeric values must be the documented ones:
 * a wrong fallback would deny an unrelated code and miss the real mutator. */
C_ASSERT(FSCTL_SET_ZERO_DATA == 0x980C8);
C_ASSERT(FSCTL_SET_SPARSE == 0x900C4);
C_ASSERT(FSCTL_SET_COMPRESSION == 0x9C040);
C_ASSERT(FSCTL_SET_ENCRYPTION == 0x900D7);
C_ASSERT(FSCTL_ENCRYPTION_FSCTL_IO == 0x900DB);
C_ASSERT(FSCTL_SET_OBJECT_ID == 0x90098);
C_ASSERT(FSCTL_SET_OBJECT_ID_EXTENDED == 0x900BC);
C_ASSERT(FSCTL_CREATE_OR_GET_OBJECT_ID == 0x900C0);
C_ASSERT(FSCTL_DELETE_OBJECT_ID == 0x900A0);
C_ASSERT(FSCTL_SET_REPARSE_POINT == 0x900A4);
C_ASSERT(FSCTL_DELETE_REPARSE_POINT == 0x900AC);
C_ASSERT(FSCTL_SET_INTEGRITY_INFORMATION == 0x9C280);
C_ASSERT(FSCTL_DUPLICATE_EXTENTS_TO_FILE == 0x98344);
C_ASSERT(FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX == 0x983E8);
C_ASSERT(FSCTL_FILE_LEVEL_TRIM == 0x98208);
C_ASSERT(FSCTL_OFFLOAD_WRITE == 0x98268);
C_ASSERT(FSCTL_SET_EXTERNAL_BACKING == 0x9030C);
C_ASSERT(FSCTL_WRITE_RAW_ENCRYPTED == 0x900DF);
C_ASSERT(FSCTL_SET_ZERO_ON_DEALLOCATION == 0x90194);
C_ASSERT(FSCTL_DELETE_EXTERNAL_BACKING == 0x90314);

static BOOLEAN StageMutatingFsctl(ULONG Code)
{
    switch (Code) {
    case FSCTL_SET_ZERO_DATA: case FSCTL_SET_SPARSE: case FSCTL_SET_COMPRESSION: case FSCTL_SET_ENCRYPTION:
    case FSCTL_ENCRYPTION_FSCTL_IO: case FSCTL_SET_OBJECT_ID: case FSCTL_SET_OBJECT_ID_EXTENDED:
    case FSCTL_CREATE_OR_GET_OBJECT_ID: case FSCTL_DELETE_OBJECT_ID: case FSCTL_SET_REPARSE_POINT:
    case FSCTL_DELETE_REPARSE_POINT: case FSCTL_SET_INTEGRITY_INFORMATION: case FSCTL_DUPLICATE_EXTENTS_TO_FILE:
    case FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX: case FSCTL_FILE_LEVEL_TRIM: case FSCTL_OFFLOAD_WRITE:
    case FSCTL_SET_EXTERNAL_BACKING: case FSCTL_WRITE_RAW_ENCRYPTED:
    case FSCTL_SET_ZERO_ON_DEALLOCATION: case FSCTL_DELETE_EXTERNAL_BACKING:
        return TRUE;
    default:
        return FALSE;
    }
}

static BOOLEAN StageReparseFsctl(ULONG Code)
{
    return Code == FSCTL_SET_REPARSE_POINT || Code == FSCTL_DELETE_REPARSE_POINT;
}

/* The deny ring names the refusing code by the caller of this helper (the choke point in SafeUploadStageDispatch
 * records the refusal and picks the hint up), so the helper must not be inlined into its callers. */
__declspec(noinline) static FLT_PREOP_CALLBACK_STATUS StageCompleteAccessDenied(_Inout_ PFLT_CALLBACK_DATA Data)
{
    SafeUploadDenySiteHint(Data, _ReturnAddress());
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

#if SAFEUPLOAD_STAGING_PROTOTYPE
/* A mutating FSCTL through a file object that was never admitted. The service PID is not an exception here: these
 * operations can mutate caller-selected physical objects, so they receive the same scope and alias checks as others.
 * Safe name and alias resolution is supported only for fixed NTFS objects at PASSIVE_LEVEL without a top-level IRP.
 * Reparse-changing FSCTLs also cover ancestors of a protected prefix, because turning a parent into a junction
 * redirects the protected namespace. When a safe alias check is unavailable, refuse only if the cached volume
 * classifier says this instance could contain a current, pending, or boot scope. */
static FLT_PREOP_CALLBACK_STATUS StageUnownedMutatingFsctl(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, _Outptr_result_maybenull_ PVOID *MutatingIoContext)
{
    PFLT_FILE_NAME_INFORMATION name = NULL;
    ULONG code;
    BOOLEAN ancestors;
    BOOLEAN protectedAlias = FALSE;
    BOOLEAN unresolved = TRUE;
    FLT_FILESYSTEM_TYPE fs;
    SAFEUPLOAD_VOLUME_KIND kind;
    BOOLEAN trackedWriter = FALSE;
    NTSTATUS status;

    *MutatingIoContext = NULL;
    if (Data->Iopb->MinorFunction != IRP_MN_USER_FS_REQUEST) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    code = Data->Iopb->Parameters.FileSystemControl.Common.FsControlCode;
    if (!StageMutatingFsctl(code)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (FLT_IS_FASTIO_OPERATION(Data)) return FLT_PREOP_DISALLOW_FASTIO;            /* retried as an IRP */
    (VOID)SafeUploadStageWritersBeginMutatingIo(Data, Objects->Instance, Objects->FileObject,
        MutatingIoContext, &trackedWriter);
    if (trackedWriter)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    ancestors = StageReparseFsctl(code);

    if (KeGetCurrentIrql() == PASSIVE_LEVEL && IoGetTopLevelIrp() == NULL &&
        !FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) {
        status = FltGetFileSystemType(Objects->Instance, &fs);
        if (!NT_SUCCESS(status) || fs != FLT_FSTYPE_NTFS) goto Unresolved;

        status = FltGetFileNameInformation(Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name);
        if (!NT_SUCCESS(status)) goto Unresolved;
        status = FltParseFileNameInformation(name);
        if (!NT_SUCCESS(status)) {
            FltReleaseFileNameInformation(name);
            name = NULL;
            goto Unresolved;
        }

        kind = StageVolumeKind(Objects->Instance);
        if (SafeUploadStageWritersNameActivating(Objects->Instance, &name->Name) ||
            SafeUploadPolicyMatchesCurrentOrPendingDestination(kind, &name->Name, ancestors) ||
            (ancestors ? SafeUploadStageTouchesProtectedNamespace(name, kind) :
                SafeUploadStageProtectedName(name, kind))) {
            FltReleaseFileNameInformation(name);
            return StageCompleteAccessDenied(Data);
        }

        /* The alias scanner intentionally supports NTFS only. Do not let a cached/name-level out-of-scope result
         * stand in for alias coverage on network, removable, unknown, or other filesystem types. */
        if (Objects->FileObject == NULL) goto Unresolved;
        status = SafeUploadStageCheckObjectAliases(Data, Objects->Instance, Objects->FileObject,
            &name->Volume, kind, &protectedAlias);
        FltReleaseFileNameInformation(name);
        name = NULL;
        if (!NT_SUCCESS(status)) goto Unresolved;
        unresolved = FALSE;
        if (protectedAlias) return StageCompleteAccessDenied(Data);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* At APC_LEVEL, in paging I/O, or with a top-level IRP, do not query a name. */
Unresolved:
    if (name != NULL) FltReleaseFileNameInformation(name);
    /* Orchestrator decision P0-1: the unsafe-context and alias-loss fallback is volume-scoped. */
    if (unresolved && !SafeUploadPolicyMayMatchInstanceVolume(Objects->Instance))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    return StageCompleteAccessDenied(Data);
}
#endif

#if SAFEUPLOAD_STAGING_PROTOTYPE
#ifndef SEC_IMAGE
#define SEC_IMAGE 0x01000000
#endif
/* A writable data section created through a file object that was never admitted. Such a handle predates the
 * filter or its policy scope, so its later paging writes could not be redirected. The writer registry's live
 * SOP index accounts for existing sections; current+pending name admission closes new section creation.
 * Querying a name in a PRE-operation section-synchronization callback is documented as allowed; when no name
 * can be resolved the section is denied and counted. */
static FLT_PREOP_CALLBACK_STATUS StageUnownedWritableSection(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS Objects)
{
    PFLT_FILE_NAME_INFORMATION name = NULL;
    SAFEUPLOAD_VOLUME_KIND kind = StageVolumeKind(Objects->Instance);
    FLT_FILESYSTEM_TYPE fs;
    BOOLEAN unresolved = TRUE;
    NTSTATUS status;
    UINT32 denyReason = SAFEUPLOAD_DENY_REASON_NONE;
    NTSTATUS denyAux = STATUS_SUCCESS;

    if (Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType != SyncTypeCreateSection) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!FlagOn(Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection,
            PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (FlagOn(Data->Iopb->Parameters.AcquireForSectionSynchronization.AllocationAttributes, SEC_IMAGE)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || IoGetTopLevelIrp() != NULL) {
        denyReason = SAFEUPLOAD_DENY_REASON_TOP_LEVEL_IRP;
        goto Deny;
    }
    status = FltGetFileSystemType(Objects->Instance, &fs);
    if (!NT_SUCCESS(status)) {
        /* A classification error is not evidence that the file system is outside policy. The normalized
         * name below can still resolve its scope; if that also fails, this writable section is denied. */
        SafeUploadTrace("writable section file-system classification failed; checking protected-name policy\n");
    } else if (fs != FLT_FSTYPE_NTFS) {
        /* Positively outside the qualified file-ID registry, but still subject to name/policy admission. */
        SafeUploadTrace("writable section outside the qualified registry; checking protected-name policy\n");
    }
    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name);
    if (!NT_SUCCESS(status)) {
        denyReason = SAFEUPLOAD_DENY_REASON_NAME_UNRESOLVED;
        denyAux = status;
        goto Deny;
    }
    /* The current+pending union is read under one shared policy-lock hold. Separate checks can straddle a shrink:
     * pending misses the old-only scope, then the swap publishes the new current policy before the current check. */
    status = FltParseFileNameInformation(name);
    if (!NT_SUCCESS(status)) {
        denyReason = SAFEUPLOAD_DENY_REASON_NAME_UNRESOLVED;
        denyAux = status;
        goto Deny;
    }
    if (SafeUploadPolicyMatchesCurrentOrPendingDestination(kind, &name->Name, FALSE) ||
        SafeUploadStageProtectedName(name, kind)) {
        unresolved = FALSE;
        denyReason = SAFEUPLOAD_DENY_REASON_POLICY_SCOPE;
        goto Deny;
    }
    if (SafeUploadStageWritersSopMatchesPolicy(Objects->Instance, Objects->FileObject, FALSE)) {
        /* T2c: the opened name is outside every scope but the stream's entry says it may match. If that is only a pending alias
         * probe (a writer from before the policy apply) or a scope transition, wait a bounded time and decide again: the opened
         * name and the entry, under a scope sequence that does not change during that decision (a publication meanwhile
         * refuses; Luna T2c review P1). */
        ULONGLONG sequence;
        SafeUploadStageWritersAwaitClassification(Objects->Instance, Objects->FileObject);
        sequence = SafeUploadPolicyScopeSequenceSnapshot();
        if (SafeUploadPolicyMatchesCurrentOrPendingDestination(kind, &name->Name, FALSE) ||
            SafeUploadStageProtectedName(name, kind)) {
            unresolved = FALSE;
            denyReason = SAFEUPLOAD_DENY_REASON_POLICY_SCOPE;
            goto Deny;
        }
        if (SafeUploadStageWritersSopMatchesPolicy(Objects->Instance, Objects->FileObject, FALSE) ||
            SafeUploadPolicyScopeSequenceSnapshot() != sequence) {
            unresolved = FALSE;
            /* The opened name is outside. A conservative SOP/transition result
             * is not a literal name match; retain the exact reason for the next
             * capture instead of labelling unrelated cache files policyScope. */
            denyReason = SAFEUPLOAD_DENY_REASON_REGISTRY_SCOPE;
            denyAux = (NTSTATUS)(0xE5000000UL |
                SafeUploadStageWritersSopOutsideWhy(Objects->Instance, Objects->FileObject));
            goto Deny;
        }
    }
    if (SafeUploadStageWritersNameActivating(Objects->Instance, &name->Name)) {
        unresolved = FALSE;
        denyReason = SAFEUPLOAD_DENY_REASON_ACTIVATING_NAME;
        goto Deny;
    }
    unresolved = FALSE;
    FltReleaseFileNameInformation(name);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
 Deny:
    if (unresolved && KeGetCurrentIrql() <= APC_LEVEL &&
        SafeUploadStageWritersSopKnownOutside(Objects->Instance, Objects->FileObject)) {
        /* The name cannot be queried here (a nested call, or the lookup failed), but this stream has a registry entry
         * that recorded its name and was classified outside every scope: decide by that, not by "the volume may hold a
         * scope". Entries that are Activating, alias-pending, renamed, Unknown or in scope still answer "matches". */
        if (name != NULL) FltReleaseFileNameInformation(name);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (unresolved && !SafeUploadPolicyMayMatchInstanceVolume(Objects->Instance)) {
        if (name != NULL) FltReleaseFileNameInformation(name);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    SafeUploadDenyDetail(Data, denyReason, denyAux, name != NULL ? &name->Name : NULL);
    if (name != NULL) FltReleaseFileNameInformation(name);
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}
#endif

#if SAFEUPLOAD_STAGING_PROTOTYPE
static BOOLEAN StageEpochOperation(_In_ PFLT_CALLBACK_DATA Data)
{
    switch (Data->Iopb->MajorFunction) {
    case IRP_MJ_CREATE:
        {
            PIO_SECURITY_CONTEXT security = Data->Iopb->Parameters.Create.SecurityContext;
            ULONG disposition = Data->Iopb->Parameters.Create.Options >> 24;
            if (security == NULL) return TRUE; /* An unresolvable create still needs an epoch. */
            return BooleanFlagOn(security->DesiredAccess,
                FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
                FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE |
                GENERIC_ALL | MAXIMUM_ALLOWED) ||
                FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE) ||
                disposition == FILE_CREATE || disposition == FILE_SUPERSEDE ||
                disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF ||
                disposition == FILE_OPEN_IF;
        }
    case IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION:
        return Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType == SyncTypeCreateSection &&
            FlagOn(Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection,
                PAGE_READWRITE | PAGE_EXECUTE_READWRITE);
    case IRP_MJ_SET_INFORMATION:
        /* Namespace and metadata mutations must drain with the policy snapshot
         * they were admitted under. FilePositionInformation only changes a
         * handle-local cursor and does not enter the lower mutation path. */
        return Data->Iopb->Parameters.SetFileInformation.FileInformationClass !=
            FilePositionInformation;
    case IRP_MJ_SET_SECURITY:
        return TRUE; /* Publication must drain ancestor ACL changes too. */
    case IRP_MJ_FILE_SYSTEM_CONTROL:
        /* Publication must drain case/reparse/data FSCTLs too. Oplock requests
         * and waiting reads never mutate, yet stay pending in lower layers until
         * an unrelated break, record or repair: an epoch token held through their
         * completion pinned the epoch, so the first policy swap after boot timed
         * out and failed closed (m2t5boot6, SetPolicy STATUS_IO_TIMEOUT). Only a
         * user/kernel FS request carries an FsControlCode; others stay epochs. */
        if (Data->Iopb->MinorFunction != IRP_MN_USER_FS_REQUEST &&
            Data->Iopb->MinorFunction != IRP_MN_KERNEL_CALL) return TRUE;
        switch (Data->Iopb->Parameters.FileSystemControl.Common.FsControlCode) {
        case FSCTL_REQUEST_OPLOCK_LEVEL_1:
        case FSCTL_REQUEST_OPLOCK_LEVEL_2:
        case FSCTL_REQUEST_BATCH_OPLOCK:
        case FSCTL_REQUEST_FILTER_OPLOCK:
        case FSCTL_REQUEST_OPLOCK:
        case FSCTL_OPLOCK_BREAK_ACKNOWLEDGE:
        case FSCTL_OPBATCH_ACK_CLOSE_PENDING:
        case FSCTL_OPLOCK_BREAK_NOTIFY:
        case FSCTL_OPLOCK_BREAK_ACK_NO_2:
        case FSCTL_READ_USN_JOURNAL:
        case FSCTL_WAIT_FOR_REPAIR:
            return FALSE;
        default:
            return TRUE;
        }
    default:
        return FALSE;
    }
}

static BOOLEAN StageEpochOperationTouchesUnion(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects)
{
    PFLT_FILE_NAME_INFORMATION name = NULL, destination = NULL;
    SAFEUPLOAD_VOLUME_KIND kind = StageVolumeKind(Objects->Instance);
    BOOLEAN matched = FALSE;
    NTSTATUS status;
    /* Section release only retires a C slot. Let it reach lower completion so
     * the epoch drain and any Activating promotion can make progress. */
    if (Data->Iopb->MajorFunction == IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION) return FALSE;
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) return FALSE;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || IoGetTopLevelIrp() != NULL) {
        /* The policy push lock and name APIs are not safe on this path. Retry only when the
         * mounted volume could contain a current/pending scope. */
        return SafeUploadPolicyMayMatchInstanceVolume(Objects->Instance);
    }
    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name);
    if (!NT_SUCCESS(status)) return SafeUploadPolicyMayMatchInstanceVolume(Objects->Instance);
    status = FltParseFileNameInformation(name);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(name);
        return SafeUploadPolicyMayMatchInstanceVolume(Objects->Instance);
    }
    matched = SafeUploadPolicyMatchesCurrentOrPendingDestination(kind, &name->Name,
        Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION ||
        (Data->Iopb->MajorFunction == IRP_MJ_CREATE &&
         FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)));
    if (Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION) {
        FILE_INFORMATION_CLASS cls = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
        if (cls == FileRenameInformation || cls == FileRenameInformationEx ||
            cls == FileLinkInformation || cls == FileLinkInformationEx) {
            PFILE_RENAME_INFORMATION rename = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
            ULONG length = Data->Iopb->Parameters.SetFileInformation.Length;
            if (rename == NULL || length < (ULONG)FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName) ||
                rename->FileNameLength == 0 || (rename->FileNameLength & 1) ||
                rename->FileNameLength > length - (ULONG)FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName)) {
                matched = SafeUploadPolicyMayMatchInstanceVolume(Objects->Instance);
            } else if (NT_SUCCESS(FltGetDestinationFileNameInformation(Objects->Instance,
                Objects->FileObject, rename->RootDirectory, rename->FileName, rename->FileNameLength,
                FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &destination))) {
                if (SafeUploadPolicyMatchesCurrentOrPendingDestination(kind, &destination->Name, TRUE))
                    matched = TRUE;
            } else if (SafeUploadPolicyMayMatchInstanceVolume(Objects->Instance)) {
                matched = TRUE;
            }
        }
    }
    if (destination != NULL) FltReleaseFileNameInformation(destination);
    FltReleaseFileNameInformation(name);
    return matched;
}

__declspec(noinline) static FLT_PREOP_CALLBACK_STATUS StageCompleteEpochRetry(_Inout_ PFLT_CALLBACK_DATA Data)
{
    SafeUploadDenySiteHint(Data, _ReturnAddress());
    Data->IoStatus.Status = STATUS_RETRY;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}
#endif

#if SAFEUPLOAD_STAGING_PROTOTYPE
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageMvpCancelNames(_In_ PFLT_INSTANCE Instance,
    _In_ PUNICODE_STRING Source, _In_opt_ PUNICODE_STRING Target, _In_ BOOLEAN Cancel);
_IRQL_requires_(PASSIVE_LEVEL)
static FLT_PREOP_CALLBACK_STATUS StageMvpNamespacePre(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _Flt_CompletionContext_Outptr_ PVOID *CompletionContext,
    _Out_ PBOOLEAN Handled, _Inout_ PSTAGE_ADMISSION_TOKEN_SLOT Slot);
_IRQL_requires_max_(APC_LEVEL)
static BOOLEAN StageMvpRenameNeedsCopy(_In_ PFLT_FILE_NAME_INFORMATION Source,
    _In_ PFLT_FILE_NAME_INFORMATION Target);
#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, StageMvpRenameNeedsCopy)
#pragma alloc_text(PAGE, StageMvpCancelNames)
#pragma alloc_text(PAGE, StageMvpNamespacePre)
#endif

/* Fence is already installed. Pin only one stream per RPC; no stack array or
 * unbounded allocation, and no namespace/stream resource spans the exchange. */
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageMvpCancelNames(_In_ PFLT_INSTANCE Instance, _In_ PUNICODE_STRING Source,
    _In_opt_ PUNICODE_STRING Target, _In_ BOOLEAN Cancel)
{
    ULONG attempt;
    PAGED_CODE();
    for (attempt = 0; attempt <= STAGE_LIMIT; ++attempt) {
        PLIST_ENTRY link;
        PSTAGE_STREAM cancel = NULL;
        NTSTATUS status = STATUS_SUCCESS;
        StageAcquire(&StageNamespaceResource);
        for (link = StageStreams.Flink; link != &StageStreams; link = link->Flink) {
            PSTAGE_STREAM stream = CONTAINING_RECORD(link, STAGE_STREAM, Link);
            if (stream->OriginalInstance != Instance || (!RtlEqualUnicodeString(&stream->Name, Source, TRUE) &&
                (Target == NULL || !RtlEqualUnicodeString(&stream->Name, Target, TRUE)))) continue;
            StageAcquire(&stream->Resource);
            if (stream->ShareAccess.OpenCount != 0 || stream->RenameExchange != NULL ||
                stream->AllocationRpcInFlight || stream->SealRpcInFlight || stream->SealRpcPending ||
                stream->PrivateCancellationBusy || stream->BoundAllocation) status = STATUS_SHARING_VIOLATION;
            StageRelease(&stream->Resource);
            if (!NT_SUCCESS(status)) break;
            if (!Cancel) continue; /* Read-only preflight before original NTFS CREATE. */
            if (stream->Discarded || stream->PrivateCancellationAccepted || stream->Disposed ||
                stream->MvpPublicationObserved) continue;
            if (!stream->Sealed) {
                /* A closed, never-sealed probe cannot have an inspector. Use
                 * ordinary private discard; the worker owns the exact ACK. */
                stream->DiscardDisposition = TRUE;
                stream->DiscardOnClose = TRUE;
                if (stream->View != NULL && stream->View->Current == stream) stream->View->Detached = TRUE;
                StageQueueStream(stream, &StageCounters.WakeInline);
            } else if (cancel == NULL) cancel = stream;
        }
        if (NT_SUCCESS(status) && cancel != NULL) InterlockedIncrement(&cancel->RpcReferences);
        StageRelease(&StageNamespaceResource);
        if (!NT_SUCCESS(status)) return status;
        if (cancel == NULL) return STATUS_SUCCESS;
        status = StageCancelSealedPrivate(cancel, TRUE);
        StageAcquire(&StageNamespaceResource);
        InterlockedDecrement(&cancel->RpcReferences);
        StageQueueStream(cancel, &StageCounters.WakeInline);
        StageRelease(&StageNamespaceResource);
        if (!NT_SUCCESS(status)) return status;
    }
    return STATUS_SHARING_VIOLATION;
}

_IRQL_requires_max_(APC_LEVEL)
static BOOLEAN StageMvpRenameNeedsCopy(_In_ PFLT_FILE_NAME_INFORMATION Source,
    _In_ PFLT_FILE_NAME_INFORMATION Target)
{
    PAGED_CODE();
    return SafeUploadStageProtectedName(Target, SafeUploadVolumeFixed) &&
        (!SafeUploadPolicySameProtectedScope(&Source->Name, &Target->Name) ||
         (!SafeUploadPolicyMatchesExtension(&Source->Name) && SafeUploadPolicyMatchesExtension(&Target->Name)));
}

/* Native original-object path for the unbound local NTFS profile. No handle
 * export, second open, flag translation or synthetic FILE_OBJECT. NTFS checks
 * the original grant and all native sharing/image/read-only/flag semantics. */
_IRQL_requires_(PASSIVE_LEVEL)
static FLT_PREOP_CALLBACK_STATUS StageMvpNamespacePre(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _Flt_CompletionContext_Outptr_ PVOID *CompletionContext,
    _Out_ PBOOLEAN Handled, _Inout_ PSTAGE_ADMISSION_TOKEN_SLOT Slot)
{
    PFLT_FILE_NAME_INFORMATION source = NULL, target = NULL;
    PFILE_OBJECT file = Data->Iopb->TargetFileObject;
    UCHAR major = Data->Iopb->MajorFunction;
    FILE_INFORMATION_CLASS cls = FileMaximumInformation;
    PFILE_RENAME_INFORMATION rename = NULL;
    FILE_STANDARD_INFORMATION standard;
    FLT_FILESYSTEM_TYPE fs;
    BOOLEAN mutation = FALSE, replace = FALSE;
    PVOID mutatingIoContext = NULL, registryRenameContext = NULL;
    BOOLEAN trackedWriter = FALSE;
    STAGE_NAMESPACE_BINDINGS bindings;
    NTSTATUS status = STATUS_SUCCESS;
    FLT_PREOP_CALLBACK_STATUS result = FLT_PREOP_SUCCESS_NO_CALLBACK;
    PAGED_CODE();
    *Handled = FALSE;
    *CompletionContext = NULL;
    if (file == NULL || Objects->Transaction != NULL || !FLT_IS_IRP_OPERATION(Data) ||
        KeGetCurrentIrql() != PASSIVE_LEVEL || IoGetTopLevelIrp() != NULL ||
        StageVolumeKind(Objects->Instance) != SafeUploadVolumeFixed ||
        SafeUploadStageProtocolNativeForwardAllowed(0, 0) ||
        (SafeUploadIsAuthenticatedClient() && FltGetRequestorProcessId(Data) == SafeUploadData.InspectorProcessId))
        return result;
    if (major == IRP_MJ_CREATE) {
        if (!StageMvpNamespaceOpen(Data) || FlagOn(Data->Iopb->Parameters.Create.Options,
            FILE_DIRECTORY_FILE | FILE_OPEN_BY_FILE_ID | FILE_OPEN_REPARSE_POINT) ||
            FlagOn(Data->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY)) return result;
        mutation = BooleanFlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE);
    } else if (major == IRP_MJ_SET_INFORMATION) {
        ULONG length = Data->Iopb->Parameters.SetFileInformation.Length;
        PVOID buffer = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        if (file->WriteAccess) return result;
        cls = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
        if (cls == FileRenameInformation || cls == FileRenameInformationEx) {
            rename = buffer;
            if (rename == NULL || length < (ULONG)FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName) ||
                rename->FileNameLength == 0 || (rename->FileNameLength & 1) != 0 ||
                rename->FileNameLength > length - (ULONG)FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName)) return result;
            replace = cls == FileRenameInformationEx ?
                BooleanFlagOn(*(PULONG)rename, FILE_RENAME_REPLACE_IF_EXISTS) : rename->ReplaceIfExists;
            mutation = TRUE;
        } else if (cls == FileDispositionInformation || cls == FileDispositionInformationEx) {
            if (buffer == NULL || length < (cls == FileDispositionInformation ? sizeof(BOOLEAN) : sizeof(ULONG)))
                return result;
            mutation = cls == FileDispositionInformation ? ((PFILE_DISPOSITION_INFORMATION)buffer)->DeleteFile :
                BooleanFlagOn(*(PULONG)buffer, FILE_DISPOSITION_DELETE);
        } else if (cls != FileBasicInformation) return result;
    } else return result;
    if (!NT_SUCCESS(FltGetFileSystemType(Objects->Instance, &fs)) || fs != FLT_FSTYPE_NTFS) return result;
    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY |
            FLT_FILE_NAME_REQUEST_FROM_CURRENT_PROVIDER, &source);
    if (!NT_SUCCESS(status) || !NT_SUCCESS(FltParseFileNameInformation(source))) goto Exit;
    if (source->Stream.Length != 0 || !SafeUploadStageProtectedName(source, SafeUploadVolumeFixed)) goto Exit;
    if (major == IRP_MJ_CREATE) {
        FILE_ID_INFORMATION identity;
        BOOLEAN privateName;
        StageAcquire(&StageNamespaceResource);
        privateName = StageFindView(FltGetRequestorProcess(Data), &source->Name) != NULL ||
            StageHiddenName(FltGetRequestorProcess(Data), &source->Name);
        StageRelease(&StageNamespaceResource);
        if (privateName) goto Exit;
        status = SafeUploadStageQueryIdentity(Objects->Instance, &source->Name, FALSE, &identity);
        if (!NT_SUCCESS(status)) goto Exit; /* existing non-directory file only */
        /* OPEN_IF may use this route only as OPEN_EXISTING. The native open
         * still checks existence and authority; a racing unlink cannot create
         * an uninspected placeholder through this branch. */
        if ((Data->Iopb->Parameters.Create.Options >> 24) == FILE_OPEN_IF) {
            Data->Iopb->Parameters.Create.Options =
                (Data->Iopb->Parameters.Create.Options & 0x00FFFFFF) | (FILE_OPEN << 24);
            FltSetCallbackDataDirty(Data);
        }
    } else {
        status = FltQueryInformationFile(Objects->Instance, file, &standard, sizeof(standard),
            FileStandardInformation, NULL);
        if (!NT_SUCCESS(status) || standard.Directory) goto Exit;
    }
    *Handled = TRUE;
    if (mutation && (major == IRP_MJ_CREATE ?
        !FlagOn(Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess, DELETE) : !file->DeleteAccess)) {
        status = STATUS_ACCESS_DENIED; goto Refuse;
    }
    if (rename != NULL) {
        status = FltGetDestinationFileNameInformation(Objects->Instance, file, rename->RootDirectory,
            rename->FileName, rename->FileNameLength,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY |
            FLT_FILE_NAME_REQUEST_FROM_CURRENT_PROVIDER, &target);
        if (!NT_SUCCESS(status)) goto Refuse;
        status = FltParseFileNameInformation(target);
        if (!NT_SUCCESS(status)) goto Refuse;
        if (target->Stream.Length != 0) { status = STATUS_NOT_SUPPORTED; goto Refuse; }
        if (StageMvpRenameNeedsCopy(source, target)) {
            status = STATUS_NOT_SAME_DEVICE; goto Refuse;
        }
    }
    if (!mutation) {
        if (major == IRP_MJ_CREATE) result = SafeUploadPreCreate(Data, Objects, CompletionContext);
        goto Exit;
    }
    status = StageNamespaceBeginMutation(Slot);
    if (!NT_SUCCESS(status)) goto Refuse;
    /* Fresh filesystem observations under the common fence, including exact
     * source-object/name and destination-parent/leaf bindings. */
    status = StageNamespaceCaptureBindings(Data, Objects, source, target, &bindings);
    if (!NT_SUCCESS(status)) goto Refuse;
    if (major != IRP_MJ_CREATE) {
        (VOID)SafeUploadStageWritersBeginMutatingIo(Data, Objects->Instance, file,
            &mutatingIoContext, &trackedWriter);
        if (rename != NULL) {
            (VOID)SafeUploadStageWritersPrepareRename(Data, Objects, &source->Name, &target->Name,
                FALSE, &registryRenameContext);
            SafeUploadStageWritersAttachMutatingIo(registryRenameContext, &mutatingIoContext);
        }
        if (target != NULL && replace) {
            status = SafeUploadStageCheckRenameAccess(Data, Objects->Instance, &target->Name, TRUE);
            if (!NT_SUCCESS(status)) goto Refuse;
        }
        status = StageMvpCancelNames(Objects->Instance, &source->Name,
            target != NULL && replace ? &target->Name : NULL, TRUE);
        if (!NT_SUCCESS(status)) goto Refuse;
    }
    status = StageNamespaceRevalidateBindings(Data, Objects, source, target, &bindings);
    if (!NT_SUCCESS(status)) goto Refuse;
    if (major == IRP_MJ_CREATE) {
        PVOID legacyContext = NULL;
        status = StageMvpCancelNames(Objects->Instance, &source->Name, NULL, FALSE);
        if (!NT_SUCCESS(status)) goto Refuse;
        result = SafeUploadPreCreate(Data, Objects, &legacyContext);
        if (result == FLT_PREOP_COMPLETE) goto Exit;
        /* Only the successful original CREATE proves the caller's NTFS
         * authorization. Its PASSIVE post cancels before app cleanup. */
        StageMvpNamespaceCreateName = source;
        source = NULL;
        StageMvpNamespaceCreateIdentity = bindings.Source;
        StageMvpNamespaceCreateContext = legacyContext;
        StageMvpNamespaceCreateCallback = result == FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }
    StageMvpNamespaceRegistryContext = registryRenameContext != NULL ? registryRenameContext : mutatingIoContext;
    registryRenameContext = mutatingIoContext = NULL;
    *CompletionContext = (PVOID)&StageMvpNamespaceCompletionTag;
    /* The admission epoch owns exclusion through registry/lower completion. */
    result = major == IRP_MJ_CREATE ? FLT_PREOP_SUCCESS_WITH_CALLBACK : FLT_PREOP_SYNCHRONIZE;
    goto Exit;
Refuse:
    Data->IoStatus.Status = status;
    Data->IoStatus.Information = 0;
    result = FLT_PREOP_COMPLETE;
Exit:
    SafeUploadStageWritersCompleteRename(Objects->Instance, registryRenameContext, FALSE, FALSE);
    SafeUploadStageWritersEndMutatingIo(mutatingIoContext);
    if (target != NULL) FltReleaseFileNameInformation(target);
    if (source != NULL) FltReleaseFileNameInformation(source);
    return result;
}

_IRQL_requires_(PASSIVE_LEVEL)
static VOID StageMvpNamespacePostCreate(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _In_opt_ PVOID LegacyContext,
    _In_ BOOLEAN LegacyCallback, _In_ FLT_POST_OPERATION_FLAGS Flags);
#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, StageMvpNamespacePostCreate)
#endif
_IRQL_requires_(PASSIVE_LEVEL)
static VOID StageMvpNamespacePostCreate(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _In_opt_ PVOID LegacyContext,
    _In_ BOOLEAN LegacyCallback, _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    PFLT_FILE_NAME_INFORMATION name = StageMvpNamespaceCreateName;
    FILE_ID_INFORMATION identity;
    ULONG returned = 0;
    NTSTATUS status = STATUS_ACCESS_DENIED;
    PAGED_CODE();
    StageMvpNamespaceCreateName = NULL;
    if (LegacyCallback) (VOID)SafeUploadPostCreate(Data, Objects, LegacyContext, Flags);
    /* CREATE post is PASSIVE even on drain. A denied lower CREATE
     * must never cancel a pending save. No lock spans the V28 RPC. */
    if (!FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) && Data->IoStatus.Status == STATUS_SUCCESS) {
        if (name != NULL && Objects->FileObject->DeleteAccess) {
            status = FltQueryInformationFile(Objects->Instance, Objects->FileObject,
                &identity, sizeof(identity), FileIdInformation, &returned);
            if (NT_SUCCESS(status) && returned != sizeof(identity)) status = STATUS_INVALID_BUFFER_SIZE;
            if (NT_SUCCESS(status) && !RtlEqualMemory(&identity,
                &StageMvpNamespaceCreateIdentity, sizeof(identity))) status = STATUS_SHARING_VIOLATION;
            if (NT_SUCCESS(status))
                status = StageMvpCancelNames(Objects->Instance, &name->Name, NULL, TRUE);
        }
        if (!NT_SUCCESS(status)) {
            FltCancelFileOpen(Objects->Instance, Objects->FileObject);
            Data->IoStatus.Status = status;
            Data->IoStatus.Information = 0;
        }
    }
    if (name != NULL) FltReleaseFileNameInformation(name);
}


/* Resident ownership completion. Only CREATE calls the PASSIVE helper; the
 * Filter Manager post-CREATE contract applies even during draining. */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID StageMvpNamespacePost(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    PVOID legacyContext = StageMvpNamespaceCreateContext;
    BOOLEAN legacyCallback = StageMvpNamespaceCreateCallback;
    PVOID registryContext = StageMvpNamespaceRegistryContext;
    StageMvpNamespaceCreateContext = NULL;
    StageMvpNamespaceCreateCallback = FALSE;
    StageMvpNamespaceRegistryContext = NULL;
    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
        StageMvpNamespacePostCreate(Data, Objects, legacyContext, legacyCallback, Flags);
    } else {
        SafeUploadStageWritersSetMutatingIoCompletion(registryContext, Data, Flags);
        if (SafeUploadStageWritersIsRenameContext(registryContext))
            SafeUploadStageWritersCompleteRename(Objects->Instance, registryContext,
                !FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) && Data->IoStatus.Status == STATUS_SUCCESS,
                FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING));
        else SafeUploadStageWritersEndMutatingIo(registryContext);
    }
    /* The epoch wrapper releases the common fence only AFTER this work;
     * draining latches it until reboot instead of admitting stale names. */
}

#endif

static FLT_PREOP_CALLBACK_STATUS StageDispatchCore(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, PVOID *CompletionContext,
    PSTAGE_ADMISSION_TOKEN_SLOT AdmissionSlot)
{
    FLT_PREOP_CALLBACK_STATUS result;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    PVOID sectionInFlight = NULL;
#endif
    *CompletionContext = NULL;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    {
        BOOLEAN handled;
        result = SafeUploadBoundPublicationPre(Data, Objects, CompletionContext, &handled);
        if (handled) return result;
    }
#endif
    if (Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION &&
        SafeUploadStageTxfSetInformationMustRefuse(Data, Objects)) {
        SafeUploadStageTxfRecordRefused();
        return StageCompleteAccessDenied(Data);
    }
    {
        /* The TxF FSCTL gate never leaves a completion context; give it a scratch one so *CompletionContext stays provably NULL
           for the legacy callbacks below (PREfast C6388 on each of their call sites). */
        PVOID txfFsctlContext = NULL;
        result = SafeUploadStageTxfFsctlPreOperation(Data, Objects, &txfFsctlContext);
    }
    if (result != FLT_PREOP_SUCCESS_NO_CALLBACK) return result;
    /* Owned-stream routing MUST precede all legacy taint/context/policy callbacks. */
    if (StageStreamForObject(Data->Iopb->TargetFileObject) != NULL)
        return StagePreOperation(Data, Objects, CompletionContext, AdmissionSlot);
#if SAFEUPLOAD_STAGING_PROTOTYPE
    {
        BOOLEAN handled = FALSE;
        if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
            *CompletionContext = NULL; /* _Flt_CompletionContext_Outptr_ requires a NULL output on entry */
            result = StageMvpNamespacePre(Data, Objects, CompletionContext, &handled, AdmissionSlot);
        }
        if (handled) return result;
    }
#endif
    switch (Data->Iopb->MajorFunction) {
    case IRP_MJ_CREATE:
        {
        PVOID legacyCompletionContext = NULL;
        HANDLE directoryCollisionHold = NULL;
        SAFEUPLOAD_CREATE_ALIAS_PROOF aliasProof;
#if SAFEUPLOAD_STAGING_PROTOTYPE
        PVOID writerReservation = NULL;
        BOOLEAN reservationRequired = FALSE;
        NTSTATUS reserveStatus;
#endif
        RtlZeroMemory(&aliasProof, sizeof(aliasProof));
        result = StageAdmit(Data, Objects, &aliasProof, AdmissionSlot, &directoryCollisionHold);
        if (directoryCollisionHold != NULL) {
            /* The original FILE_CREATE is collision-only. The epoch wrapper
             * owns the handle until post-create, also on lower failure/drain. */
            AdmissionSlot->DirectoryCollision = TRUE;
            *CompletionContext = directoryCollisionHold;
            return FLT_PREOP_SUCCESS_WITH_CALLBACK;
        }
        if (result != FLT_PREOP_SUCCESS_NO_CALLBACK) return result;
#if SAFEUPLOAD_STAGING_PROTOTYPE
        /* StageCreate may have settled and detached the requester's last
         * disposed view. Classify the now-native open before legacy CREATE. */
        if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
            BOOLEAN handled;
            *CompletionContext = NULL; /* _Flt_CompletionContext_Outptr_ requires a NULL output on entry */
            result = StageMvpNamespacePre(Data, Objects, CompletionContext, &handled, AdmissionSlot);
            if (handled) return result;
        }
#endif
        result = SafeUploadPreCreate(Data, Objects, &legacyCompletionContext);
        if (result == FLT_PREOP_COMPLETE) return result;
#if SAFEUPLOAD_STAGING_PROTOTYPE
        /* Reserve bounded registry capacity before a physical writer create reaches NTFS. A
         * tracking failure records Unknown and leaves this admission decision unchanged. */
        reserveStatus = SafeUploadStageWritersReserveCreate(Data, Objects,
            &writerReservation, &reservationRequired, &aliasProof);
        if (!NT_SUCCESS(reserveStatus)) {
            if (writerReservation != NULL)
                SafeUploadStageWritersCancelReservation(writerReservation);
            SafeUploadStageWritersTrackingLost(Objects->Instance,
                SAFEUPLOAD_REGISTRY_UNKNOWN_ALLOCATION);
            reservationRequired = FALSE;
            writerReservation = NULL;
        }
        if (reservationRequired && writerReservation != NULL) {
            SafeUploadStageWritersSetCompletion(writerReservation, legacyCompletionContext,
                result == FLT_PREOP_SUCCESS_WITH_CALLBACK);
            *CompletionContext = writerReservation;
            return FLT_PREOP_SUCCESS_WITH_CALLBACK;
        }
        if (reservationRequired)
            SafeUploadStageWritersTrackingLost(Objects->Instance,
                SAFEUPLOAD_REGISTRY_UNKNOWN_ALLOCATION);
#endif
        *CompletionContext = legacyCompletionContext;
        return result;
        }
    case IRP_MJ_QUERY_OPEN:
    case IRP_MJ_NETWORK_QUERY_OPEN:
        if (FltGetRequestorProcessId(Data) > 4 &&
            FltGetRequestorProcessId(Data) != SafeUploadData.InspectorProcessId &&
            SafeUploadProcessHasMappings(FltGetRequestorProcessId(Data))) {
            if (Data->Iopb->MajorFunction == IRP_MJ_QUERY_OPEN) return FLT_PREOP_DISALLOW_FSFILTER_IO;
            if (FLT_IS_FASTIO_OPERATION(Data)) return FLT_PREOP_DISALLOW_FASTIO;
        }
        break;
    case IRP_MJ_DIRECTORY_CONTROL:
        *CompletionContext = NULL;
#if SAFEUPLOAD_STAGING_PROTOTYPE
        if (Data->Iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY)
            return FLT_PREOP_SUCCESS_WITH_CALLBACK; /* no allocation, wait or owning reference */
#endif
        return SafeUploadStageDirectoryQuery(Data, Objects, CompletionContext);
    case IRP_MJ_CLEANUP:
#if SAFEUPLOAD_STAGING_PROTOTYPE
        StageTraceFileLifetime(Data, Objects, SAFEUPLOAD_ADMISSION_TRACE_EVENT_FILE_CLEANUP);
#endif
        /* Legacy pre-callback SAL requires an empty completion slot. The
         * unhandled V26 lookup above cannot supply legacy cleanup ownership. */
        *CompletionContext = NULL;
        result = SafeUploadPreCleanup(Data, Objects, CompletionContext);
#if SAFEUPLOAD_STAGING_PROTOTYPE
        /* Synchronize: post-cleanup writer processing calls PAGE code (SafeUploadInstanceIsTrusted),
         * and a plain post-op may run at DISPATCH_LEVEL. */
        if (result == FLT_PREOP_SUCCESS_NO_CALLBACK || result == FLT_PREOP_SUCCESS_WITH_CALLBACK)
            return FLT_PREOP_SYNCHRONIZE;
#endif
        return result;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    case IRP_MJ_CLOSE:
        StageTraceFileLifetime(Data, Objects, SAFEUPLOAD_ADMISSION_TRACE_EVENT_FILE_CLOSE);
#if SAFEUPLOAD_STAGING_PROTOTYPE
        SafeUploadStageWritersQueueLifetimeRecheck(Objects->Instance, Objects->FileObject);
#endif
        if (SafeUploadStageNativePreClose(Objects, CompletionContext))
            return FLT_PREOP_SYNCHRONIZE;
        break;
    case IRP_MJ_MDL_READ_COMPLETE:
        /* Completion releases a previously returned MDL; do not block the release path. */
        break;
    case IRP_MJ_PREPARE_MDL_WRITE:
        /* PREPARE_MDL_WRITE fast I/O bypasses W. A retry uses IRP_MJ_WRITE below, which counts
         * W through completion for IRP_MN_MDL and IRP_MN_COMPLETE_MDL too. */
        if (FLT_IS_FASTIO_OPERATION(Data)) {
            FLT_FILESYSTEM_TYPE fileSystemType;
            BOOLEAN trackedWriter = SafeUploadStageWritersIsTrackedWriter(
                Objects->Instance, Objects->FileObject);
            if (trackedWriter) return FLT_PREOP_DISALLOW_FASTIO;
            if (StageVolumeKind(Objects->Instance) == SafeUploadVolumeFixed &&
                SafeUploadPolicyMayMatchInstanceVolume(Objects->Instance)) {
                NTSTATUS fileSystemStatus = FltGetFileSystemType(Objects->Instance,
                    &fileSystemType);
                if (!NT_SUCCESS(fileSystemStatus) || fileSystemType == FLT_FSTYPE_NTFS)
                    return FLT_PREOP_DISALLOW_FASTIO;
            }
        }
        break;
    case IRP_MJ_MDL_WRITE_COMPLETE:
        /* Completion releases the prepared MDL; the write request owns W rundown. */
        break;
#endif
    case IRP_MJ_WRITE:
#if SAFEUPLOAD_STAGING_PROTOTYPE
        {
            /* IRP_MN_MDL and IRP_MN_COMPLETE_MDL remain IRP_MJ_WRITE requests and take W here. */
            LONG traceState = SafeUploadAdmissionTraceControlState;
            if ((traceState & 1) != 0 && SafeUploadStageAdmissionTraceBegin(traceState)) {
                SAFEUPLOAD_ADMISSION_TRACE_ENTRY entry;

                StageAdmissionTraceFillOperation(&entry, Data, Objects,
                    FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO) ?
                        SAFEUPLOAD_ADMISSION_TRACE_EVENT_PAGING_WRITE :
                        SAFEUPLOAD_ADMISSION_TRACE_EVENT_UNOWNED_NONPAGING_WRITE,
                    FALSE);
                entry.MmDoesResult = SAFEUPLOAD_ADMISSION_TRACE_MMDOES_SKIPPED;
                SafeUploadStageAdmissionTraceRecord(&entry);
                SafeUploadStageAdmissionTraceEnd();
            }
        }
#endif
        if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) {
#if SAFEUPLOAD_STAGING_PROTOTYPE
            PVOID mutatingIoContext = NULL;
            BOOLEAN exactSopTracked = FALSE;
            PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;

            /* Owned-stage file objects were routed through StagePreOperation
             * above. A public physical FILE_OBJECT can still receive paging
             * writes from a writable section opened while the filter was
             * attached. Keep its exact writer/SOP mutation ticket (W) alive
             * until lower completion; never refuse it. Paging I/O is a ledger,
             * not a gate (2026-10-05 decision): an old writer finishes under the
             * rights it was granted and its file stays Activating until Free(F).
             * This path does not infer section lifetime from Cleanup or Close. */
            (VOID)SafeUploadStageWritersBeginPagingIo(Data, Objects->Instance,
                fileObject, &mutatingIoContext, &exactSopTracked);
            if (mutatingIoContext != NULL) {
                *CompletionContext = mutatingIoContext;
                return FLT_PREOP_SUCCESS_WITH_CALLBACK;
            }
#else
            /* Normal builds keep owned-stream staging compiled out. */
#endif
            break;
        }
        {
            PVOID mutatingIoContext = NULL;
            PVOID legacyContext = NULL;
            BOOLEAN trackedWriter = FALSE;
            if (FLT_IS_FASTIO_OPERATION(Data)) return FLT_PREOP_DISALLOW_FASTIO;
            (VOID)SafeUploadStageWritersBeginMutatingIo(Data, Objects->Instance, Objects->FileObject,
                &mutatingIoContext, &trackedWriter);
            result = StagePhysicalMutationEx(Data, Objects, FALSE, trackedWriter, &mutatingIoContext);
            if (result != FLT_PREOP_SUCCESS_NO_CALLBACK) {
                SafeUploadStageWritersEndMutatingIo(mutatingIoContext);
                return result;
            }
            result = SafeUploadPreWrite(Data, Objects, &legacyContext);
            if (result != FLT_PREOP_SUCCESS_NO_CALLBACK) {
                SafeUploadStageWritersEndMutatingIo(mutatingIoContext);
                return result;
            }
            *CompletionContext = mutatingIoContext != NULL ? mutatingIoContext : legacyContext;
            return *CompletionContext != NULL ? FLT_PREOP_SUCCESS_WITH_CALLBACK : result;
        }
    case IRP_MJ_SET_INFORMATION:
        {
        PVOID registryRenameContext = NULL;
        PVOID mutatingIoContext = NULL;
        PVOID legacyContext = NULL;
        FILE_INFORMATION_CLASS cls = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
        BOOLEAN trackedWriter = FALSE;
        if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO))
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        if (cls != FilePositionInformation && FLT_IS_FASTIO_OPERATION(Data))
            return FLT_PREOP_DISALLOW_FASTIO;
        if (cls != FilePositionInformation)
            (VOID)SafeUploadStageWritersBeginMutatingIo(Data, Objects->Instance, Objects->FileObject,
                &mutatingIoContext, &trackedWriter);
        result = StageExternalRename(Data, Objects, trackedWriter, &registryRenameContext, AdmissionSlot);
        if (result != FLT_PREOP_SUCCESS_NO_CALLBACK) {
            SafeUploadStageWritersEndMutatingIo(mutatingIoContext);
            return result;
        }
        if (cls != FilePositionInformation) {
            /* Publication rename is checked/consumed by StageExternalRename. */
            if (cls != FileRenameInformation && cls != FileRenameInformationEx &&
                cls != FileLinkInformation && cls != FileLinkInformationEx) {
#if SAFEUPLOAD_STAGING_PROTOTYPE
                BOOLEAN directoryHandled = FALSE;
                if (KeGetCurrentIrql() == PASSIVE_LEVEL)
                    result = StageNativeDirectoryInformation(Data, Objects, AdmissionSlot, &directoryHandled);
                if (!directoryHandled)
#endif
                /* Only a delete can remove a directory above a protected scope from under it (renames and links went
                 * through StageExternalRename above). Attribute, time and size changes of an ancestor leave the scope's
                 * bytes alone, and refusing them broke every caller that touches the volume root: the Profile Service
                 * sets basic information on C:\ while it builds a new profile, so first sign-in failed. */
                result = StagePhysicalMutationEx(Data, Objects,
                    cls == FileDispositionInformation || cls == FileDispositionInformationEx, trackedWriter, &mutatingIoContext);
                if (result != FLT_PREOP_SUCCESS_NO_CALLBACK) {
                    SafeUploadStageWritersEndMutatingIo(mutatingIoContext);
                    SafeUploadStageWritersCompleteRename(Objects->Instance,
                        registryRenameContext, FALSE, FALSE);
                    return result;
                }
            }
        }
        result = SafeUploadPreSetInformation(Data, Objects, &legacyContext);
#if SAFEUPLOAD_STAGING_PROTOTYPE
        if (result != FLT_PREOP_SUCCESS_NO_CALLBACK) {
            SafeUploadStageWritersCompleteRename(Objects->Instance, registryRenameContext, FALSE, FALSE);
            SafeUploadStageWritersEndMutatingIo(mutatingIoContext);
            return result;
        }
        if (registryRenameContext != NULL) {
            SafeUploadStageWritersAttachMutatingIo(registryRenameContext, &mutatingIoContext);
            *CompletionContext = registryRenameContext;
            return FLT_PREOP_SUCCESS_WITH_CALLBACK;
        }
#endif
        *CompletionContext = mutatingIoContext != NULL ? mutatingIoContext : legacyContext;
        if (*CompletionContext != NULL) return FLT_PREOP_SUCCESS_WITH_CALLBACK;
        return result;
        }
    case IRP_MJ_SET_SECURITY:
        /* T10 (owner decision 2026-10-08): a permission, owner or audit change adds no content, so it is applied to the real file
         * or folder and Windows decides who may make it: the I/O manager checks WRITE_DAC, WRITE_OWNER or ACCESS_SYSTEM_SECURITY
         * on the handle. Staged handles never get here (owned-stream routing above), and their creates strip those rights, so the
         * private backing's ACL never changes; non-service opens of the private namespace are refused at create. */
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    case IRP_MJ_SET_EA:
        {
            PVOID mutatingIoContext = NULL;
            BOOLEAN trackedWriter = FALSE;
            if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO))
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            if (FLT_IS_FASTIO_OPERATION(Data)) return FLT_PREOP_DISALLOW_FASTIO;
            (VOID)SafeUploadStageWritersBeginMutatingIo(Data, Objects->Instance, Objects->FileObject,
                &mutatingIoContext, &trackedWriter);
            result = StagePhysicalMutationEx(Data, Objects, FALSE, trackedWriter, &mutatingIoContext);
            if (result != FLT_PREOP_SUCCESS_NO_CALLBACK) {
                SafeUploadStageWritersEndMutatingIo(mutatingIoContext);
                return result;
            }
            if (mutatingIoContext != NULL) {
                *CompletionContext = mutatingIoContext;
                return FLT_PREOP_SUCCESS_WITH_CALLBACK;
            }
            return result;
        }
    case IRP_MJ_FILE_SYSTEM_CONTROL:
#if SAFEUPLOAD_STAGING_PROTOTYPE
        {
            PVOID mutatingIoContext = NULL;
            result = StageUnownedMutatingFsctl(Data, Objects, &mutatingIoContext);
            if (result != FLT_PREOP_SUCCESS_NO_CALLBACK) {
                SafeUploadStageWritersEndMutatingIo(mutatingIoContext);
                return result;
            }
            if (mutatingIoContext != NULL) {
                *CompletionContext = mutatingIoContext;
                return FLT_PREOP_SUCCESS_WITH_CALLBACK;
            }
        }
#endif
        break;
    case IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION:
    case IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION:
#if SAFEUPLOAD_STAGING_PROTOTYPE
        if (Data->Iopb->MajorFunction == IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION) {
            NTSTATUS sectionStatus;
            /* Reserve C before scope/name/SOP admission. If this request passed
             * the old gate, promotion must observe it; if the gate wins first,
             * admission below refuses it. */
            sectionStatus = SafeUploadStageSectionAcquired(Data, Objects, &sectionInFlight);
            if (!NT_SUCCESS(sectionStatus)) return StageCompleteAccessDenied(Data);
            result = StageUnownedWritableSection(Data, Objects);
            if (result != FLT_PREOP_SUCCESS_NO_CALLBACK) {
                if (sectionInFlight != NULL) SafeUploadStageSectionAcquireFailed(sectionInFlight);
                return result;
            }
            StageTraceWritableCreateSection(Data, Objects);
        } else {
            SafeUploadStageSectionReleasePrepare(Data, Objects->Instance, &sectionInFlight);
        }
        {
            LONG traceState = SafeUploadAdmissionTraceControlState;
            if ((traceState & 1) != 0 && SafeUploadAdmissionTraceSectionEvents != 0 &&
                SafeUploadStageAdmissionTraceBegin(traceState)) {
                SAFEUPLOAD_ADMISSION_TRACE_ENTRY entry;

                StageAdmissionTraceFillOperation(&entry, Data, Objects,
                    Data->Iopb->MajorFunction == IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION ?
                        SAFEUPLOAD_ADMISSION_TRACE_EVENT_SECTION_ACQUIRE :
                        SAFEUPLOAD_ADMISSION_TRACE_EVENT_SECTION_RELEASE,
                    FALSE);
                entry.MmDoesResult = SAFEUPLOAD_ADMISSION_TRACE_MMDOES_SKIPPED;
                if (Data->Iopb->MajorFunction == IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION) {
                    entry.SyncType = (UINT32)Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType;
                    entry.PageProtection = Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection;
                    entry.SyncParametersValid = 1;
                } else {
                    entry.SyncType = SAFEUPLOAD_ADMISSION_TRACE_SYNC_UNAVAILABLE;
                    entry.SyncParametersValid = 0;
                }
                SafeUploadStageAdmissionTraceRecord(&entry);
                SafeUploadStageAdmissionTraceEnd();
            }
        }
        if (sectionInFlight || Data->Iopb->MajorFunction == IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION) {
            /* A post-operation callback removes the entry if the acquire fails below us (no release follows). */
            *CompletionContext = sectionInFlight;
            return FLT_PREOP_SUCCESS_WITH_CALLBACK;
        }
#endif
        break;
    default: break;
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_PREOP_CALLBACK_STATUS StageDispatchEpoch(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, PVOID *CompletionContext)
{
    STAGE_ADMISSION_TOKEN_SLOT slot;
    *CompletionContext = NULL;
    RtlZeroMemory(&slot, sizeof(slot));
    slot.Owner = StageAdmissionTokenDispatch;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    PSAFEUPLOAD_ADMISSION_EPOCH_TOKEN token = NULL;
    PVOID innerContext = NULL;
    FLT_PREOP_CALLBACK_STATUS result;
    NTSTATUS status;
    slot.DirectorySequence = InterlockedCompareExchange64(&StageDirectorySequence, 0, 0);
    /* Exact native/combined disposition owns its epoch only after its shared
     * turn arrives. Generic policy quiescence must not count a queued delete
     * against the publication which that very delete is waiting for. */
    if (Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION &&
        !SafeUploadStageTxfSetInformationMustRefuse(Data, Objects)) {
        BOOLEAN handled;
        result = SafeUploadStagePublicDispositionPre(Data, Objects, CompletionContext, &handled);
        if (handled) return result;
        {
            PSTAGE_STREAM stream = StageStreamForObject(Objects->FileObject);
            FILE_INFORMATION_CLASS information = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
            if (stream != NULL && stream->BoundAllocation && stream->Sealed &&
                (information == FileDispositionInformation || information == FileDispositionInformationEx))
                return StagePreOperation(Data, Objects, CompletionContext, &slot);
        }
    }
    /* Boot-path invariant: the boot snapshot scopes mutation only. Reads,
     * image loads, and executes outside it do not acquire an epoch or enter
     * Activating denial; loss of an epoch token cannot widen the scope gate. */
    if (!StageEpochOperation(Data)) {
        return StageDispatchCore(Data, Objects, CompletionContext, &slot);
    }
    /* Fast I/O has no post-operation slot in which to retain an epoch token. */
    if (FLT_IS_FASTIO_OPERATION(Data)) return FLT_PREOP_DISALLOW_FASTIO;
    status = SafeUploadPolicyAdmissionAcquire(&token);
    if (!NT_SUCCESS(status)) {
        /* An epoch serializes a policy swap; it is not an authorization result.
         * If it is unavailable, refuse only an operation that can reach the
         * current/pending protected union. Clearly out-of-scope mutations keep
         * flowing, including during early boot before the service connects. */
        if (StageEpochOperationTouchesUnion(Data, Objects)) {
            if (SafeUploadPolicyAdmissionMustRetry()) return StageCompleteEpochRetry(Data);
            return StageCompleteAccessDenied(Data);
        }
        SafeUploadBoundPublicationNamespaceCoverageLost();
        result = StageDispatchCore(Data, Objects, &innerContext, &slot);
        *CompletionContext = innerContext;
        return result;
    }
    if (SafeUploadPolicyAdmissionMustRetry() && StageEpochOperationTouchesUnion(Data, Objects)) {
        SafeUploadPolicyAdmissionRelease(token);
        *CompletionContext = NULL;
        return StageCompleteEpochRetry(Data);
    }
    slot.Token = token;
    result = StageDispatchCore(Data, Objects, &innerContext, &slot);
    if (result == FLT_PREOP_PENDING) {
        /* Pending owners take the token before the callback returns. The
         * attach queue additionally waits for this producer-side handoff. */
        if (slot.Owner == StageAdmissionTokenAttach && slot.Transaction != NULL &&
            slot.Token == NULL) {
            StageAttachCommitPreOpReturn((PSTAGE_ATTACH_TRANSACTION)slot.Transaction);
            slot.Transaction = NULL;
        } else if (slot.Owner != StageAdmissionTokenPaging || slot.Token != NULL) {
            SafeUploadPolicyAdmissionRelease((PSAFEUPLOAD_ADMISSION_EPOCH_TOKEN)slot.Token);
            slot.Token = NULL;
            Data->IoStatus.Status = STATUS_DEVICE_NOT_READY;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
        *CompletionContext = NULL;
        return result;
    }
    if (result == FLT_PREOP_SUCCESS_NO_CALLBACK || result == FLT_PREOP_SUCCESS_WITH_CALLBACK ||
        result == FLT_PREOP_SYNCHRONIZE) {
        if (slot.Token == NULL) {
            Data->IoStatus.Status = STATUS_DEVICE_NOT_READY;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
        slot.Owner = StageAdmissionTokenPostOperation;
        token = (PSAFEUPLOAD_ADMISSION_EPOCH_TOKEN)slot.Token;
        token->InnerCompletionContext = innerContext;
        token->OperationKind = Data->Iopb->MajorFunction |
            (slot.DirectoryCollision ? STAGE_EPOCH_DIRECTORY_COLLISION : 0);
        token->DirectoryMutation = slot.DirectoryMutation;
        *CompletionContext = (PVOID)((ULONG_PTR)token | 1);
        /* Even an otherwise no-callback pass-through holds its epoch through lower completion. */
        return result == FLT_PREOP_SYNCHRONIZE ? FLT_PREOP_SYNCHRONIZE : FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }
    if (slot.DirectoryMutation) StageDirectoryEndMutation(FALSE);
    SafeUploadPolicyAdmissionRelease((PSAFEUPLOAD_ADMISSION_EPOCH_TOKEN)slot.Token);
    slot.Token = NULL;
    *CompletionContext = NULL;
    return result;
#else
    return StageDispatchCore(Data, Objects, CompletionContext, &slot);
#endif
}

/* The choke point for refusals: every operation is registered through here, so an operation this driver completes
 * itself with an error status is noted in the deny ring whichever code path chose it. */
FLT_PREOP_CALLBACK_STATUS SafeUploadStageDispatch(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, PVOID *CompletionContext)
{
    FLT_PREOP_CALLBACK_STATUS result;

#if SAFEUPLOAD_STAGING_PROTOTYPE
    /* FltStartFiltering may present callbacks before it returns. A CREATE
     * cannot reach epoch admission, writer reservation, or StageCreate until
     * DriverEntry publishes successful startup. On start failure the gate is
     * never opened, so no staged FILE_OBJECT can retain instance references
     * across the DriverEntry unregister/free path. */
    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE &&
        (InterlockedCompareExchange(&StageFilteringReady, 0, 0) == 0 ||
         (InterlockedCompareExchange(&StageUnloadAdmissionClosed, 0, 0) != 0 &&
          !(SafeUploadIsAuthenticatedClient() &&
            FltGetRequestorProcessId(Data) == SafeUploadData.InspectorProcessId)) ||
         SafeUploadStageMandatoryTeardownActive())) {
        *CompletionContext = NULL;
        Data->IoStatus.Status = STATUS_DEVICE_NOT_READY;
        Data->IoStatus.Information = 0;
        result = FLT_PREOP_COMPLETE;
    } else {
        result = StageDispatchEpoch(Data, Objects, CompletionContext);
    }
#else
    result = StageDispatchEpoch(Data, Objects, CompletionContext);
#endif

    if (result == FLT_PREOP_COMPLETE) SafeUploadDenyNote(Data, Objects, Data->IoStatus.Status, FALSE);
    return result;
}

static FLT_POSTOP_CALLBACK_STATUS StagePostOperationCore(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
#if SAFEUPLOAD_STAGING_PROTOTYPE
    /* A directory completion or an independent reader's last cleanup can
     * remove a previously pending original link. Coalesce through the native
     * map revision/worker; do not perform observations or RPC in this callback.
     * Observer-owned directory CLEANUP must not trigger a replay feedback loop. */
    if (!FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) &&
        ((Data->Iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL &&
          Data->Iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY && NT_SUCCESS(Data->IoStatus.Status)) ||
         (Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION && Data->IoStatus.Status == STATUS_SUCCESS &&
          FltGetRequestorProcessId(Data) != SafeUploadData.InspectorProcessId) ||
         (Data->Iopb->MajorFunction == IRP_MJ_CLEANUP &&
          FltGetRequestorProcessId(Data) != SafeUploadData.InspectorProcessId)))
        SafeUploadStageNativeNameChanged(Objects->Instance);
    if (CompletionContext == (PVOID)&StageMvpNamespaceCompletionTag) {
        StageMvpNamespacePost(Data, Objects, Flags);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (SafeUploadBoundPublicationPost(Data, Objects, CompletionContext, Flags))
        return FLT_POSTOP_FINISHED_PROCESSING;
    if (Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION &&
        SafeUploadStagePublicDispositionPost(Data, Objects, CompletionContext, Flags))
        return FLT_POSTOP_FINISHED_PROCESSING;
    if (Data->Iopb->MajorFunction == IRP_MJ_CLOSE &&
        SafeUploadStageNativePostClose(Data, Objects, CompletionContext, Flags))
        return FLT_POSTOP_FINISHED_PROCESSING;
    if (Data->Iopb->MajorFunction == IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION && CompletionContext != NULL) {
        if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
            /* Outcome unavailable while draining: keep the entry and make writer state Unknown. */
            SafeUploadStageSectionAcquireDraining(Objects->Instance, CompletionContext);
        } else if (!NT_SUCCESS(Data->IoStatus.Status)) {
            /* The acquire failed below us: no release follows, so drop the in-flight entry here. */
            SafeUploadStageSectionAcquireFailed(CompletionContext);
        } else {
            SafeUploadStageSectionAcquireComplete(CompletionContext);
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION &&
        SafeUploadStageWritersIsRenameContext(CompletionContext)) {
        SafeUploadStageWritersSetMutatingIoCompletion(CompletionContext, Data, Flags);
        SafeUploadStageWritersCompleteRename(Objects->Instance, CompletionContext,
            !FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) && Data->IoStatus.Status == STATUS_SUCCESS,
            FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING));
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if ((Data->Iopb->MajorFunction == IRP_MJ_WRITE ||
         Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION ||
         Data->Iopb->MajorFunction == IRP_MJ_SET_EA ||
         Data->Iopb->MajorFunction == IRP_MJ_SET_SECURITY ||
         Data->Iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
        SafeUploadStageWritersIsMutatingIoContext(CompletionContext)) {
        /* Includes ordinary success/failure and POST_OPERATION_DRAINING. */
        SafeUploadStageWritersSetMutatingIoCompletion(CompletionContext, Data, Flags);
        SafeUploadStageWritersEndMutatingIo(CompletionContext);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (Data->Iopb->MajorFunction == IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION) {
        SafeUploadStageSectionReleaseComplete(Objects->Instance, CompletionContext,
            !FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) && NT_SUCCESS(Data->IoStatus.Status),
            FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING));
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (Data->Iopb->MajorFunction == IRP_MJ_CLEANUP) {
        SafeUploadStageNativePostCleanup(Data, Objects, Flags);
        if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
            SafeUploadStageWritersMutationDraining(Objects->Instance,
                Objects->FileObject != NULL ? Objects->FileObject->SectionObjectPointer : NULL);
        } else if (NT_SUCCESS(Data->IoStatus.Status)) {
            SafeUploadStageWritersOnCleanup(Data, Objects);
            SafeUploadStageWritersQueueLifetimeRecheck(Objects->Instance, Objects->FileObject);
        }
    }
#endif
    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
#if SAFEUPLOAD_STAGING_PROTOTYPE
        if (SafeUploadStageNativePostCreate(Data, Objects, CompletionContext, Flags))
            return FLT_POSTOP_FINISHED_PROCESSING;
        if (SafeUploadStageWritersIsReservation(CompletionContext)) {
            PVOID legacyCompletionContext = NULL;
            BOOLEAN legacyCallbackRequired = FALSE;
            NTSTATUS writerStatus = SafeUploadStageWritersPostCreate(Data, Objects, Flags,
                CompletionContext, &legacyCompletionContext, &legacyCallbackRequired);
            if (!NT_SUCCESS(writerStatus)) return FLT_POSTOP_FINISHED_PROCESSING;
            if (legacyCallbackRequired)
                return SafeUploadPostCreate(Data, Objects, legacyCompletionContext, Flags);
            return FLT_POSTOP_FINISHED_PROCESSING;
        }
#endif
        return SafeUploadPostCreate(Data, Objects, CompletionContext, Flags);
    }
    if (CompletionContext != NULL) {
        PSTAGE_STREAM stream = CompletionContext;
        ExReleaseRundownProtection(&stream->PagingRundown);
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS SafeUploadStagePostOperation(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
#if SAFEUPLOAD_STAGING_PROTOTYPE
    /* Epoch tokens are pool allocations. A context that is not a system-range address is
     * an inner context passed through unwrapped (operations outside the epoch, or a failed
     * epoch acquire): the legacy create passes its volume kind (1 fixed, 2 removable,
     * 3 network, optionally | SAFEUPLOAD_POSTCREATE_OVERRIDE), whose low bits collide with
     * the token tags (run c01g: bugcheck 0x3B dereferencing token (1 & ~1) == NULL). */
    BOOLEAN systemAddress = (ULONG_PTR)CompletionContext >= (ULONG_PTR)MmSystemRangeStart;
    /* Draining can run at DISPATCH_LEVEL: do not inspect CREATE security
     * context or other paged preoperation input merely to classify loss. */
    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) &&
        (Data->Iopb->MajorFunction == IRP_MJ_CREATE || Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION ||
         Data->Iopb->MajorFunction == IRP_MJ_SET_SECURITY || Data->Iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL ||
         Data->Iopb->MajorFunction == IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION))
        SafeUploadBoundPublicationNamespaceCoverageLost();
    if (systemAddress && ((ULONG_PTR)CompletionContext & 1) != 0) {
        PSAFEUPLOAD_ADMISSION_EPOCH_TOKEN token = (PSAFEUPLOAD_ADMISSION_EPOCH_TOKEN)
            ((ULONG_PTR)CompletionContext & ~(ULONG_PTR)1);
        FLT_POSTOP_CALLBACK_STATUS result;
        if (token->Signature == SAFEUPLOAD_ADMISSION_EPOCH_TOKEN_SIGNATURE) {
            if (FlagOn(token->OperationKind, STAGE_EPOCH_DIRECTORY_COLLISION)) {
                /* The documented post-CREATE exception guarantees PASSIVE,
                 * including this CREATE-only context's cleanup on drain. Close
                 * before dropping the epoch; preserve the lower result. */
                NT_ASSERT(Data->Iopb->MajorFunction == IRP_MJ_CREATE && KeGetCurrentIrql() == PASSIVE_LEVEL);
                StageDirectoryCollisionComplete((HANDLE)token->InnerCompletionContext);
                token->InnerCompletionContext = NULL;
                SafeUploadPolicyAdmissionRelease(token);
                return FLT_POSTOP_FINISHED_PROCESSING;
            }
            if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING))
                SafeUploadStageWritersMutationDraining(Objects->Instance,
                    Objects->FileObject != NULL ? Objects->FileObject->SectionObjectPointer : NULL);
            result = StagePostOperationCore(Data, Objects, token->InnerCompletionContext, Flags);
            if (token->DirectoryMutation)
                StageDirectoryEndMutation(FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING));
            SafeUploadPolicyAdmissionRelease(token);
            return result;
        }
    }
    if (systemAddress && ((ULONG_PTR)CompletionContext & 0x3) == 0x2) {
        SafeUploadPolicyAdmissionRelease(
            (PSAFEUPLOAD_ADMISSION_EPOCH_TOKEN)CompletionContext);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
#endif
    return StagePostOperationCore(Data, Objects, CompletionContext, Flags);
}

static BOOLEAN StageDirectoryChild(PUNICODE_STRING Directory, PUNICODE_STRING Name, PUNICODE_STRING Child)
{
    USHORT i, offset = Directory->Length;
    UNICODE_STRING prefix = *Name;
    if (Name->Length <= offset || Name->Buffer[offset / sizeof(WCHAR)] != L'\\') return FALSE;
    prefix.Length = offset;
    if (!RtlEqualUnicodeString(Directory, &prefix, TRUE)) return FALSE;
    offset += sizeof(WCHAR);
    Child->Buffer = (PWCH)((PUCHAR)Name->Buffer + offset);
    Child->Length = Child->MaximumLength = Name->Length - offset;
    for (i = 0; i < Child->Length / sizeof(WCHAR); ++i) if (Child->Buffer[i] == L'\\') return FALSE;
    return Child->Length != 0;
}

BOOLEAN SafeUploadProcessHasMappings(_In_ ULONG Owner)
{
    PEPROCESS process = NULL;
    PLIST_ENTRY link;
    BOOLEAN found = FALSE;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(ULongToHandle(Owner), &process))) return FALSE;
    StageAcquire(&StageNamespaceResource);
    /* The owner's private namespace: attached views and the names it renamed away. A detached view no longer names anything,
     * and its current version may already be released (T4). */
    for (link = StageViews.Flink; link != &StageViews && !found; link = link->Flink)
        found = CONTAINING_RECORD(link, STAGE_VIEW, Link)->Owner == process &&
            !CONTAINING_RECORD(link, STAGE_VIEW, Link)->Detached;
    for (link = StageTombstones.Flink; link != &StageTombstones && !found; link = link->Flink)
        found = CONTAINING_RECORD(link, STAGE_TOMBSTONE, Link)->Owner == process;
    StageRelease(&StageNamespaceResource);
    ObDereferenceObject(process);
    return found;
}

static NTSTATUS StageAddOverlay(PLIST_ENTRY Overlays, PUNICODE_STRING Name, PSTAGE_STREAM Stream)
{
    PSAFEUPLOAD_DIRECTORY_OVERLAY overlay = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*overlay) + Name->Length, SAFEUPLOAD_POOL_TAG);
    NTSTATUS status = STATUS_SUCCESS;
    if (overlay == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    overlay->Deleted = Stream == NULL;
    overlay->Name.Buffer = (PWCH)(overlay + 1);
    overlay->Name.Length = overlay->Name.MaximumLength = Name->Length;
    RtlCopyMemory(overlay->Name.Buffer, Name->Buffer, Name->Length);
    if (Stream != NULL) {
        StageAcquire(&Stream->Resource);
        status = Stream->BackingObject == NULL ? STATUS_DEVICE_BUSY :
            FltQueryInformationFile(Stream->BackingInstance, Stream->BackingObject,
            &overlay->Basic, sizeof(overlay->Basic), FileBasicInformation, NULL);
        overlay->Standard.EndOfFile = Stream->Header.FileSize;
        overlay->Standard.AllocationSize = Stream->Header.AllocationSize;
        overlay->Standard.NumberOfLinks = 1;
        overlay->ExtendedId = Stream->View->Identity.FileId;
        StageRelease(&Stream->Resource);
    }
    if (NT_SUCCESS(status)) InsertTailList(Overlays, &overlay->Link);
    else ExFreePoolWithTag(overlay, SAFEUPLOAD_POOL_TAG);
    return status;
}

NTSTATUS SafeUploadCollectDirectoryOverlay(_In_ ULONG Owner, _In_ PUNICODE_STRING Directory, _Inout_ PLIST_ENTRY Overlays)
{
    PEPROCESS process = NULL;
    PLIST_ENTRY link, old;
    UNICODE_STRING child;
    NTSTATUS status;
    /* Directory handles do not contribute to a stage's FileObjects count,
     * but StageAddOverlay queries its backing after that count reaches zero. */
    if (!ExAcquireRundownProtection(&StageOwnedCallbackBodies)) return STATUS_FLT_DELETING_OBJECT;
    status = PsLookupProcessByProcessId(ULongToHandle(Owner), &process);
    if (!NT_SUCCESS(status)) {
        ExReleaseRundownProtection(&StageOwnedCallbackBodies);
        return status;
    }
    StageAcquire(&StageNamespaceResource);
    for (old = StageTombstones.Flink; old != &StageTombstones; old = old->Flink) {
        PSTAGE_TOMBSTONE hidden = CONTAINING_RECORD(old, STAGE_TOMBSTONE, Link);
        if (hidden->Owner == process && StageFindView(process, &hidden->Name) == NULL &&
            StageDirectoryChild(Directory, &hidden->Name, &child)) {
            status = StageAddOverlay(Overlays, &child, NULL);
            if (!NT_SUCCESS(status)) goto Exit;
        }
    }
    for (link = StageViews.Flink; link != &StageViews; link = link->Flink) {
        PSTAGE_VIEW view = CONTAINING_RECORD(link, STAGE_VIEW, Link);
        if (view->Owner != process) continue;
        if (!view->Detached && StageDirectoryChild(Directory, &view->Name, &child)) {
            status = StageAddOverlay(Overlays, &child, view->Current);
            if (!NT_SUCCESS(status)) goto Exit;
        }
    }
Exit:
    StageRelease(&StageNamespaceResource);
    ObDereferenceObject(process);
    ExReleaseRundownProtection(&StageOwnedCallbackBodies);
    return status;
}

BOOLEAN SafeUploadHasDirectoryOverlay(_In_ ULONG Owner, _In_ PUNICODE_STRING Directory)
{
    PEPROCESS process = NULL;
    PLIST_ENTRY link, old;
    UNICODE_STRING child;
    BOOLEAN found = FALSE;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(ULongToHandle(Owner), &process))) return FALSE;
    StageAcquire(&StageNamespaceResource);
    for (link = StageViews.Flink; link != &StageViews && !found; link = link->Flink) {
        PSTAGE_VIEW view = CONTAINING_RECORD(link, STAGE_VIEW, Link);
        found = view->Owner == process && !view->Detached && StageDirectoryChild(Directory, &view->Name, &child);
    }
    for (old = StageTombstones.Flink; old != &StageTombstones && !found; old = old->Flink) {
        PSTAGE_TOMBSTONE hidden = CONTAINING_RECORD(old, STAGE_TOMBSTONE, Link);
        found = hidden->Owner == process && StageDirectoryChild(Directory, &hidden->Name, &child);
    }
    StageRelease(&StageNamespaceResource);
    ObDereferenceObject(process);
    return found;
}

#if SAFEUPLOAD_STAGING_PROTOTYPE
#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SafeUploadStagePublicationAcquireSource)
#pragma alloc_text(PAGE, SafeUploadStagePublicationSourceCurrent)
#pragma alloc_text(PAGE, SafeUploadStagePublicationReleaseSource)
#endif
/* NamespaceResource protects lookup and acquisition. RpcReferences prevents
 * StageTryReleaseStream from unlinking the version after the lock drops. */
_Use_decl_annotations_
NTSTATUS SafeUploadStagePublicationAcquireSource(const SAFEUPLOAD_BOUND_PUBLICATION_REQUEST *Request,
    PSAFEUPLOAD_PUBLICATION_SOURCE Source)
{
    PLIST_ENTRY link;
    PSTAGE_STREAM found = NULL;
    NTSTATUS status = STATUS_DEVICE_NOT_READY;
    PAGED_CODE();
    RtlZeroMemory(Source, sizeof(*Source));
    StageAcquire(&StageNamespaceResource);
    if (!StageStopping && !SafeUploadStageMandatoryTeardownActive()) {
        for (link = StageStreams.Flink; link != &StageStreams; link = link->Flink) {
            PSTAGE_STREAM stream = CONTAINING_RECORD(link, STAGE_STREAM, Link);
            if (!stream->BoundAllocation || !stream->HasTransferId || !stream->StageIdentityValid ||
                !RtlEqualMemory(&stream->TransferId, &Request->TransferId, sizeof(GUID)) ||
                !RtlEqualMemory(&stream->DriverInstanceId, &Request->DriverInstanceId, sizeof(GUID)) ||
                stream->DestinationGeneration != (UINT64)Request->DestinationGeneration ||
                !StageV19IdentityEqual(&stream->StageIdentity, &Request->StageIdentity)) continue;
            StageAcquire(&stream->Resource);
            if (!stream->Sealed || stream->Discarded || stream->DiscardOnClose || stream->Disposed ||
                stream->Header.FileSize.QuadPart != Request->MeasuredLength ||
                !StageBoundSeedReady(stream) || stream->PublicationWriterLease == NULL || !stream->PublicationEvidenceClosed ||
                stream->RenameExchange != NULL || stream->RenameRpcInFlight || stream->DiscardRpcInFlight ||
                stream->SeedCompletion.AuthorityRevision != SafeUploadStageProtocolNativeAuthority()) {
                StageRelease(&stream->Resource);
                break;
            }
            InterlockedIncrement(&stream->RpcReferences);
            found = stream;
            Source->Version = stream;
            Source->Writer = stream->PublicationWriterLease;
            Source->SectorSize = stream->SectorSize;
            StageRelease(&stream->Resource);
            break;
        }
    }
    StageRelease(&StageNamespaceResource);
    if (found != NULL) status = SafeUploadStagePublicPublicationSecurity(Source->Writer, Request, Source);
    else SafeUploadStagePublicRecordWriterRefusal(StageWriterNativeCreateSecurityUnproved);
    if (status != STATUS_SUCCESS) SafeUploadStagePublicationReleaseSource(Source);
    return status;
}

_Use_decl_annotations_
BOOLEAN SafeUploadStagePublicationSourceCurrent(const SAFEUPLOAD_BOUND_PUBLICATION_REQUEST *Request,
    const SAFEUPLOAD_PUBLICATION_SOURCE *Source)
{
    PSTAGE_STREAM stream = Source->Version;
    BOOLEAN current;
    PAGED_CODE();
    if (stream == NULL || Source->Writer == NULL) return FALSE;
    StageAcquire(&StageNamespaceResource);
    StageAcquire(&stream->Resource);
    current = !StageStopping && !SafeUploadStageMandatoryTeardownActive() && stream->Sealed && stream->PublicationEvidenceClosed &&
        !stream->Disposed && !stream->Discarded && !stream->DiscardOnClose && StageBoundSeedReady(stream) &&
        stream->Header.FileSize.QuadPart == Request->MeasuredLength &&
        stream->DestinationGeneration == (UINT64)Request->DestinationGeneration &&
        StageV19IdentityEqual(&stream->StageIdentity, &Request->StageIdentity) &&
        stream->SeedCompletion.AuthorityRevision == SafeUploadStageProtocolNativeAuthority();
    StageRelease(&stream->Resource);
    StageRelease(&StageNamespaceResource);
    return current && SafeUploadStagePublicPublicationCurrent(Source->Writer);
}

_Use_decl_annotations_
VOID SafeUploadStagePublicationReleaseSource(PSAFEUPLOAD_PUBLICATION_SOURCE Source)
{
    PSTAGE_STREAM stream = Source->Version;
    PAGED_CODE();
    if (Source->Root != NULL) ObDereferenceObject(Source->Root);
    if (Source->Parent != NULL) ObDereferenceObject(Source->Parent);
    if (Source->Instance != NULL) FltObjectDereference(Source->Instance);
    if (Source->Construction != NULL) ExFreePoolWithTag(Source->Construction, 'bUpS');
    if (Source->Stored != NULL) ExFreePoolWithTag(Source->Stored, 'bUpS');
    RtlZeroMemory(Source, sizeof(*Source));
    if (stream != NULL) {
        StageAcquire(&StageNamespaceResource);
        if (InterlockedDecrement(&stream->RpcReferences) == 0 && !SafeUploadStageMandatoryTeardownActive())
            StageQueueStream(stream, &StageCounters.WakeInline);
        StageRelease(&StageNamespaceResource);
    }
}
#endif
