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
#define SAFEUPLOAD_TX_ASSOC_PENDING 0
#define SAFEUPLOAD_TX_ASSOC_ENLISTED 1
#define SAFEUPLOAD_TX_ASSOC_TERMINAL 2
#define SAFEUPLOAD_TX_ASSOC_FAILED 3
#define SAFEUPLOAD_CUTOFF_PAGING_DRAIN_TIMEOUT_100NS (30LL * 10 * 1000 * 1000)

typedef struct _STAGE_REGISTRY_ENTRY STAGE_REGISTRY_ENTRY, *PSTAGE_REGISTRY_ENTRY;

typedef struct _STAGE_WRITER_NODE {
    LIST_ENTRY Link;
    PFILE_OBJECT FileObject;        /* identity token only */
    PSTAGE_REGISTRY_ENTRY Entry;    /* referenced until this exact node is cleaned up */
    ULONG ProcessId;
} STAGE_WRITER_NODE, *PSTAGE_WRITER_NODE;

struct _STAGE_REGISTRY_ENTRY {
    LIST_ENTRY Link;
    volatile LONG References;
    volatile LONG H;
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
    ULONG FirstSeenGeneration;
    ULONG State;
    ULONG ActivationGeneration;
    volatile LONG ActivationEnforced;
    volatile LONG CutoffStarted;
    volatile LONG CutoffComplete;
    volatile LONG CutoffFailed;
    volatile LONG PagingWriteGateClosed;
    volatile LONG PagingWritesInFlight;
    volatile LONG CutoffFlushPairs;
    volatile LONG DirtyAfterCutoff; /* Sticky until reboot; a later scope expansion cannot promote this stream. */
    volatile LONG StuckSProbe;
    volatile LONG LastSState;
    ULONGLONG Sequence;
    USHORT NameChars;
    BOOLEAN Listed;
    BOOLEAN Retired;
    KSPIN_LOCK HolderLock;
    KSPIN_LOCK PagingWriteLock;
    KEVENT PagingWritesDrained;
    ULONG OpenerPidCount;
    ULONG OpenerPids[8];
    ULONG OpenerPidReferences[8];
    WCHAR Name[SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS];
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
    BOOLEAN SlotReserved;
    BOOLEAN NameReserved;
    BOOLEAN Active;
    BOOLEAN LegacyCallbackRequired;
    BOOLEAN InstanceReferenceTransferred;
    BOOLEAN VolumeReferenceTransferred;
    volatile LONG TeardownState;
} STAGE_WRITER_RESERVATION, *PSTAGE_WRITER_RESERVATION;

typedef struct _STAGE_REGISTRY_RENAME_CONTEXT {
    ULONG Signature;
    PSTAGE_REGISTRY_ENTRY Entry; /* referenced through the set-information post-operation */
    ULONG NameChars;
    BOOLEAN LinkOperation;
    BOOLEAN Ambiguous;
    WCHAR Name[SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS];
} STAGE_REGISTRY_RENAME_CONTEXT, *PSTAGE_REGISTRY_RENAME_CONTEXT;

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
} STAGE_REGISTRY_SOP_SLOT, *PSTAGE_REGISTRY_SOP_SLOT;

typedef struct _STAGE_DEFERRED_INSTANCE_UNKNOWN {
    PFLT_INSTANCE Instance;         /* temporary rundown reference for direct instance losses */
    PSTAGE_REGISTRY_ENTRY Entry;    /* referenced until the worker safely reads its live Instance */
    LONG Reason;
} STAGE_DEFERRED_INSTANCE_UNKNOWN, *PSTAGE_DEFERRED_INSTANCE_UNKNOWN;

static BOOLEAN StageRegistryEntryQuiescent(_In_ PSTAGE_REGISTRY_ENTRY Entry, _In_ PFLT_INSTANCE Instance,
    _In_ PFLT_VOLUME Volume);
static NTSTATUS StageRegistryOpenIdentity(_In_ PSTAGE_REGISTRY_ENTRY Entry,
    _In_ PFLT_INSTANCE Instance, _In_ PFLT_VOLUME Volume, _Out_ PHANDLE Handle,
    _Outptr_result_nullonfailure_ PFILE_OBJECT *Object);
static VOID StageRegistryActivationProcess(_In_ PSTAGE_REGISTRY_ENTRY Entry,
    _In_ PFLT_INSTANCE Instance, _In_ PFLT_VOLUME Volume);
static NTSTATUS StageRegistryWaitPagingWritesDrained(_In_ PSTAGE_REGISTRY_ENTRY Entry);
static VOID StageRegistryReclaimWorker(_In_ PFLT_GENERIC_WORKITEM WorkItem, _In_ PVOID FltObject,
    _In_opt_ PVOID Context);
static VOID StageRegistryUnknownWorker(_In_ PFLT_GENERIC_WORKITEM WorkItem, _In_ PVOID FltObject,
    _In_opt_ PVOID Context);
static BOOLEAN StageRegistryQueueInstanceUnknown(_In_ PFLT_INSTANCE Instance, _In_ LONG Reason);
static BOOLEAN StageRegistryQueueEntryUnknown(_In_ PSTAGE_REGISTRY_ENTRY Entry, _In_ LONG Reason);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SafeUploadStageWritersApplyPendingScope)
#pragma alloc_text(PAGE, SafeUploadStageWritersReconcileCurrentScope)
#pragma alloc_text(PAGE, SafeUploadStageWritersActivatingStatusPage)
#pragma alloc_text(PAGE, StageRegistryEntryQuiescent)
#pragma alloc_text(PAGE, StageRegistryOpenIdentity)
#pragma alloc_text(PAGE, StageRegistryActivationProcess)
#pragma alloc_text(PAGE, StageRegistryWaitPagingWritesDrained)
#pragma alloc_text(PAGE, StageRegistryReclaimWorker)
#pragma alloc_text(PAGE, StageRegistryUnknownWorker)
#endif

static EX_PUSH_LOCK RegistryLock;
static LIST_ENTRY RegistryEntries;
static LIST_ENTRY RegistryReservations;
static LIST_ENTRY TransactionAssociations;
static ULONG RegistryEntryCount;
static ULONG RegistryReservationCount;
static ULONG RegistryReservedSlots;
static ULONG RegistryNameBytes;
static ULONG RegistryReservedNameBytes;
static ULONG RegistryAssociationCount;
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
static volatile LONG RegistryReclaimRescan;
static ULONGLONG RegistryEntrySequence;
static ULONGLONG RegistryReclaimCursor;
static BOOLEAN StageRegistryQueueReclaim(VOID);
static STAGE_REGISTRY_SOP_SLOT RegistrySopSlots[SAFEUPLOAD_WRITER_REGISTRY_TOTAL_LIMIT];
static VOID StageRegistryRetireInstance(_In_ PFLT_INSTANCE Instance, _In_ BOOLEAN Dismount);
static VOID StageRegistryBeginInstanceTeardown(_In_ PFLT_INSTANCE Instance,
    _In_opt_ PSAFEUPLOAD_INSTANCE_TEARDOWN_TOKEN Token, _In_ BOOLEAN Dismount);
static VOID StageRegistryAssociationDereference(_In_opt_ PSTAGE_TX_ASSOCIATION Association);
__declspec(noinline) static UINT32 StageRegistrySnapshotC(_In_ PSTAGE_REGISTRY_ENTRY Entry,
    _Out_writes_opt_(Capacity) PUINT32 ProcessIds, _In_ ULONG Capacity,
    _Out_opt_ PUINT32 ProcessIdCount);

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

static VOID StageRegistryReference(_In_ PSTAGE_REGISTRY_ENTRY Entry)
{
    InterlockedIncrement(&Entry->References);
}

static VOID StageRegistryDereference(_In_opt_ PSTAGE_REGISTRY_ENTRY Entry)
{
    if (Entry == NULL) return;
    if (InterlockedDecrement(&Entry->References) == 0) {
        if (Entry->Volume != NULL) FltObjectDereference(Entry->Volume);
        if (Entry->Instance != NULL) FltObjectDereference(Entry->Instance);
        ExFreePoolWithTag(Entry, SAFEUPLOAD_REGISTRY_POOL_TAG);
    }
}

static VOID StageRegistryMarkUnknown(_In_opt_ PFLT_INSTANCE Instance,
    _In_ LONG Reason, _In_ BOOLEAN MachineWide)
{
    PSAFEUPLOAD_INSTANCE_CONTEXT context = NULL;
    BOOLEAN instanceMarked = FALSE;
    InterlockedOr((volatile LONG *)&RegistryUnknownReasons, Reason);
    if (Instance != NULL) {
        if (KeGetCurrentIrql() <= APC_LEVEL &&
            NT_SUCCESS(FltGetInstanceContext(Instance, (PFLT_CONTEXT *)&context))) {
            InterlockedOr(&context->RegistryUnknownReasons, Reason);
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
        (KeGetCurrentIrql() > APC_LEVEL && !instanceMarked))
        InterlockedExchange(&WriterGlobalUnknown, 1);
}

static VOID StageRegistryMarkEntryUnknown(_In_ PSTAGE_REGISTRY_ENTRY Entry, _In_ LONG Reason)
{
    InterlockedOr(&Entry->UnknownReasons, Reason);
    InterlockedExchange((volatile LONG *)&Entry->State, SAFEUPLOAD_REGISTRY_STATE_UNKNOWN);
    InterlockedIncrement64(&RegistryChangeSequence);
    /* Narrowest scope: a loss about this file (identity, transaction, section binding) stays on its entry, which is keyed by
     * file ID and can never be Free. Only a rename loss widens: the entry's name is then stale, and scope classification
     * matches by name, so this file could fall inside a newly added scope unmatched; the instance must be Unknown. */
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
    KeAcquireSpinLock(&Entry->HolderLock, &irql);
    for (index = 0; index < Entry->OpenerPidCount; ++index) {
        if (Entry->OpenerPids[index] == ProcessId) {
            if (Entry->OpenerPidReferences[index] != MAXULONG)
                Entry->OpenerPidReferences[index] += 1;
            InterlockedIncrement64(&RegistryChangeSequence);
            KeReleaseSpinLock(&Entry->HolderLock, irql);
            return;
        }
    }
    if (Entry->OpenerPidCount < RTL_NUMBER_OF(Entry->OpenerPids)) {
        Entry->OpenerPids[Entry->OpenerPidCount] = ProcessId;
        Entry->OpenerPidReferences[Entry->OpenerPidCount] = 1;
        Entry->OpenerPidCount += 1;
        InterlockedIncrement64(&RegistryChangeSequence);
    }
    KeReleaseSpinLock(&Entry->HolderLock, irql);
}

__declspec(noinline) static VOID StageRegistryRemoveOpener(_In_ PSTAGE_REGISTRY_ENTRY Entry, _In_ ULONG ProcessId)
{
    ULONG index;
    KIRQL irql;
    if (ProcessId == 0) return;
    KeAcquireSpinLock(&Entry->HolderLock, &irql);
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
    KeReleaseSpinLock(&Entry->HolderLock, irql);
}

/* ProcessIds and Count are resident scratch; pageable status buffers are filled after this returns. */
__declspec(noinline) static VOID StageRegistryCopyOpeners(_In_ PSTAGE_REGISTRY_ENTRY Entry,
    _Out_writes_(Capacity) PUINT32 ProcessIds, _In_ ULONG Capacity, _Out_ PUINT32 Count)
{
    ULONG index, copied;
    KIRQL irql;
    *Count = 0;
    KeAcquireSpinLock(&Entry->HolderLock, &irql);
    copied = min(Entry->OpenerPidCount, Capacity);
    for (index = 0; index < copied; ++index) ProcessIds[index] = Entry->OpenerPids[index];
    KeReleaseSpinLock(&Entry->HolderLock, irql);
    *Count = copied;
}

static PSTAGE_REGISTRY_ENTRY StageRegistryFindByKeyLocked(_In_ PFLT_INSTANCE Instance,
    _In_ PFLT_VOLUME Volume, _In_ ULONGLONG VolumeSerial, _In_ const FILE_ID_128 *FileId)
{
    PLIST_ENTRY link;
    for (link = RegistryEntries.Flink; link != &RegistryEntries; link = link->Flink) {
        PSTAGE_REGISTRY_ENTRY entry = CONTAINING_RECORD(link, STAGE_REGISTRY_ENTRY, Link);
        if (!entry->Retired && entry->Instance == Instance && entry->Volume == Volume &&
            entry->VolumeSerial == VolumeSerial &&
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
        if (!entry->Retired && entry->Instance == Instance) count += 1;
    }
    for (link = RegistryReservations.Flink; link != &RegistryReservations; link = link->Flink) {
        PSTAGE_WRITER_RESERVATION reserve = CONTAINING_RECORD(link, STAGE_WRITER_RESERVATION, Link);
        if (reserve->Active && reserve->SlotReserved && reserve->Instance == Instance) count += 1;
    }
    return count;
}

static VOID StageRegistryFinishReservationAccountingLocked(
    _Inout_ PSTAGE_WRITER_RESERVATION Reservation)
{
    if (!Reservation->Active) return;
    if (Reservation->SlotReserved && RegistryReservedSlots != 0) RegistryReservedSlots -= 1;
    Reservation->SlotReserved = FALSE;
    if (Reservation->NameReserved && RegistryReservedNameBytes >= Reservation->NameChars * sizeof(WCHAR))
        RegistryReservedNameBytes -= Reservation->NameChars * sizeof(WCHAR);
    Reservation->NameReserved = FALSE;
    RemoveEntryList(&Reservation->Link);
    if (RegistryReservationCount != 0) RegistryReservationCount -= 1;
    Reservation->Active = FALSE;
}

static VOID StageRegistryReleaseReservationCapacityLocked(
    _Inout_ PSTAGE_WRITER_RESERVATION Reservation)
{
    if (Reservation->SlotReserved && RegistryReservedSlots != 0) RegistryReservedSlots -= 1;
    Reservation->SlotReserved = FALSE;
    if (Reservation->NameReserved && RegistryReservedNameBytes >= Reservation->NameChars * sizeof(WCHAR))
        RegistryReservedNameBytes -= Reservation->NameChars * sizeof(WCHAR);
    Reservation->NameReserved = FALSE;
}

static PSTAGE_REGISTRY_ENTRY StageRegistryGetOrInsert(_In_ PSTAGE_WRITER_RESERVATION Reservation,
    _In_ const FILE_ID_INFORMATION *Identity, _In_opt_ PVOID SectionObjectPointer)
{
    PSTAGE_REGISTRY_ENTRY entry;
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
        Identity->VolumeSerialNumber, &Identity->FileId);
    if (entry != NULL) {
        StageRegistryReference(entry);
        Reservation->BoundEntry = entry;
        FltReleasePushLock(&RegistryLock);
        return entry;
    }

    capacity = StageRegistryCapacityLocked();
    if (RegistryEntryCount + RegistryReservedSlots >= capacity ||
        StageRegistryInstanceCountLocked(Reservation->Instance) >=
            min((ULONG)SAFEUPLOAD_WRITER_REGISTRY_INSTANCE_LIMIT, capacity) ||
        RegistryNameBytes + RegistryReservedNameBytes > SAFEUPLOAD_WRITER_REGISTRY_NAME_BUDGET -
            Reservation->Shell->NameChars * sizeof(WCHAR)) {
        RegistryOverflow += 1;
        FltReleasePushLock(&RegistryLock);
        InterlockedIncrement64(&RegistryCapacityFailures);
        StageRegistryMarkUnknown(Reservation->Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_CAPACITY, FALSE);
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
    entry->FirstSeenGeneration = (ULONG)SafeUploadCurrentPolicyGeneration();
    entry->State = SAFEUPLOAD_REGISTRY_STATE_UNSCOPED;
    entry->LastSState = SAFEUPLOAD_REGISTRY_S_UNKNOWN;
    entry->Sequence = ++RegistryEntrySequence;
    KeInitializeSpinLock(&entry->HolderLock);
    KeInitializeSpinLock(&entry->PagingWriteLock);
    KeInitializeEvent(&entry->PagingWritesDrained, NotificationEvent, TRUE);
    entry->Listed = TRUE;
    entry->References = 2; /* Registry history plus the reservation's bound-entry reference. */
    InsertTailList(&RegistryEntries, &entry->Link);
    RegistryEntryCount += 1;
    RegistryNameBytes += entry->NameChars * sizeof(WCHAR);
    Reservation->BoundEntry = entry;
    {
        /* Reclaim before the limits are reached: at 3/4 of the instance or total limit. */
        BOOLEAN pressure = RegistryEntryCount * 4 >= capacity * 3 ||
            StageRegistryInstanceCountLocked(Reservation->Instance) * 4 >=
                min((ULONG)SAFEUPLOAD_WRITER_REGISTRY_INSTANCE_LIMIT, capacity) * 3;
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
    for (link = RegistryReservations.Flink; link != &RegistryReservations; link = link->Flink) {
        PSTAGE_WRITER_RESERVATION reservation = CONTAINING_RECORD(link,
            STAGE_WRITER_RESERVATION, Link);
        UNICODE_STRING reservedName;
        if (!reservation->Active || reservation->Instance != Instance || reservation->Volume != Volume)
            continue;
        if (reservation->Shell != NULL && reservation->NameChars != 0) {
            reservedName.Buffer = reservation->Shell->Name;
            reservedName.Length = reservedName.MaximumLength =
                (USHORT)(reservation->NameChars * sizeof(WCHAR));
        } else if (reservation->BoundEntry != NULL && reservation->BoundEntry->NameChars != 0) {
            reservedName.Buffer = reservation->BoundEntry->Name;
            reservedName.Length = reservedName.MaximumLength =
                (USHORT)(reservation->BoundEntry->NameChars * sizeof(WCHAR));
        } else continue;
        if (RtlEqualUnicodeString(&reservedName, NormalizedName, TRUE)) return TRUE;
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
    PUNICODE_STRING fullName;
    FLT_FILESYSTEM_TYPE fs;
    SAFEUPLOAD_VOLUME_KIND kind;
    ULONG index, capacity;
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
        InterlockedIncrement64(&RegistryIdentityFailures);
        StageRegistryMarkUnknown(FltObjects->Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY, FALSE);
        return STATUS_SUCCESS; /* a by-ID writer has no name key: tracking lost, the create proceeds */
    }
    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name);
    if (!NT_SUCCESS(status)) goto RefuseIdentity;
    status = FltParseFileNameInformation(name);
    if (!NT_SUCCESS(status) || name->Volume.Length > name->Name.Length ||
        name->Name.Length == 0 || (name->Name.Length & 1) != 0) goto RefuseIdentity;
    fullName = &name->Name;
    for (index = name->Volume.Length / sizeof(WCHAR); index < fullName->Length / sizeof(WCHAR); ++index) {
        if (fullName->Buffer[index] == L':') goto RefuseIdentity; /* ADS is outside the registry key. */
    }
    if (fullName->Length / sizeof(WCHAR) > SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS) goto RefuseIdentity;

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

    reservation->Shell = ExAllocatePool2(POOL_FLAG_NON_PAGED,
        sizeof(*reservation->Shell), SAFEUPLOAD_REGISTRY_POOL_TAG);
    reservation->Node = ExAllocatePool2(POOL_FLAG_NON_PAGED,
        sizeof(*reservation->Node), SAFEUPLOAD_WRITER_NODE_POOL_TAG);
    if (reservation->Shell == NULL || reservation->Node == NULL) goto RefuseAllocation;
    RtlZeroMemory(reservation->Shell, sizeof(*reservation->Shell));
    RtlZeroMemory(reservation->Node, sizeof(*reservation->Node));
    reservation->Shell->VolumeKind = kind;
    reservation->NameChars = fullName->Length / sizeof(WCHAR);
    reservation->Shell->NameChars = (USHORT)reservation->NameChars;
    RtlCopyMemory(reservation->Shell->Name, fullName->Buffer, fullName->Length);

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
    capacity = StageRegistryCapacityLocked();
    /* The final file ID is unknown until post-create; every mutating open
     * reserves capacity even when its current normalized name is in history. */
    reservation->SlotReserved = TRUE;
    if (RegistryEntryCount + RegistryReservedSlots >= capacity ||
         StageRegistryInstanceCountLocked(FltObjects->Instance) >=
            min((ULONG)SAFEUPLOAD_WRITER_REGISTRY_INSTANCE_LIMIT, capacity) ||
         RegistryNameBytes + RegistryReservedNameBytes + fullName->Length >
            SAFEUPLOAD_WRITER_REGISTRY_NAME_BUDGET) {
        RegistryOverflow += 1;
        FltReleasePushLock(&RegistryLock);
        InterlockedIncrement64(&RegistryCapacityFailures);
        StageRegistryMarkUnknown(FltObjects->Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_CAPACITY, FALSE);
        StageRegistryQueueReclaim();
        status = STATUS_SUCCESS;
        goto Cleanup;
    }
    InsertTailList(&RegistryReservations, &reservation->Link);
    reservation->Active = TRUE;
    RegistryReservationCount += 1;
    RegistryReservedNameBytes += fullName->Length;
    reservation->NameReserved = TRUE;
    if (reservation->SlotReserved) RegistryReservedSlots += 1;
    FltReleasePushLock(&RegistryLock);
    FltReleaseContext(instanceContext);
    instanceContext = NULL;
    FltReleaseFileNameInformation(name);
    *ReservationOut = reservation;
    return STATUS_SUCCESS;

RefuseIdentity:
    InterlockedIncrement64(&RegistryIdentityFailures);
    StageRegistryMarkUnknown(FltObjects->Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY, FALSE);
    status = STATUS_SUCCESS;
    goto Cleanup;
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
    if (reservation->Shell != NULL) ExFreePoolWithTag(reservation->Shell, SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (reservation->BoundEntry != NULL) StageRegistryDereference(reservation->BoundEntry);
    if (reservation->Volume != NULL && !reservation->VolumeReferenceTransferred)
        FltObjectDereference(reservation->Volume);
    if (reservation->Instance != NULL && !reservation->InstanceReferenceTransferred)
        FltObjectDereference(reservation->Instance);
    reservation->Signature = 0;
    ExFreePoolWithTag(reservation, SAFEUPLOAD_REGISTRY_POOL_TAG);
}

NTSTATUS SafeUploadStageWritersPrepareRename(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ PCUNICODE_STRING Destination,
    _In_ BOOLEAN LinkOperation, _Outptr_result_maybenull_ PVOID *RenameContext)
{
    FILE_ID_INFORMATION identity;
    PSTAGE_REGISTRY_ENTRY entry = NULL;
    PSTAGE_REGISTRY_RENAME_CONTEXT context = NULL;
    PFLT_VOLUME volume = NULL;
    BOOLEAN isDirectory = FALSE;
    ULONG returned = 0, index;
    NTSTATUS status;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(Data);
    *RenameContext = NULL;
    if (!LinkOperation && (Destination == NULL || Destination->Length == 0 ||
        (Destination->Length & 1) != 0 ||
        Destination->Length / sizeof(WCHAR) > SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS)) {
        StageRegistryMarkUnknown(FltObjects->Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME, FALSE);
        InterlockedIncrement64(&RegistryRenameFailures);
        return STATUS_SUCCESS;
    }
    if (!LinkOperation) {
        for (index = 0; index < Destination->Length / sizeof(WCHAR); ++index) {
            if (Destination->Buffer[index] == L':') {
                StageRegistryMarkUnknown(FltObjects->Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME, FALSE);
                InterlockedIncrement64(&RegistryRenameFailures);
                return STATUS_SUCCESS;
            }
        }
    }

    /* A directory rename changes every descendant's name. This increment has
     * no directory scan or subtree index, so retain safety by making the
     * attachment Unknown even when the directory itself has no H entry. */
    status = FltObjects->FileObject != NULL ?
        FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &isDirectory) :
        STATUS_INVALID_PARAMETER;
    if (!NT_SUCCESS(status) || isDirectory) {
        StageRegistryMarkUnknown(FltObjects->Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME, FALSE);
        InterlockedIncrement64(&RegistryRenameFailures);
        return STATUS_SUCCESS;
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
        identity.VolumeSerialNumber, &identity.FileId);
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
        context->NameChars = Destination->Length / sizeof(WCHAR);
        RtlCopyMemory(context->Name, Destination->Buffer, Destination->Length);
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

VOID SafeUploadStageWritersCompleteRename(_In_opt_ PVOID Context,
    _In_ BOOLEAN Succeeded, _In_ BOOLEAN Draining)
{
    PSTAGE_REGISTRY_RENAME_CONTEXT rename = (PSTAGE_REGISTRY_RENAME_CONTEXT)Context;
    PSTAGE_REGISTRY_ENTRY entry;
    BOOLEAN markUnknown = FALSE;

    if (rename == NULL || !SafeUploadStageWritersIsRenameContext(Context)) return;
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
    } else if (Succeeded) {
        ULONG oldBytes, newBytes;
        oldBytes = entry->NameChars * sizeof(WCHAR);
        newBytes = rename->NameChars * sizeof(WCHAR);
        if (entry->Retired || RegistryNameBytes < oldBytes ||
            RegistryNameBytes - oldBytes > SAFEUPLOAD_WRITER_REGISTRY_NAME_BUDGET - newBytes) {
            markUnknown = TRUE;
        } else {
            RtlCopyMemory(entry->Name, rename->Name, newBytes);
            if (newBytes < sizeof(entry->Name))
                RtlZeroMemory((PUCHAR)entry->Name + newBytes, sizeof(entry->Name) - newBytes);
            entry->NameChars = (USHORT)rename->NameChars;
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
    rename->Signature = 0;
    StageRegistryDereference(entry);
    ExFreePoolWithTag(rename, SAFEUPLOAD_REGISTRY_POOL_TAG);
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
__declspec(noinline) static BOOLEAN StageWritersInsertNode(
    _In_ PSAFEUPLOAD_STREAM_CONTEXT StreamContext,
    _In_ PSTAGE_WRITER_NODE Node)
{
    KIRQL irql;
    BOOLEAN compatible;
    PSTAGE_REGISTRY_ENTRY previous = NULL;

    KeAcquireSpinLock(&StreamContext->WriterLock, &irql);
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
    KeReleaseSpinLock(&StreamContext->WriterLock, irql);
    if (previous != NULL) StageRegistryDereference(previous);
    return compatible;
}

static NTSTATUS StageRegistryEnlistTransaction(_In_ PFLT_INSTANCE Instance,
    _In_ PKTRANSACTION Transaction, _In_ PSTAGE_REGISTRY_ENTRY Entry);
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
    BOOLEAN directory = FALSE, hasWriterHandle;
    ULONG returned = 0;
    NTSTATUS status = STATUS_SUCCESS;
    PAGED_CODE();

    if (LegacyCompletionContext != NULL) *LegacyCompletionContext = NULL;
    if (LegacyCallbackRequired != NULL) *LegacyCallbackRequired = FALSE;

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
        goto IdentityFailure;
    }
    if (!StageRegistryAssociateSectionPointer(reservation, entry, fileObject->SectionObjectPointer)) {
        StageRegistryMarkEntryUnknown(entry, SAFEUPLOAD_REGISTRY_UNKNOWN_CAPACITY);
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

    hasWriterHandle = fileObject->WriteAccess || fileObject->DeleteAccess;
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
    StageRegistryMarkUnknown(reservation->Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY, FALSE);
TrackingLost:
    /* Tracking this writer failed. The open is never refused or cancelled (the registry is a ledger, not a gate): the loss is
     * recorded above as entry, instance or machine Unknown, which withholds every protection claim and promotion. Scoped
     * writes are still decided by the admission path. */
    if (streamContext != NULL) FltReleaseContext(streamContext);
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

VOID SafeUploadStageWritersOnCleanup(
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

    KeAcquireSpinLock(&streamContext->WriterLock, &irql);
    for (link = streamContext->WriterObjects.Flink; link != &streamContext->WriterObjects; link = link->Flink) {
        PSTAGE_WRITER_NODE node = CONTAINING_RECORD(link, STAGE_WRITER_NODE, Link);
        if (node->FileObject == fileObject) {
            RemoveEntryList(&node->Link);
            lastWriter = InterlockedDecrement(&node->Entry->H) == 0;
            found = node;
            break;
        }
    }
    KeReleaseSpinLock(&streamContext->WriterLock, irql);

    if (found != NULL) {
        InterlockedIncrement64(&RegistryChangeSequence);
        if (lastWriter && InterlockedCompareExchange((volatile LONG *)&found->Entry->State, 0, 0) ==
            SAFEUPLOAD_REGISTRY_STATE_ACTIVATING) StageRegistryQueueReclaim();
        StageRegistryRemoveOpener(found->Entry, found->ProcessId);
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
        if (tokenState != SAFEUPLOAD_INSTANCE_STATE_TEARING_DOWN) {
            /* This node still identifies the exact lost writer. Mark it before
             * H can reach zero so Evaluate cannot observe a false-Free window. */
            StageRegistryMarkEntryUnknown(node->Entry, SAFEUPLOAD_REGISTRY_UNKNOWN_CLEANUP);
        }
        InterlockedDecrement(&node->Entry->H);
        InterlockedIncrement64(&RegistryChangeSequence);
        StageRegistryRemoveOpener(node->Entry, node->ProcessId);
        StageRegistryDereference(node->Entry);
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

/* ---- C(F): writable CreateSections in flight -----------------------------------------------
 * Every section-synchronization acquire occupies a slot, including read-only and SyncTypeOther.
 * Releases have no protection field, so non-writable acquisitions must participate in pairing:
 * their release must not retire an enclosing writable acquisition of the same thread/file object.
 * A spin lock makes slot identity, stream identity and counters one atomic snapshot. Releases match
 * only the acquiring thread and file object, newest first; no cross-thread fallback can undercount.
 * Failed acquires carry their exact slot to post-operation, which may run on another thread.
 * Overflow is sticky and makes every per-stream snapshot unknown until this driver is unloaded.
 * Nothing expires an old entry or treats a missing release as proof of writer freedom. */

#define STAGE_SECTION_SLOTS 64
#define STAGE_SECTION_STUCK_100NS (20LL * 1000 * 1000)     /* 2 s */

typedef struct _STAGE_SECTION_SLOT {
    PFILE_OBJECT FileObject;       /* identity only; never dereferenced while holding SectionLock */
    PVOID Thread;
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

static KSPIN_LOCK SectionLock;
static STAGE_SECTION_SLOT SectionSlots[STAGE_SECTION_SLOTS];
static ULONG SectionNow;
static ULONG SectionMaxDepth;
static ULONGLONG SectionSequence;
static UINT64 SectionInserted;
static UINT64 SectionReleased;
static UINT64 SectionOverflow;
static UINT64 SectionRemovedOnFailure;

/* One resident lookup/removal unit for instance teardown. The returned map or
 * slot reference is released by the caller after SectionLock has been dropped. */
__declspec(noinline) static PSTAGE_REGISTRY_ENTRY StageRegistryDetachOneInstanceSectionBinding(
    _In_ PFLT_INSTANCE Instance)
{
    PSTAGE_REGISTRY_ENTRY entry = NULL;
    ULONG index;
    KIRQL irql;

    KeAcquireSpinLock(&SectionLock, &irql);
    for (index = 0; index < RTL_NUMBER_OF(RegistrySopSlots); ++index) {
        if (RegistrySopSlots[index].Entry != NULL &&
            RegistrySopSlots[index].Entry->Instance == Instance) {
            entry = RegistrySopSlots[index].Entry;
            RtlZeroMemory(&RegistrySopSlots[index], sizeof(RegistrySopSlots[index]));
            break;
        }
    }
    if (entry == NULL) {
        for (index = 0; index < STAGE_SECTION_SLOTS; ++index) {
            STAGE_SECTION_SLOT *slot = &SectionSlots[index];
            if (slot->RegistryEntry != NULL && slot->RegistryEntry->Instance == Instance) {
                entry = slot->RegistryEntry;
                if (slot->Writable && SectionNow != 0) SectionNow -= 1;
                RtlZeroMemory(slot, sizeof(*slot));
                break;
            }
        }
    }
    KeReleaseSpinLock(&SectionLock, irql);
    return entry;
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
        PSTAGE_REGISTRY_ENTRY entry = StageRegistryDetachOneInstanceSectionBinding(Instance);
        if (entry == NULL) break;
        StageRegistryDereference(entry); /* The map or exact C slot reference. */
    }

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
                if (RegistryEntryCount != 0) RegistryEntryCount -= 1;
                if (RegistryNameBytes >= entry->NameChars * sizeof(WCHAR))
                    RegistryNameBytes -= entry->NameChars * sizeof(WCHAR);
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
__declspec(noinline) static BOOLEAN StageRegistryAssociateSectionPointer(_In_ PSTAGE_WRITER_RESERVATION Reservation,
    _In_ PSTAGE_REGISTRY_ENTRY Entry, _In_opt_ PVOID SectionObjectPointer)
{
    ULONG index, empty = MAXULONG;
    PVOID oldSectionObjectPointer;
    /* Map references dropped by a rebind; released after both locks (a release may free the entry). Each pointer occupies at
     * most one slot and this entry at most one other, so at most two bindings are dropped. */
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
    KeAcquireSpinLock(&SectionLock, &irql);
    for (index = 0; index < STAGE_SECTION_SLOTS; ++index) {
        if (SectionSlots[index].SectionObjectPointer == SectionObjectPointer &&
            SectionSlots[index].Writable && SectionSlots[index].RegistryEntry != NULL &&
            SectionSlots[index].RegistryEntry != Entry) {
            pointerConflict = TRUE;
            break;
        }
    }
    if (pointerConflict) {
        KeReleaseSpinLock(&SectionLock, irql);
        FltReleasePushLock(&RegistryLock);
        return FALSE;
    }
    /* The conflict check above stands: a writable section in flight on this pointer bound to another entry is inconsistent. */
    InterlockedExchangePointer((PVOID volatile *)&Entry->SectionObjectPointer, SectionObjectPointer);
    for (index = 0; index < RTL_NUMBER_OF(RegistrySopSlots); ++index) {
        PSTAGE_REGISTRY_SOP_SLOT map = &RegistrySopSlots[index];
        if (map->Entry == Entry && oldSectionObjectPointer != NULL && oldSectionObjectPointer != SectionObjectPointer &&
            map->SectionObjectPointer == oldSectionObjectPointer && releasedCount < RTL_NUMBER_OF(released)) {
            /* This file's previous incarnation: drop its binding. */
            released[releasedCount++] = map->Entry;
            RtlZeroMemory(map, sizeof(*map));
        } else if (map->SectionObjectPointer == SectionObjectPointer) {
            if (map->Entry != Entry && releasedCount < RTL_NUMBER_OF(released)) {
                /* The pointer was reused by this stream after another file's SCB was freed: the old binding is stale. */
                (VOID)InterlockedCompareExchangePointer((PVOID volatile *)&map->Entry->SectionObjectPointer,
                    NULL, SectionObjectPointer);
                released[releasedCount++] = map->Entry;
                StageRegistryReference(Entry);
                map->Entry = Entry;
            }
            ok = map->Entry == Entry;
        }
        if (empty == MAXULONG && map->SectionObjectPointer == NULL) empty = index;
    }
    if (!ok && empty != MAXULONG) {
        StageRegistryReference(Entry);
        RegistrySopSlots[empty].SectionObjectPointer = SectionObjectPointer;
        RegistrySopSlots[empty].Entry = Entry;
        ok = TRUE;
    }
    if (ok) {
        ULONG slotIndex;
        for (slotIndex = 0; slotIndex < STAGE_SECTION_SLOTS; ++slotIndex) {
            STAGE_SECTION_SLOT *slot = &SectionSlots[slotIndex];
            if (slot->SectionObjectPointer == SectionObjectPointer && slot->RegistryEntry == NULL) {
                StageRegistryReference(Entry);
                slot->RegistryEntry = Entry;
                slot->VolumeSerial = Entry->VolumeSerial;
                slot->FileId = Entry->FileId;
            }
        }
    }
    KeReleaseSpinLock(&SectionLock, irql);
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
    ULONG index;
    KIRQL irql;
    BOOLEAN busy = FALSE;
    *MapReference = NULL;
    *InstanceReference = NULL;
    *VolumeReference = NULL;
    if (!Entry->Listed || Entry->Retired ||
        InterlockedCompareExchange((volatile LONG *)&Entry->State, 0, 0) == SAFEUPLOAD_REGISTRY_STATE_ACTIVATING ||
        InterlockedCompareExchange(&Entry->H, 0, 0) != 0 || InterlockedCompareExchange(&Entry->T, 0, 0) != 0 ||
        InterlockedCompareExchange(&Entry->DirtyAfterCutoff, 0, 0) != 0 ||
        InterlockedCompareExchange(&Entry->RenameInFlight, 0, 0) != 0 ||
        InterlockedCompareExchange(&Entry->PagingWritesInFlight, 0, 0) != 0 ||
        InterlockedCompareExchange(&Entry->UnknownReasons, 0, 0) != 0) return FALSE;
    for (link = RegistryReservations.Flink; link != &RegistryReservations; link = link->Flink) {
        if (CONTAINING_RECORD(link, STAGE_WRITER_RESERVATION, Link)->BoundEntry == Entry) return FALSE;
    }
    for (link = TransactionAssociations.Flink; link != &TransactionAssociations; link = link->Flink) {
        if (CONTAINING_RECORD(link, STAGE_TX_ASSOCIATION, Link)->Entry == Entry) return FALSE;
    }
    KeAcquireSpinLock(&SectionLock, &irql);
    for (index = 0; index < STAGE_SECTION_SLOTS; ++index) {
        if (SectionSlots[index].RegistryEntry == Entry) { busy = TRUE; break; }
    }
    if (!busy) {
        for (index = 0; index < RTL_NUMBER_OF(RegistrySopSlots); ++index) {
            if (RegistrySopSlots[index].Entry == Entry) {
                *MapReference = Entry;
                RtlZeroMemory(&RegistrySopSlots[index], sizeof(RegistrySopSlots[index]));
                break;
            }
        }
    }
    KeReleaseSpinLock(&SectionLock, irql);
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
    if (RegistryEntryCount != 0) RegistryEntryCount -= 1;
    if (RegistryNameBytes >= Entry->NameChars * sizeof(WCHAR)) RegistryNameBytes -= Entry->NameChars * sizeof(WCHAR);
    return TRUE;
}

/* PASSIVE. Opens the candidate by its 64-bit NTFS file reference (never the 16-byte form, which NTFS reads as an object
 * ID), verifies all 128 ID bits and the volume serial, and reports whether the live stream is quiescent. A file that no
 * longer exists is quiescent too: nothing can write to it. */
static BOOLEAN StageRegistryEntryQuiescent(_In_ PSTAGE_REGISTRY_ENTRY Entry, _In_ PFLT_INSTANCE Instance,
    _In_ PFLT_VOLUME Volume)
{
    UNICODE_STRING volumeName = { 0 }, name;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io = { 0 };
    FILE_ID_INFORMATION actual;
    HANDLE handle = NULL;
    PFILE_OBJECT object = NULL;
    PWCHAR buffer = NULL;
    ULONG needed = 0, bytes, returned = 0;
    BOOLEAN quiescent = FALSE;
    NTSTATUS status;

    PAGED_CODE();
    if (InterlockedCompareExchange(&Entry->PagingWritesInFlight, 0, 0) != 0) return FALSE;
    status = FltGetVolumeName(Volume, NULL, &needed);
    if (status != STATUS_BUFFER_TOO_SMALL || needed == 0 || needed > MAXUSHORT - 64) return FALSE;
    bytes = needed + sizeof(WCHAR) + sizeof(ULONGLONG);
    buffer = ExAllocatePool2(POOL_FLAG_PAGED, bytes, SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (buffer == NULL) return FALSE;
    volumeName.Buffer = buffer;
    volumeName.MaximumLength = (USHORT)needed;
    status = FltGetVolumeName(Volume, &volumeName, NULL);
    if (!NT_SUCCESS(status)) goto Exit;
    buffer[volumeName.Length / sizeof(WCHAR)] = L'\\';
    RtlCopyMemory((PUCHAR)buffer + volumeName.Length + sizeof(WCHAR), Entry->FileId.Identifier, sizeof(ULONGLONG));
    name.Buffer = buffer;
    name.Length = name.MaximumLength = (USHORT)(volumeName.Length + sizeof(WCHAR) + sizeof(ULONGLONG));
    InitializeObjectAttributes(&attributes, &name, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = FltCreateFileEx2(SafeUploadData.Filter, Instance, &handle, &object, FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &attributes, &io, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
        FILE_OPEN_BY_FILE_ID | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_COMPLETE_IF_OPLOCKED,
        NULL, 0, 0, NULL);
    if (status == STATUS_INVALID_PARAMETER || status == STATUS_OBJECT_NAME_NOT_FOUND ||
        status == STATUS_FILE_DELETED || status == STATUS_DELETE_PENDING) {
        quiescent = TRUE; /* the file is gone (or going): no writer, mapping or cache can reach it */
        goto Exit;
    }
    if (status != STATUS_SUCCESS || object == NULL) goto Exit;
    RtlZeroMemory(&actual, sizeof(actual));
    status = FltQueryInformationFile(Instance, object, &actual, sizeof(actual), FileIdInformation, &returned);
    if (status != STATUS_SUCCESS || returned != sizeof(actual)) goto Exit;
    if (actual.VolumeSerialNumber != Entry->VolumeSerial ||
        !RtlEqualMemory(&actual.FileId, &Entry->FileId, sizeof(actual.FileId))) {
        quiescent = TRUE; /* the reference now names another file: the tracked one is gone */
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
    ExFreePoolWithTag(buffer, SAFEUPLOAD_REGISTRY_POOL_TAG);
    return quiescent;
}

static NTSTATUS StageRegistryOpenIdentity(_In_ PSTAGE_REGISTRY_ENTRY Entry,
    _In_ PFLT_INSTANCE Instance, _In_ PFLT_VOLUME Volume, _Out_ PHANDLE Handle,
    _Outptr_result_nullonfailure_ PFILE_OBJECT *Object)
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
    status = FltGetVolumeName(Volume, NULL, &needed);
    if (status != STATUS_BUFFER_TOO_SMALL || needed == 0 || needed > MAXUSHORT - 64)
        return STATUS_FLT_INSTANCE_NOT_FOUND;
    bytes = needed + sizeof(WCHAR) + sizeof(ULONGLONG);
    buffer = ExAllocatePool2(POOL_FLAG_PAGED, bytes, SAFEUPLOAD_REGISTRY_POOL_TAG);
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
Exit:
    ExFreePoolWithTag(buffer, SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (!NT_SUCCESS(status)) {
        if (*Object != NULL) { ObDereferenceObject(*Object); *Object = NULL; }
        if (*Handle != NULL) { FltClose(*Handle); *Handle = NULL; }
    }
    return status;
}

static NTSTATUS StageRegistryWaitPagingWritesDrained(_In_ PSTAGE_REGISTRY_ENTRY Entry)
{
    LARGE_INTEGER timeout;
    NTSTATUS status;
    PAGED_CODE();
    if (InterlockedCompareExchange(&Entry->PagingWritesInFlight, 0, 0) == 0) return STATUS_SUCCESS;
    timeout.QuadPart = -(LONGLONG)SAFEUPLOAD_CUTOFF_PAGING_DRAIN_TIMEOUT_100NS;
    status = KeWaitForSingleObject(&Entry->PagingWritesDrained, Executive, KernelMode, FALSE, &timeout);
    if (status != STATUS_SUCCESS ||
        InterlockedCompareExchange(&Entry->PagingWritesInFlight, 0, 0) != 0)
        return STATUS_IO_TIMEOUT;
    return STATUS_SUCCESS;
}

/* Keep Entry's paging-write lock in resident code. Entry, its event, and the
 * registry sequence are nonpaged; pageable callers do file/cache work outside. */
__declspec(noinline) static VOID StageRegistryClosePagingWriteGate(_In_ PSTAGE_REGISTRY_ENTRY Entry)
{
    KIRQL irql;

    KeAcquireSpinLock(&Entry->PagingWriteLock, &irql);
    InterlockedExchange(&Entry->PagingWriteGateClosed, 1);
    if (InterlockedCompareExchange(&Entry->PagingWritesInFlight, 0, 0) == 0)
        KeSetEvent(&Entry->PagingWritesDrained, IO_NO_INCREMENT, FALSE);
    KeReleaseSpinLock(&Entry->PagingWriteLock, irql);
}

__declspec(noinline) static VOID StageRegistryMarkCutoffFailed(_In_ PSTAGE_REGISTRY_ENTRY Entry)
{
    KIRQL irql;

    KeAcquireSpinLock(&Entry->PagingWriteLock, &irql);
    InterlockedExchange(&Entry->CutoffFailed, 1);
    KeReleaseSpinLock(&Entry->PagingWriteLock, irql);
}

__declspec(noinline) static VOID StageRegistryCompleteCutoffFlush(_In_ PSTAGE_REGISTRY_ENTRY Entry)
{
    KIRQL irql;

    KeAcquireSpinLock(&Entry->PagingWriteLock, &irql);
    InterlockedIncrement(&Entry->CutoffFlushPairs);
    InterlockedExchange(&Entry->CutoffComplete, 1);
    KeReleaseSpinLock(&Entry->PagingWriteLock, irql);
}

/* RegistryLock remains held by the pageable caller, stabilizing the name and
 * list membership. Name comparison is done there because its snapshot is paged. */
__declspec(noinline) static VOID StageRegistryTryPromoteEntry(
    _In_ PSTAGE_REGISTRY_ENTRY Entry,
    _In_ BOOLEAN NameMatches,
    _In_ USHORT NameSnapshotChars,
    _In_ ULONG RenameVersion,
    _In_ ULONG CurrentGeneration,
    _In_ BOOLEAN SopEmpty)
{
    KIRQL irql;

    KeAcquireSpinLock(&Entry->PagingWriteLock, &irql);
    if (Entry->Listed && !Entry->Retired &&
        InterlockedCompareExchange((volatile LONG *)&Entry->State, 0, 0) == SAFEUPLOAD_REGISTRY_STATE_ACTIVATING &&
        InterlockedCompareExchange(&Entry->H, 0, 0) == 0 &&
        InterlockedCompareExchange(&Entry->T, 0, 0) == 0 &&
        InterlockedCompareExchange(&Entry->UnknownReasons, 0, 0) == 0 &&
        InterlockedCompareExchange(&Entry->DirtyAfterCutoff, 0, 0) == 0 &&
        InterlockedCompareExchange(&Entry->CutoffFailed, 0, 0) == 0 &&
        InterlockedCompareExchange(&Entry->PagingWriteGateClosed, 0, 0) != 0 &&
        InterlockedCompareExchange(&Entry->PagingWritesInFlight, 0, 0) == 0 &&
        InterlockedCompareExchange(&Entry->RenameInFlight, 0, 0) == 0 &&
        (ULONG)InterlockedCompareExchange(&Entry->RenameVersion, 0, 0) == RenameVersion &&
        Entry->ActivationGeneration == CurrentGeneration &&
        InterlockedCompareExchange(&Entry->ActivationEnforced, 0, 0) != 0 &&
        Entry->NameChars == NameSnapshotChars && NameSnapshotChars != 0 && NameMatches &&
        SopEmpty &&
        StageRegistrySnapshotC(Entry, NULL, 0, NULL) == 0) {
        if (InterlockedCompareExchange((volatile LONG *)&Entry->State,
                SAFEUPLOAD_REGISTRY_STATE_PROTECTED,
                SAFEUPLOAD_REGISTRY_STATE_ACTIVATING) == SAFEUPLOAD_REGISTRY_STATE_ACTIVATING) {
            InterlockedExchange(&Entry->StuckSProbe, 0);
            InterlockedIncrement64(&RegistryChangeSequence);
        }
    }
    KeReleaseSpinLock(&Entry->PagingWriteLock, irql);
}

__declspec(noinline) static VOID StageRegistryPreparePagingActivation(_In_ PSTAGE_REGISTRY_ENTRY Entry)
{
    KIRQL irql;

    KeAcquireSpinLock(&Entry->PagingWriteLock, &irql);
    InterlockedExchange((volatile LONG *)&Entry->State, SAFEUPLOAD_REGISTRY_STATE_ACTIVATING);
    InterlockedExchange(&Entry->CutoffStarted, 0);
    InterlockedExchange(&Entry->CutoffComplete, 0);
    InterlockedExchange(&Entry->CutoffFailed, 0);
    InterlockedExchange(&Entry->PagingWriteGateClosed, 0);
    InterlockedExchange(&Entry->CutoffFlushPairs, 0);
    InterlockedExchange(&Entry->StuckSProbe, 0);
    InterlockedExchange(&Entry->LastSState, SAFEUPLOAD_REGISTRY_S_UNKNOWN);
    if (InterlockedCompareExchange(&Entry->PagingWritesInFlight, 0, 0) == 0)
        KeSetEvent(&Entry->PagingWritesDrained, IO_NO_INCREMENT, FALSE);
    else
        KeClearEvent(&Entry->PagingWritesDrained);
    KeReleaseSpinLock(&Entry->PagingWriteLock, irql);
}

__declspec(noinline) static VOID StageRegistryClearPagingActivation(_In_ PSTAGE_REGISTRY_ENTRY Entry)
{
    KIRQL irql;
    LONG state;

    KeAcquireSpinLock(&Entry->PagingWriteLock, &irql);
    InterlockedExchange(&Entry->ActivationEnforced, 0);
    state = InterlockedCompareExchange((volatile LONG *)&Entry->State, 0, 0);
    if (state == SAFEUPLOAD_REGISTRY_STATE_ACTIVATING || state == SAFEUPLOAD_REGISTRY_STATE_PROTECTED)
        InterlockedExchange((volatile LONG *)&Entry->State, SAFEUPLOAD_REGISTRY_STATE_UNSCOPED);
    InterlockedExchange(&Entry->CutoffStarted, 0);
    InterlockedExchange(&Entry->CutoffComplete, 0);
    InterlockedExchange(&Entry->CutoffFailed, 0);
    InterlockedExchange(&Entry->PagingWriteGateClosed, 0);
    InterlockedExchange(&Entry->CutoffFlushPairs, 0);
    InterlockedExchange(&Entry->StuckSProbe, 0);
    if (InterlockedCompareExchange(&Entry->PagingWritesInFlight, 0, 0) == 0)
        KeSetEvent(&Entry->PagingWritesDrained, IO_NO_INCREMENT, FALSE);
    else
        KeClearEvent(&Entry->PagingWritesDrained);
    KeReleaseSpinLock(&Entry->PagingWriteLock, irql);
}

static VOID StageRegistryActivationProcess(_In_ PSTAGE_REGISTRY_ENTRY Entry,
    _In_ PFLT_INSTANCE Instance, _In_ PFLT_VOLUME Volume)
{
    HANDLE handle = NULL;
    PFILE_OBJECT object = NULL;
    PSECTION_OBJECT_POINTERS sop = NULL;
    IO_STATUS_BLOCK io = { 0 };
    FILE_STANDARD_INFORMATION standard = { 0 };
    PSAFEUPLOAD_INSTANCE_CONTEXT instanceContext = NULL;
    PWCHAR nameSnapshot = NULL;
    UNICODE_STRING entryName = { 0 };
    LARGE_INTEGER flushed, interval;
    ULONG returned = 0, attempt;
    USHORT nameSnapshotChars = 0;
    ULONG renameVersion = 0;
    SAFEUPLOAD_VOLUME_KIND volumeKind = SafeUploadVolumeUnknown;
    LONG instanceUnknownReasons = 0;
    BOOLEAN cached, freeNow = FALSE, currentlyScoped;
    BOOLEAN nameStillMatches, sopEmpty;
    BOOLEAN cutoffEpochHeld = FALSE;
    ULONG currentGeneration;
    NTSTATUS status;

    PAGED_CODE();
    if (!SafeUploadInstanceIsTrusted(Instance)) {
        StageRegistryMarkEntryUnknown(Entry, SAFEUPLOAD_REGISTRY_UNKNOWN_TRUST);
        InterlockedIncrement64(&RegistryChangeSequence);
        return;
    }
    if (SafeUploadStageWritersGlobalUnknown() != 0) {
        StageRegistryMarkEntryUnknown(Entry, SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY);
        goto Exit;
    }

    nameSnapshot = ExAllocatePool2(POOL_FLAG_PAGED,
        SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS * sizeof(WCHAR), SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (nameSnapshot == NULL) {
        StageRegistryMarkEntryUnknown(Entry, SAFEUPLOAD_REGISTRY_UNKNOWN_ALLOCATION);
        goto Exit;
    }
    FltAcquirePushLockShared(&RegistryLock);
    if (!Entry->Listed || Entry->Retired || Entry->NameChars == 0 ||
        Entry->NameChars > SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS ||
        InterlockedCompareExchange((volatile LONG *)&Entry->State, 0, 0) !=
            SAFEUPLOAD_REGISTRY_STATE_ACTIVATING ||
        InterlockedCompareExchange(&Entry->ActivationEnforced, 0, 0) == 0 ||
        InterlockedCompareExchange(&Entry->RenameInFlight, 0, 0) != 0) {
        FltReleasePushLock(&RegistryLock);
        goto Exit;
    }
    nameSnapshotChars = Entry->NameChars;
    renameVersion = (ULONG)InterlockedCompareExchange(&Entry->RenameVersion, 0, 0);
    RtlCopyMemory(nameSnapshot, Entry->Name, nameSnapshotChars * sizeof(WCHAR));
    volumeKind = Entry->VolumeKind;
    FltReleasePushLock(&RegistryLock);
    entryName.Buffer = nameSnapshot;
    entryName.Length = entryName.MaximumLength = (USHORT)(nameSnapshotChars * sizeof(WCHAR));

    status = StageRegistryOpenIdentity(Entry, Instance, Volume, &handle, &object);
    if (!NT_SUCCESS(status)) {
        if (status == STATUS_FILE_INVALID || status == STATUS_OBJECT_NAME_NOT_FOUND ||
            status == STATUS_FILE_DELETED || status == STATUS_DELETE_PENDING)
            StageRegistryMarkEntryUnknown(Entry, SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY);
        InterlockedIncrement64(&RegistryChangeSequence);
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
    if (instanceUnknownReasons != 0) {
        StageRegistryMarkEntryUnknown(Entry, instanceUnknownReasons);
        goto Exit;
    }

    /* This is the single cutoff flush for this activation. The entry is not
     * marked cutoff-complete until both cache and filter-manager flushes end. */
    if (InterlockedCompareExchange(&Entry->CutoffStarted, 1, 0) == 0) {
        InterlockedIncrement64(&RegistryChangeSequence);
        /* A short cutoff count prevents policy finalization from racing the
         * cache pair without holding a policy/global lock across file I/O. */
        status = SafeUploadPolicyActivationCutoffBegin();
        if (!NT_SUCCESS(status)) {
            InterlockedExchange(&Entry->CutoffStarted, 0);
            InterlockedIncrement64(&RegistryChangeSequence);
            goto Exit;
        }
        cutoffEpochHeld = TRUE;
        RtlZeroMemory(&io, sizeof(io));
        io.Status = STATUS_PENDING;
        CcFlushCache(sop, NULL, 0, &io);
        StageRegistryClosePagingWriteGate(Entry);
        if (io.Status != STATUS_SUCCESS) {
            StageRegistryMarkCutoffFailed(Entry);
            InterlockedIncrement64(&RegistryChangeSequence);
            goto Exit;
        }
        status = StageRegistryWaitPagingWritesDrained(Entry);
        if (!NT_SUCCESS(status)) {
            StageRegistryMarkCutoffFailed(Entry);
            InterlockedIncrement64(&RegistryChangeSequence);
            goto Exit;
        }
        status = FltFlushBuffers(Instance, object);
        if (!NT_SUCCESS(status)) {
            StageRegistryMarkCutoffFailed(Entry);
            InterlockedIncrement64(&RegistryChangeSequence);
            goto Exit;
        }
        StageRegistryCompleteCutoffFlush(Entry);
        InterlockedIncrement64(&RegistryChangeSequence);
        SafeUploadPolicyActivationCutoffEnd();
        cutoffEpochHeld = FALSE;
    } else if (InterlockedCompareExchange(&Entry->CutoffComplete, 0, 0) == 0) {
        goto Exit;
    }
    if (InterlockedCompareExchange(&Entry->DirtyAfterCutoff, 0, 0) != 0 ||
        InterlockedCompareExchange(&Entry->UnknownReasons, 0, 0) != 0 ||
        InterlockedCompareExchange(&Entry->CutoffFailed, 0, 0) != 0 ||
        InterlockedCompareExchange(&Entry->CutoffComplete, 0, 0) == 0 ||
        InterlockedCompareExchange(&Entry->PagingWriteGateClosed, 0, 0) == 0 ||
        InterlockedCompareExchange(&Entry->PagingWritesInFlight, 0, 0) != 0) goto Exit;

    for (attempt = 0; attempt < 6; ++attempt) {
        BOOLEAN userWritable;
        LONG h = InterlockedCompareExchange(&Entry->H, 0, 0);
        LONG t = InterlockedCompareExchange(&Entry->T, 0, 0);
        UINT32 sectionCount = StageRegistrySnapshotC(Entry, NULL, 0, NULL);
        LONG c = (LONG)(sectionCount & ~SAFEUPLOAD_SECTIONS_UNTRACKED_BIT);
        if (h != 0 || t != 0 || c != 0 ||
            (sectionCount & SAFEUPLOAD_SECTIONS_UNTRACKED_BIT) != 0 ||
            InterlockedCompareExchange(&Entry->RenameInFlight, 0, 0) != 0) goto Exit;
        userWritable = (BOOLEAN)(MmDoesFileHaveUserWritableReferences(sop) != FALSE);
        {
            LONG newSState = userWritable ? SAFEUPLOAD_REGISTRY_S_YES : SAFEUPLOAD_REGISTRY_S_NO;
            if (InterlockedExchange(&Entry->LastSState, newSState) != newSState)
                InterlockedIncrement64(&RegistryChangeSequence);
        }
        if (!userWritable) { freeNow = TRUE; break; }
        if (attempt == 5) break;
        interval.QuadPart = -100 * 10 * 1000LL;
        (VOID)KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }
    if (!freeNow) {
        InterlockedExchange(&Entry->StuckSProbe, 1);
        InterlockedIncrement64(&RegistryChangeSequence);
        goto Exit;
    }
    if (InterlockedCompareExchange(&Entry->H, 0, 0) != 0 ||
        InterlockedCompareExchange(&Entry->T, 0, 0) != 0 ||
        InterlockedCompareExchange(&Entry->DirtyAfterCutoff, 0, 0) != 0 ||
        InterlockedCompareExchange(&Entry->UnknownReasons, 0, 0) != 0 ||
        sop->DataSectionObject != NULL || sop->SharedCacheMap != NULL) goto Exit;

    /* Final readback is the promotion barrier. The cutoff pair above is never
     * repeated: post-cutoff paging writes are denied, and any attempted write
     * makes this entry permanently dirty. Read the cutoff result only after
     * H=C=T=0 and S=NO. */
    status = FltQueryInformationFile(Instance, object, &standard, sizeof(standard),
        FileStandardInformation, &returned);
    if (status != STATUS_SUCCESS || returned != sizeof(standard)) goto Exit;
    cached = (BOOLEAN)(CcIsFileCached(object) != FALSE);
    flushed = CcGetFlushedValidData(sop, FALSE);
    if (cached && (flushed.QuadPart == MAXLONGLONG ||
        flushed.QuadPart < standard.EndOfFile.QuadPart)) goto Exit;
    if (!cached && flushed.QuadPart == MAXLONGLONG) {
        /* MAXLONGLONG is the documented uncached-stream result. */
    } else if (flushed.QuadPart < standard.EndOfFile.QuadPart) {
        goto Exit;
    }

    currentlyScoped = SafeUploadPolicyEntryIsCurrentlyScoped(volumeKind, &entryName);
    if (!currentlyScoped) goto Exit;
    if (InterlockedCompareExchange(&Entry->H, 0, 0) == 0 &&
        InterlockedCompareExchange(&Entry->T, 0, 0) == 0 &&
        InterlockedCompareExchange(&Entry->DirtyAfterCutoff, 0, 0) == 0 &&
        InterlockedCompareExchange(&Entry->UnknownReasons, 0, 0) == 0 &&
        InterlockedCompareExchange(&Entry->CutoffFailed, 0, 0) == 0 &&
        InterlockedCompareExchange(&Entry->PagingWriteGateClosed, 0, 0) != 0 &&
        InterlockedCompareExchange(&Entry->PagingWritesInFlight, 0, 0) == 0 &&
        sop->DataSectionObject == NULL && sop->SharedCacheMap == NULL) {
        FltAcquirePushLockExclusive(&RegistryLock);
        nameStillMatches = Entry->NameChars == nameSnapshotChars && nameSnapshotChars != 0 &&
            RtlEqualMemory(Entry->Name, nameSnapshot, nameSnapshotChars * sizeof(WCHAR));
        currentGeneration = (ULONG)SafeUploadCurrentPolicyGeneration();
        sopEmpty = sop->DataSectionObject == NULL && sop->SharedCacheMap == NULL;
        StageRegistryTryPromoteEntry(Entry, nameStillMatches, nameSnapshotChars,
            renameVersion, currentGeneration, sopEmpty);
        FltReleasePushLock(&RegistryLock);
    }
Exit:
    if (cutoffEpochHeld) SafeUploadPolicyActivationCutoffEnd();
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

static VOID StageRegistryReclaimWorker(_In_ PFLT_GENERIC_WORKITEM WorkItem, _In_ PVOID FltObject, _In_opt_ PVOID Context)
{
    PSTAGE_REGISTRY_ENTRY *candidates;
    PFLT_INSTANCE *instances;
    PFLT_VOLUME *volumes;
    PLIST_ENTRY link;
    ULONG count = 0, index;
    ULONGLONG cursor = 0, highestVisited = 0;
    BOOLEAN reachedBatch = FALSE;
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
        cursor = RegistryReclaimCursor;
        highestVisited = cursor;
        for (link = RegistryEntries.Flink; link != &RegistryEntries && count < STAGE_RECLAIM_BATCH; link = link->Flink) {
            PSTAGE_REGISTRY_ENTRY entry = CONTAINING_RECORD(link, STAGE_REGISTRY_ENTRY, Link);
            BOOLEAN activating = InterlockedCompareExchange((volatile LONG *)&entry->State, 0, 0) ==
                SAFEUPLOAD_REGISTRY_STATE_ACTIVATING;
            if (entry->Sequence <= cursor) continue;
            highestVisited = entry->Sequence;
            if (entry->Retired || entry->Instance == NULL || entry->Volume == NULL ||
                (!activating && (InterlockedCompareExchange(&entry->H, 0, 0) != 0 ||
                 InterlockedCompareExchange(&entry->T, 0, 0) != 0 ||
                 InterlockedCompareExchange(&entry->DirtyAfterCutoff, 0, 0) != 0 ||
                 InterlockedCompareExchange(&entry->UnknownReasons, 0, 0) != 0))) continue;
            if (!NT_SUCCESS(FltObjectReference(entry->Instance))) continue;
            if (!NT_SUCCESS(FltObjectReference(entry->Volume))) { FltObjectDereference(entry->Instance); continue; }
            StageRegistryReference(entry);
            candidates[count] = entry;
            instances[count] = entry->Instance;
            volumes[count] = entry->Volume;
            count += 1;
        }
        reachedBatch = count == STAGE_RECLAIM_BATCH;
        RegistryReclaimCursor = reachedBatch ? highestVisited : 0;
        FltReleasePushLock(&RegistryLock);

        for (index = 0; index < count; ++index) {
            PSTAGE_REGISTRY_ENTRY entry = candidates[index];
            PSTAGE_REGISTRY_ENTRY mapReference = NULL;
            PFLT_INSTANCE entryInstance = NULL;
            PFLT_VOLUME entryVolume = NULL;
            BOOLEAN pruned = FALSE;
            BOOLEAN activationCandidate = InterlockedCompareExchange((volatile LONG *)&entry->State, 0, 0) ==
                SAFEUPLOAD_REGISTRY_STATE_ACTIVATING;
            BOOLEAN promotedThisPass = FALSE;
            if (activationCandidate) {
                StageRegistryActivationProcess(entry, instances[index], volumes[index]);
                promotedThisPass = InterlockedCompareExchange((volatile LONG *)&entry->State, 0, 0) ==
                    SAFEUPLOAD_REGISTRY_STATE_PROTECTED;
            }
            /* The check runs without the lock; a new writer in between needs a handle, which raises H or binds a
             * reservation, and the locked re-check below refuses the prune. */
            if (!promotedThisPass && InterlockedCompareExchange((volatile LONG *)&entry->State, 0, 0) !=
                SAFEUPLOAD_REGISTRY_STATE_ACTIVATING &&
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
        if (reachedBatch) InterlockedExchange(&RegistryReclaimRescan, 1);
        ExFreePoolWithTag(candidates, SAFEUPLOAD_REGISTRY_POOL_TAG);
    }
    InterlockedExchange(&RegistryReclaimQueued, 0);
    if (InterlockedExchange(&RegistryReclaimRescan, 0) != 0) (VOID)StageRegistryQueueReclaim();
    ExReleaseRundownProtection(&SafeUploadData.ChannelRundown);
}

/* At most one pass is queued at a time. Unload waits on the channel rundown this pass holds. */
static BOOLEAN StageRegistryQueueReclaim(VOID)
{
    PFLT_GENERIC_WORKITEM item;
    if (InterlockedCompareExchange(&RegistryReclaimQueued, 1, 0) != 0) {
        InterlockedExchange(&RegistryReclaimRescan, 1);
        return TRUE;
    }
    if (!ExAcquireRundownProtection(&SafeUploadData.ChannelRundown)) {
        InterlockedExchange(&RegistryReclaimQueued, 0);
        return FALSE;
    }
    item = FltAllocateGenericWorkItem();
    if (item == NULL || !NT_SUCCESS(FltQueueGenericWorkItem(item, SafeUploadData.Filter, StageRegistryReclaimWorker,
            DelayedWorkQueue, NULL))) {
        if (item != NULL) FltFreeGenericWorkItem(item);
        ExReleaseRundownProtection(&SafeUploadData.ChannelRundown);
        InterlockedExchange(&RegistryReclaimQueued, 0);
        return FALSE;
    }
    return TRUE;
}

VOID SafeUploadStageWritersQueueRecheck(VOID)
{
    (VOID)StageRegistryQueueReclaim();
}

VOID SafeUploadStageWritersInitialize(VOID)
{
    KeInitializeSpinLock(&SectionLock);
    FltInitializePushLock(&RegistryLock);
    RegistryEntrySequence = 0;
    RegistryReclaimCursor = 0;
    InitializeListHead(&RegistryEntries);
    InitializeListHead(&RegistryReservations);
    InitializeListHead(&TransactionAssociations);
}

static BOOLEAN StageSectionWritable(_In_ PFLT_CALLBACK_DATA Data)
{
    UINT32 protection;

    if (Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType != SyncTypeCreateSection) return FALSE;
    protection = Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection;
    return (protection & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

NTSTATUS SafeUploadStageSectionAcquired(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID *CompletionContext)
{
    PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
    PVOID sop, thread;
    BOOLEAN writable;
    STAGE_SECTION_SLOT *record = NULL;
    PSTAGE_REGISTRY_ENTRY overflowEntry = NULL;
    ULONG index, sopIndex;
    ULONG processId;
    KIRQL irql;
    LONGLONG now;

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
    KeAcquireSpinLock(&SectionLock, &irql);
    for (index = 0; index < STAGE_SECTION_SLOTS; index += 1) {
        STAGE_SECTION_SLOT *slot = &SectionSlots[index];
        if (slot->FileObject != NULL) continue;
        slot->FileObject = fileObject;
        slot->Thread = thread;
        slot->SectionObjectPointer = sop;
        slot->Time = now;
        slot->Sequence = ++SectionSequence;
        slot->Writable = writable;
        for (sopIndex = 0; sopIndex < RTL_NUMBER_OF(RegistrySopSlots); ++sopIndex) {
            if (RegistrySopSlots[sopIndex].SectionObjectPointer == sop &&
                RegistrySopSlots[sopIndex].Entry != NULL) {
                PSTAGE_REGISTRY_ENTRY entry = RegistrySopSlots[sopIndex].Entry;
                StageRegistryReference(entry);
                slot->RegistryEntry = entry;
                slot->VolumeSerial = entry->VolumeSerial;
                slot->FileId = entry->FileId;
                break;
            }
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
        if (writable && sop != NULL) {
            /* A full C table is a loss about this stream when its SOP is still
             * in the registry map; otherwise the instance is the narrowest
             * identity available to this callback. */
            for (sopIndex = 0; sopIndex < RTL_NUMBER_OF(RegistrySopSlots); ++sopIndex) {
                if (RegistrySopSlots[sopIndex].SectionObjectPointer == sop &&
                    RegistrySopSlots[sopIndex].Entry != NULL) {
                    overflowEntry = RegistrySopSlots[sopIndex].Entry;
                    StageRegistryReference(overflowEntry);
                    break;
                }
            }
        }
        InterlockedIncrement64(&RegistryChangeSequence);
    }
    KeReleaseSpinLock(&SectionLock, irql);
    if (record == NULL) {
        if (overflowEntry != NULL) {
            StageRegistryMarkEntryUnknown(overflowEntry, SAFEUPLOAD_REGISTRY_UNKNOWN_CAPACITY);
            StageRegistryDereference(overflowEntry);
        } else if (writable && KeGetCurrentIrql() <= APC_LEVEL) {
            StageRegistryMarkUnknown(FltObjects->Instance,
                SAFEUPLOAD_REGISTRY_UNKNOWN_CAPACITY, FALSE);
        } else if (writable) {
            InterlockedOr((volatile LONG *)&RegistryUnknownReasons,
                SAFEUPLOAD_REGISTRY_UNKNOWN_CAPACITY);
            if (!StageRegistryQueueInstanceUnknown(FltObjects->Instance,
                    SAFEUPLOAD_REGISTRY_UNKNOWN_CAPACITY))
                InterlockedExchange(&WriterGlobalUnknown, 1);
        }
        InterlockedIncrement64(&RegistryCapacityFailures);
        /* Section accounting is a ledger. The lower acquire still proceeds; sticky Unknown withholds promotion. */
        return STATUS_SUCCESS;
    }
    *CompletionContext = record;
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

VOID SafeUploadStageSectionReleasePrepare(_In_ PFLT_CALLBACK_DATA Data,
    _Outptr_result_maybenull_ PVOID *CompletionContext)
{
    PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
    PVOID thread = PsGetCurrentThread();
    STAGE_SECTION_SLOT *record = NULL;
    ULONG index;
    KIRQL irql;

    *CompletionContext = NULL;
    if (fileObject == NULL) return;
    KeAcquireSpinLock(&SectionLock, &irql);
    /* Pair the exact file-object/thread release even after an unrelated
     * overflow. The lost binding was marked Unknown at its stream/instance. */
    for (index = 0; index < STAGE_SECTION_SLOTS; index += 1) {
        STAGE_SECTION_SLOT *slot = &SectionSlots[index];
        if (slot->FileObject == fileObject && slot->Thread == thread &&
            !slot->ReleasePending &&
            (record == NULL || slot->Sequence > record->Sequence)) record = slot;
    }
    if (record != NULL) record->ReleasePending = TRUE;
    KeReleaseSpinLock(&SectionLock, irql);
    *CompletionContext = record;
}

VOID SafeUploadStageSectionReleaseComplete(_In_opt_ PFLT_INSTANCE Instance,
    _In_opt_ PVOID CompletionContext, _In_ BOOLEAN Succeeded, _In_ BOOLEAN Draining)
{
    STAGE_SECTION_SLOT *slot = (STAGE_SECTION_SLOT *)CompletionContext;
    PSTAGE_REGISTRY_ENTRY removed = NULL;
    KIRQL irql;
    if (slot == NULL) return;
    if (Draining) SafeUploadStageSectionAcquireDraining(Instance, CompletionContext);
    KeAcquireSpinLock(&SectionLock, &irql);
    if (slot->FileObject != NULL && slot->ReleasePending) {
        if (Succeeded && !Draining) removed = StageSectionRemoveSlot(slot, FALSE);
        else slot->ReleasePending = FALSE;
    }
    KeReleaseSpinLock(&SectionLock, irql);
    if (removed != NULL) {
        StageRegistryDereference(removed);
        StageRegistryQueueReclaim();
    }
}

VOID SafeUploadStageSectionAcquireFailed(_In_ PVOID CompletionContext)
{
    STAGE_SECTION_SLOT *slot = (STAGE_SECTION_SLOT *)CompletionContext;
    PSTAGE_REGISTRY_ENTRY removed;
    KIRQL irql;

    KeAcquireSpinLock(&SectionLock, &irql);
    removed = StageSectionRemoveSlot(slot, TRUE);
    KeReleaseSpinLock(&SectionLock, irql);
    StageRegistryDereference(removed);
}

/* Draining: the acquire's outcome is unavailable and its release may never reach this filter. The slot stays
 * (its stream keeps C>0) and all writer state becomes Unknown until the driver is reloaded, i.e. until reboot in
 * production. No recovery path: an unexpected teardown is a defect to fix, not a state to clean up. */
VOID SafeUploadStageSectionAcquireDraining(_In_opt_ PFLT_INSTANCE Instance,
    _In_opt_ PVOID CompletionContext)
{
    STAGE_SECTION_SLOT *slot = (STAGE_SECTION_SLOT *)CompletionContext;
    if (slot != NULL && slot->RegistryEntry != NULL)
        StageRegistryMarkEntryUnknown(slot->RegistryEntry, SAFEUPLOAD_REGISTRY_UNKNOWN_TEARDOWN);
    else
        StageRegistryMarkUnknown(Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_TEARDOWN, FALSE);
}

/* The pageable registry-entry probe calls this resident SectionLock snapshot. */
__declspec(noinline) UINT32 SafeUploadStageSectionsInFlight(_In_opt_ PVOID SectionObjectPointer)
{
    UINT32 count = 0;
    ULONG index;
    KIRQL irql;

    if (SectionObjectPointer == NULL) return SAFEUPLOAD_SECTIONS_UNTRACKED_BIT;
    KeAcquireSpinLock(&SectionLock, &irql);
    for (index = 0; index < STAGE_SECTION_SLOTS; index += 1) {
        STAGE_SECTION_SLOT *slot = &SectionSlots[index];
        if (slot->FileObject != NULL && slot->Writable &&
            slot->SectionObjectPointer == SectionObjectPointer) count += 1;
    }
    KeReleaseSpinLock(&SectionLock, irql);
    return count;
}

BOOLEAN SafeUploadStageWritersNameActivating(_In_ PFLT_INSTANCE Instance, _In_ PCUNICODE_STRING Name)
{
    PLIST_ENTRY link;
    BOOLEAN activating = FALSE;
    if (Instance == NULL || Name == NULL || Name->Length == 0) return FALSE;
    FltAcquirePushLockShared(&RegistryLock);
    for (link = RegistryEntries.Flink; link != &RegistryEntries; link = link->Flink) {
        PSTAGE_REGISTRY_ENTRY entry = CONTAINING_RECORD(link, STAGE_REGISTRY_ENTRY, Link);
        UNICODE_STRING entryName;
        if (entry->Retired || !entry->Listed || entry->Instance != Instance ||
            InterlockedCompareExchange(&entry->ActivationEnforced, 0, 0) == 0 ||
            (InterlockedCompareExchange((volatile LONG *)&entry->State, 0, 0) !=
                SAFEUPLOAD_REGISTRY_STATE_ACTIVATING &&
             InterlockedCompareExchange((volatile LONG *)&entry->State, 0, 0) !=
                SAFEUPLOAD_REGISTRY_STATE_UNKNOWN)) continue;
        entryName.Buffer = entry->Name;
        entryName.Length = entryName.MaximumLength = (USHORT)(entry->NameChars * sizeof(WCHAR));
        if (RtlEqualUnicodeString(&entryName, Name, TRUE)) { activating = TRUE; break; }
    }
    FltReleasePushLock(&RegistryLock);
    return activating;
}

BOOLEAN SafeUploadStageWritersAdmissionUnknown(_In_ PFLT_INSTANCE Instance)
{
    PSAFEUPLOAD_INSTANCE_CONTEXT context = NULL;
    BOOLEAN unknown = SafeUploadStageWritersGlobalUnknown() != 0;
    if (!unknown) {
        if (Instance == NULL || !NT_SUCCESS(FltGetInstanceContext(Instance, (PFLT_CONTEXT *)&context))) {
            unknown = TRUE;
        } else {
            unknown = InterlockedCompareExchange(&context->WritersUntracked, 0, 0) != 0 ||
                InterlockedCompareExchange(&context->RegistryUnknownReasons, 0, 0) != 0;
            FltReleaseContext(context);
        }
    }
    return unknown;
}

__declspec(noinline) static PSTAGE_REGISTRY_ENTRY StageRegistryReferenceSop(_In_opt_ PVOID Sop, _In_ BOOLEAN ActivatingOnly)
{
    PSTAGE_REGISTRY_ENTRY entry = NULL;
    ULONG index;
    KIRQL irql;
    if (Sop == NULL) return NULL;
    KeAcquireSpinLock(&SectionLock, &irql);
    for (index = 0; index < RTL_NUMBER_OF(RegistrySopSlots); ++index) {
        PSTAGE_REGISTRY_ENTRY current = RegistrySopSlots[index].Entry;
        if (RegistrySopSlots[index].SectionObjectPointer == Sop && current != NULL) {
            LONG state = InterlockedCompareExchange((volatile LONG *)&current->State, 0, 0);
            if (!ActivatingOnly ||
                (InterlockedCompareExchange(&current->ActivationEnforced, 0, 0) != 0 &&
                 (state == SAFEUPLOAD_REGISTRY_STATE_ACTIVATING || state == SAFEUPLOAD_REGISTRY_STATE_UNKNOWN))) {
                StageRegistryReference(current);
                entry = current;
                break;
            }
        }
    }
    KeReleaseSpinLock(&SectionLock, irql);
    return entry;
}

BOOLEAN SafeUploadStageWritersIsActivatingSop(_In_opt_ PVOID SectionObjectPointer)
{
    PSTAGE_REGISTRY_ENTRY entry = StageRegistryReferenceSop(SectionObjectPointer, TRUE);
    BOOLEAN result = entry != NULL;
    StageRegistryDereference(entry);
    return result;
}

BOOLEAN SafeUploadStageWritersSopMatchesPolicy(_In_opt_ PVOID SectionObjectPointer,
    _In_ BOOLEAN IncludeAncestors, _Out_ PBOOLEAN Known)
{
    PSTAGE_REGISTRY_ENTRY entry;
    BOOLEAN matches = FALSE;
    *Known = FALSE;
    entry = StageRegistryReferenceSop(SectionObjectPointer, FALSE);
    if (entry != NULL) {
        FltAcquirePushLockShared(&RegistryLock);
        if (entry->Listed && !entry->Retired &&
            InterlockedCompareExchangePointer((PVOID volatile *)&entry->SectionObjectPointer,
                NULL, NULL) == SectionObjectPointer) {
            if (entry->NameChars != 0 &&
                entry->NameChars <= SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS) {
                UNICODE_STRING name;
                *Known = TRUE;
                name.Buffer = entry->Name;
                name.Length = name.MaximumLength = (USHORT)(entry->NameChars * sizeof(WCHAR));
                matches = SafeUploadPolicyMatchesCurrentOrPendingDestination(
                    entry->VolumeKind, &name, IncludeAncestors);
            } else if (InterlockedCompareExchange(&entry->ActivationEnforced, 0, 0) != 0) {
                *Known = TRUE;
                /* An unresolved name explicitly classified for activation stays fail closed. */
                matches = TRUE;
            }
        }
        FltReleasePushLock(&RegistryLock);
        StageRegistryDereference(entry);
    }
    return matches;
}

BOOLEAN SafeUploadStageWritersPagingWriteBegin(_In_opt_ PVOID SectionObjectPointer,
    _Outptr_result_maybenull_ PVOID *CompletionContext)
{
    PSTAGE_REGISTRY_ENTRY entry;
    BOOLEAN denied = FALSE;
    BOOLEAN transferred = FALSE;
    KIRQL irql;
    LONG state;
    *CompletionContext = NULL;
    entry = StageRegistryReferenceSop(SectionObjectPointer, TRUE);
    if (entry != NULL) {
        KeAcquireSpinLock(&entry->PagingWriteLock, &irql);
        state = InterlockedCompareExchange((volatile LONG *)&entry->State, 0, 0);
        if (state == SAFEUPLOAD_REGISTRY_STATE_UNKNOWN || state == SAFEUPLOAD_REGISTRY_STATE_PROTECTED ||
            InterlockedCompareExchange(&entry->PagingWriteGateClosed, 0, 0) != 0 ||
            InterlockedCompareExchange(&entry->CutoffComplete, 0, 0) != 0 ||
            InterlockedCompareExchange(&entry->CutoffFailed, 0, 0) != 0) {
            denied = TRUE;
            if (InterlockedCompareExchange(&entry->PagingWriteGateClosed, 0, 0) != 0 ||
                InterlockedCompareExchange(&entry->CutoffComplete, 0, 0) != 0) {
                InterlockedExchange(&entry->DirtyAfterCutoff, 1);
                InterlockedIncrement64(&RegistryChangeSequence);
            }
        } else if (state == SAFEUPLOAD_REGISTRY_STATE_ACTIVATING) {
            if (InterlockedIncrement(&entry->PagingWritesInFlight) == 1)
                KeClearEvent(&entry->PagingWritesDrained);
            *CompletionContext = entry; /* transfer the SOP lookup reference to the lower completion */
            transferred = TRUE;
        }
        KeReleaseSpinLock(&entry->PagingWriteLock, irql);
        if (transferred) return FALSE;
        StageRegistryDereference(entry);
        if (denied) return TRUE;
    }
    return denied;
}

VOID SafeUploadStageWritersPagingWriteEnd(_In_opt_ PVOID CompletionContext)
{
    PSTAGE_REGISTRY_ENTRY entry = (PSTAGE_REGISTRY_ENTRY)CompletionContext;
    KIRQL irql;
    LONG remaining;
    if (entry == NULL) return;
    KeAcquireSpinLock(&entry->PagingWriteLock, &irql);
    if (InterlockedCompareExchange(&entry->PagingWriteGateClosed, 0, 0) != 0 ||
        InterlockedCompareExchange(&entry->CutoffComplete, 0, 0) != 0) {
        InterlockedExchange(&entry->DirtyAfterCutoff, 1);
        InterlockedIncrement64(&RegistryChangeSequence);
    }
    remaining = InterlockedDecrement(&entry->PagingWritesInFlight);
    if (remaining <= 0) {
        if (remaining < 0) InterlockedExchange(&entry->PagingWritesInFlight, 0);
        KeSetEvent(&entry->PagingWritesDrained, IO_NO_INCREMENT, FALSE);
    }
    KeReleaseSpinLock(&entry->PagingWriteLock, irql);
    StageRegistryDereference(entry);
}

VOID SafeUploadStageWritersMutationDraining(_In_ PFLT_INSTANCE Instance,
    _In_opt_ PVOID SectionObjectPointer)
{
    PSTAGE_REGISTRY_ENTRY entry = StageRegistryReferenceSop(SectionObjectPointer, FALSE);
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
        UNICODE_STRING name;
        BOOLEAN newlyScoped = FALSE, nameUnresolved, volumeScoped;
        LONG state;
        if (entry->Retired || !entry->Listed || entry->Instance == NULL || entry->Volume == NULL) continue;
        nameUnresolved = entry->NameChars == 0 ||
            (InterlockedCompareExchange(&entry->UnknownReasons, 0, 0) & SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME) != 0;
        if (entry->NameChars != 0) {
            name.Buffer = entry->Name;
            name.Length = name.MaximumLength = (USHORT)(entry->NameChars * sizeof(WCHAR));
            newlyScoped = SafeUploadPolicyEntryIsNewlyScoped(entry->VolumeKind, &name);
        }
        /* A lost path is scoped by its mounted volume: any current or candidate destination there makes this identity
         * an enforced Unknown. This is the narrowest safe answer when rename history cannot identify its path. */
        volumeScoped = nameUnresolved && SafeUploadPolicyMayMatchVolume(entry->VolumeKind, entry->Volume);
        if (!newlyScoped && !volumeScoped) continue;
        state = InterlockedCompareExchange((volatile LONG *)&entry->State, 0, 0);
        if (volumeScoped) {
            if (entry->NameChars == 0) {
                InterlockedOr(&entry->UnknownReasons, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME);
                /* With no path to index, this identity can alias any candidate
                 * path on its mounted volume; the instance is the narrowest
                 * reliable admission scope. */
                StageRegistryMarkUnknown(entry->Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME, FALSE);
            }
            InterlockedExchange((volatile LONG *)&entry->State, SAFEUPLOAD_REGISTRY_STATE_UNKNOWN);
        } else if (state == SAFEUPLOAD_REGISTRY_STATE_PROTECTED || state == SAFEUPLOAD_REGISTRY_STATE_UNSCOPED) {
            StageRegistryPreparePagingActivation(entry);
        }
        InterlockedExchange(&entry->ActivationEnforced, 1);
        entry->ActivationGeneration = (ULONG)SafeUploadCurrentPolicyGeneration() + 1;
        InterlockedIncrement64(&RegistryChangeSequence);
        queued = TRUE;
    }
    FltReleasePushLock(&RegistryLock);
    if (queued && !StageRegistryQueueReclaim()) {
        /* If no PASSIVE worker can establish the cutoff, keep the affected
         * candidate records Unknown and deny their new writers/paging writes. */
        FltAcquirePushLockExclusive(&RegistryLock);
        for (link = RegistryEntries.Flink; link != &RegistryEntries; link = link->Flink) {
            PSTAGE_REGISTRY_ENTRY entry = CONTAINING_RECORD(link, STAGE_REGISTRY_ENTRY, Link);
            if (InterlockedCompareExchange(&entry->ActivationEnforced, 0, 0) != 0 &&
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
    BOOLEAN activating = FALSE;
    PAGED_CODE();
    FltAcquirePushLockExclusive(&RegistryLock);
    for (link = RegistryEntries.Flink; link != &RegistryEntries; link = link->Flink) {
        PSTAGE_REGISTRY_ENTRY entry = CONTAINING_RECORD(link, STAGE_REGISTRY_ENTRY, Link);
        UNICODE_STRING name;
        BOOLEAN scoped, nameUnresolved;
        LONG state;
        if (entry->Retired || !entry->Listed || entry->Instance == NULL || entry->Volume == NULL ||
            InterlockedCompareExchange(&entry->ActivationEnforced, 0, 0) == 0) continue;
        nameUnresolved = entry->NameChars == 0 ||
            (InterlockedCompareExchange(&entry->UnknownReasons, 0, 0) & SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME) != 0;
        if (nameUnresolved) {
            scoped = SafeUploadPolicyMayMatchVolume(entry->VolumeKind, entry->Volume);
        } else {
            name.Buffer = entry->Name;
            name.Length = name.MaximumLength = (USHORT)(entry->NameChars * sizeof(WCHAR));
            scoped = SafeUploadPolicyEntryIsCurrentlyScoped(entry->VolumeKind, &name);
        }
        state = InterlockedCompareExchange((volatile LONG *)&entry->State, 0, 0);
        if (!scoped) {
            /* A dirty-after-cutoff fact remains in history and prevents promotion if a later
             * expansion reactivates this entry, but an out-of-scope shrink removes admission. */
            StageRegistryClearPagingActivation(entry);
            InterlockedIncrement64(&RegistryChangeSequence);
        } else if (state == SAFEUPLOAD_REGISTRY_STATE_ACTIVATING) {
            entry->ActivationGeneration = (ULONG)SafeUploadCurrentPolicyGeneration();
            activating = TRUE;
        }
    }
    FltReleasePushLock(&RegistryLock);
    if (activating) (VOID)StageRegistryQueueReclaim();
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
    if (StartIndex > SAFEUPLOAD_WRITER_REGISTRY_TOTAL_LIMIT) return STATUS_INVALID_PARAMETER;
    Page->PolicyGeneration = (UINT32)SafeUploadCurrentPolicyGeneration();
    startSequence = (UINT64)InterlockedCompareExchange64(&RegistryChangeSequence, 0, 0);
    FltAcquirePushLockShared(&RegistryLock);
    for (link = RegistryEntries.Flink; link != &RegistryEntries; link = link->Flink) {
        PSTAGE_REGISTRY_ENTRY entry = CONTAINING_RECORD(link, STAGE_REGISTRY_ENTRY, Link);
        if (entry->Retired || (InterlockedCompareExchange(&entry->ActivationEnforced, 0, 0) == 0 &&
            InterlockedCompareExchange(&entry->DirtyAfterCutoff, 0, 0) == 0)) continue;
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
            output->CutoffFlushPairs = (UINT32)max(0,
                InterlockedCompareExchange(&entry->CutoffFlushPairs, 0, 0));
            output->UnknownReasons = (ULONG)InterlockedCompareExchange(&entry->UnknownReasons, 0, 0);
            if (InterlockedCompareExchange(&entry->DirtyAfterCutoff, 0, 0) != 0)
                output->Flags |= SAFEUPLOAD_ACTIVATING_ENTRY_FLAG_DIRTY_AFTER_CUTOFF;
            if (InterlockedCompareExchange(&entry->CutoffComplete, 0, 0) != 0)
                output->Flags |= SAFEUPLOAD_ACTIVATING_ENTRY_FLAG_CUTOFF_COMPLETE;
            if (InterlockedCompareExchange(&entry->CutoffStarted, 0, 0) != 0)
                output->Flags |= SAFEUPLOAD_ACTIVATING_ENTRY_FLAG_CUTOFF_STARTED;
            if (InterlockedCompareExchange(&entry->CutoffFailed, 0, 0) != 0)
                output->Flags |= SAFEUPLOAD_ACTIVATING_ENTRY_FLAG_CUTOFF_FAILED;
            if (InterlockedCompareExchange(&entry->PagingWriteGateClosed, 0, 0) != 0)
                output->Flags |= SAFEUPLOAD_ACTIVATING_ENTRY_FLAG_PAGING_GATE_CLOSED;
            if (InterlockedCompareExchange(&entry->StuckSProbe, 0, 0) != 0)
                output->Flags |= SAFEUPLOAD_ACTIVATING_ENTRY_FLAG_STUCK_S_PROBE;
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
    snapshot.RegistryEntries = RegistryEntryCount;
    snapshot.RegistryReservations = RegistryReservationCount;
    snapshot.RegistryOverflow = RegistryOverflow;
    snapshot.RegistryUnknownReasons = RegistryUnknownReasons;
    snapshot.RegistryInstanceUnknown = RegistryInstanceUnknown;
    snapshot.RegistryCapacity = StageRegistryCapacityLocked();
    snapshot.TransactionAssociations = RegistryAssociationCount;
    FltReleasePushLock(&RegistryLock);
    SafeUploadStageGetUnloadStatus(&snapshot.StageStreams, &snapshot.StageFileObjects,
        &snapshot.LastUnloadVeto, &snapshot.LastUnloadStatus);
    KeAcquireSpinLock(&SectionLock, &irql);
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
    KeReleaseSpinLock(&SectionLock, irql);
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

/* PID outputs are resident caller scratch; callers merge them into pageable replies after release. */
__declspec(noinline) static UINT32 StageRegistrySnapshotC(_In_ PSTAGE_REGISTRY_ENTRY Entry,
    _Out_writes_opt_(Capacity) PUINT32 ProcessIds, _In_ ULONG Capacity,
    _Out_opt_ PUINT32 ProcessIdCount)
{
    ULONG index;
    UINT32 count = 0;
    KIRQL irql;
    if (ProcessIdCount != NULL) *ProcessIdCount = 0;
    KeAcquireSpinLock(&SectionLock, &irql);
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
    KeReleaseSpinLock(&SectionLock, irql);
    return count;
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
    BOOLEAN trusted, reservationInFlight, entryRetired;
    LONG renameVersion, renameInFlight;
    NTSTATUS status;

    PAGED_CODE();
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    RtlZeroMemory(Result, sizeof(*Result));
    Result->StructSize = sizeof(*Result);
    RtlZeroMemory(&identity, sizeof(identity));
    status = FltQueryInformationFile(Instance, SourceObject, &identity, sizeof(identity),
        FileIdInformation, &returned);
    if (status != STATUS_SUCCESS || returned != sizeof(identity)) return STATUS_FILE_INVALID;
    status = FltGetVolumeFromInstance(Instance, &volume);
    if (!NT_SUCCESS(status)) return status;

    FltAcquirePushLockExclusive(&RegistryLock);
    entry = StageRegistryFindByKeyLocked(Instance, volume, identity.VolumeSerialNumber, &identity.FileId);
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
            identity.VolumeSerialNumber, &identity.FileId);
        if (entry != NULL) StageRegistryReference(entry);
        reservationInFlight = StageRegistryHasCreateReservationLocked(Instance, volume, NormalizedName);
        globalUnknown = SafeUploadStageWritersGlobalUnknown() != 0;
        FltReleasePushLock(&RegistryLock);
        if (entry == NULL) {
            Result->HistoryPresent = 0;
            Result->NameMatches = 1;
            unknown = 0;
            if (unknownInstance || globalUnknown) unknown |= SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY;
            if (!trusted) unknown |= SAFEUPLOAD_REGISTRY_UNKNOWN_TRUST;
            if (reservationInFlight) unknown |= SAFEUPLOAD_REGISTRY_UNKNOWN_CREATE_IN_FLIGHT;
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
    if (renameInFlight != 0 || renameVersion !=
        InterlockedCompareExchange(&entry->RenameVersion, 0, 0))
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
            Result->NameMatches = RtlEqualUnicodeString(&retained, NormalizedName, TRUE) ? 1 : 0;
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
    if (renameInFlight != 0 || renameVersion !=
        InterlockedCompareExchange(&entry->RenameVersion, 0, 0))
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
