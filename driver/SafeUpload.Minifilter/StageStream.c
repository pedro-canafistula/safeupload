/* Original-stack, owned FCB/cache data path. See STAGED-WRITES.md for the
 * lock order, version retirement gate and the intentionally bounded namespace.
 * Every operation on one of our upper objects is completed or routed here. */
#include "Filter.h"
#include "Stage.h"
#include "StageSecurity.h"
#include <ntstrsafe.h>

#if SAFEUPLOAD_STAGING_PROTOTYPE
static VOID StageAdmissionTraceShutdown(VOID);
static NTSTATUS StageAdmissionProbeWorkerBody(_In_ PCUNICODE_STRING VolumeName,
    _In_ PCUNICODE_STRING RelativePath);
#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SafeUploadStageAdmissionTraceControl)
#pragma alloc_text(PAGE, SafeUploadStageAdmissionTraceReadBatch)
#pragma alloc_text(PAGE, SafeUploadStageAdmissionProbe)
#pragma alloc_text(PAGE, StageAdmissionProbeWorkerBody)
#pragma alloc_text(PAGE, StageAdmissionTraceShutdown)
#endif
#endif

#define STAGE_TAG 'sUpS'
#define STAGE_LIMIT 128
#define STAGE_MAX_BYTES (16 * 1024 * 1024)

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
    NTSTATUS DrainStatus;
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
} STAGE_STREAM, *PSTAGE_STREAM;

typedef struct _STAGE_HANDLE {
    PSTAGE_STREAM Stream;
    ACCESS_MASK GrantedAccess;
    BOOLEAN Cleaned;
    ULONG LockOwnerCount;
    PEPROCESS LockOwners[16]; /* Duplicate handles can issue locks in other processes. */
} STAGE_HANDLE, *PSTAGE_HANDLE;

static LIST_ENTRY StageStreams;
static KSPIN_LOCK StageListLock;
static ERESOURCE StageNamespaceResource;
static volatile ULONG StageStreamCount;
static volatile LONG64 StageLastUnloadVeto;
static LONG64 StageNamespaceSequence;
static volatile LONG StageFileObjects;
static BOOLEAN StageStopping;
static LIST_ENTRY StageViews;
static KEVENT StageWorkerStop;
static HANDLE StageWorkerHandle;
static BOOLEAN StageInitialized;

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

NTSTATUS SafeUploadStageAdmissionTraceControl(_In_ UINT32 Command, _In_ UINT32 Options)
{
    LONG state;
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
        InterlockedExchange(&SafeUploadAdmissionTraceControlState,
                            StageAdmissionTraceNextState(state, FALSE));
        if (!AdmissionTraceRundownClosed) {
            ExWaitForRundownProtectionRelease(&AdmissionTraceRundown);
            AdmissionTraceRundownClosed = TRUE;
        }

        if (Command == SAFEUPLOAD_CONTROL_ADMISSION_TRACE_CLEAR) {
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
    if (InterlockedCompareExchange(&streamContext->WriteObjects, 0, 0) <= 0) {
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
#endif

typedef struct _STAGE_OLD_NAME {
    LIST_ENTRY Link;
    UNICODE_STRING Name;
    LONG64 Sequence;
    PSTAGE_STREAM Version; /* The durable tombstone belongs to the renamed GUID. */
} STAGE_OLD_NAME, *PSTAGE_OLD_NAME;

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
    PSTAGE_STREAM Current;
    LIST_ENTRY OldNames;
    UNICODE_STRING Name;
    WCHAR NameBuffer[SAFEUPLOAD_MAX_PATH_CHARS];
} STAGE_VIEW, *PSTAGE_VIEW;

static FLT_PREOP_CALLBACK_STATUS StagePreOperation(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, PVOID *CompletionContext);

static PSTAGE_STREAM StageStreamForObject(PFILE_OBJECT FileObject)
{
    PLIST_ENTRY link;
    KIRQL irql;
    PSTAGE_STREAM found = NULL;
    if (FileObject == NULL || FileObject->FsContext == NULL) return NULL;
    KeAcquireSpinLock(&StageListLock, &irql);
    for (link = StageStreams.Flink; link != &StageStreams; link = link->Flink) {
        PSTAGE_STREAM stream = CONTAINING_RECORD(link, STAGE_STREAM, Link);
        if (FileObject->FsContext == &stream->Header) { found = stream; break; }
    }
    KeReleaseSpinLock(&StageListLock, irql);
    /* Streams remain allocated until unregister has drained all callbacks. */
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
    KeEnterCriticalRegion();
    if (!ExAcquireResourceSharedLite(&stream->PagingResource, Wait)) {
        KeLeaveCriticalRegion();
        return FALSE;
    }
    return TRUE;
}

static VOID StageCacheRelease(PVOID Context)
{
    PSTAGE_STREAM stream = Context;
    StageRelease(&stream->PagingResource);
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

static NTSTATUS StageFlush(PSTAGE_STREAM Stream)
{
    IO_STATUS_BLOCK io = {0};
    if (Stream->Sections.DataSectionObject != NULL) {
        CcFlushCache(&Stream->Sections, NULL, 0, &io);
        if (!NT_SUCCESS(io.Status)) return io.Status;
    }
    return Stream->ReadOnly ? STATUS_SUCCESS : FltFlushBuffers(Stream->BackingInstance, Stream->BackingObject);
}

static VOID StageFreeStream(PSTAGE_STREAM Stream)
{
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

static NTSTATUS StageOpenBacking(PSTAGE_STREAM Stream, BOOLEAN ReadOnly)
{
    UNICODE_STRING drive = RTL_CONSTANT_STRING(L"\\??\\C:");
    PFLT_VOLUME volume = NULL, sourceVolume = NULL;
    PDEVICE_OBJECT sourceDevice = NULL, backingDevice = NULL;
    FLT_VOLUME_PROPERTIES properties;
    ULONG needed;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io;
    FILE_STANDARD_INFORMATION standard;
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
    InitializeObjectAttributes(&attributes, &Stream->StageName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = FltCreateFileEx2(SafeUploadData.Filter, Stream->BackingInstance,
        &Stream->BackingHandle, &Stream->BackingObject,
        FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE |
            (ReadOnly ? 0 : FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES),
        &attributes, &io, NULL, FILE_ATTRIBUTE_NORMAL, ReadOnly ? FILE_SHARE_READ : 0, FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_NO_INTERMEDIATE_BUFFERING,
        NULL, 0, IO_STOP_ON_SYMLINK, NULL);
    if (status == STATUS_STOPPED_ON_SYMLINK && io.Information != 0) ExFreePool((PVOID)io.Information);
    if (!NT_SUCCESS(status)) goto Exit;
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

static PSTAGE_STREAM StageHiddenStream(PEPROCESS Owner, PUNICODE_STRING Name)
{
    PLIST_ENTRY link, old;
    PSTAGE_STREAM found = NULL;
    LONG64 newest = 0;
    for (link = StageViews.Flink; link != &StageViews; link = link->Flink) {
        PSTAGE_VIEW view = CONTAINING_RECORD(link, STAGE_VIEW, Link);
        if (view->Owner != Owner) continue;
        for (old = view->OldNames.Flink; old != &view->OldNames; old = old->Flink) {
            PSTAGE_OLD_NAME tombstone = CONTAINING_RECORD(old, STAGE_OLD_NAME, Link);
            if (tombstone->Sequence > newest && RtlEqualUnicodeString(&tombstone->Name, Name, TRUE)) {
                newest = tombstone->Sequence;
                found = tombstone->Version;
            }
        }
    }
    return found;
}

static BOOLEAN StageHiddenName(PEPROCESS Owner, PUNICODE_STRING Name)
{
    return StageHiddenStream(Owner, Name) != NULL;
}

static VOID StageFreeView(PSTAGE_VIEW View)
{
    while (!IsListEmpty(&View->OldNames)) ExFreePoolWithTag(CONTAINING_RECORD(
        RemoveHeadList(&View->OldNames), STAGE_OLD_NAME, Link), STAGE_TAG);
    if (View->Owner != NULL) ObDereferenceObject(View->Owner);
    SafeUploadStageFreeSecurity(View->Security, View->AssignedSecurity);
    ExFreePoolWithTag(View, STAGE_TAG);
}

/* NamespaceResource serializes CREATE, rotation, retarget and retirement.
 * An upper FILE_OBJECT references a version, never a mutable current pointer. */
static NTSTATUS StageCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS Objects,
    PFLT_FILE_NAME_INFORMATION Name, SAFEUPLOAD_VOLUME_KIND Kind, BOOLEAN Writer,
    PSTAGE_VIEW ExpectedView, BOOLEAN PrivateNamespace, PBOOLEAN Handled)
{
    PSTAGE_VIEW view = NULL;
    PSTAGE_STREAM hiddenStream = NULL;
    PSTAGE_STREAM stream = NULL;
    PSTAGE_HANDLE handle = NULL;
    PFILE_OBJECT file = Data->Iopb->TargetFileObject;
    ACCESS_MASK desired = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    ACCESS_MASK granted = 0;
    ULONG disposition = Data->Iopb->Parameters.Create.Options >> 24;
    ULONG information = FILE_OPENED;
    PEPROCESS owner = FltGetRequestorProcess(Data);
    BOOLEAN newView = FALSE, newStream = FALSE, exists = FALSE;
    FLT_FILESYSTEM_TYPE fs;
    WCHAR basename[SAFEUPLOAD_MAX_STAGE_NAME_CHARS];
    USHORT basenameLength;
    KIRQL irql;
    NTSTATUS status = STATUS_SUCCESS;
    *Handled = TRUE;
    if (owner == NULL) return STATUS_ACCESS_DENIED;
    StageAcquire(&StageNamespaceResource);
    if (StageStopping) { status = STATUS_DEVICE_NOT_READY; goto Exit; }
    view = StageFindView(owner, &Name->Name);
    /* A name snapshot for a file-ID open must still name that same live view.
     * Rename/replacement between lookup and admission must never create a new
     * view or return the newly occupying file. Views remain allocated to unload. */
    if (ExpectedView != NULL && (view != ExpectedView ||
        view->Current->OriginalInstance != Objects->Instance)) {
        status = STATUS_SHARING_VIOLATION; goto Exit;
    }
    if (view == NULL) hiddenStream = StageHiddenStream(owner, &Name->Name);
    if (hiddenStream != NULL) {
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
        (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_OPEN_BY_FILE_ID) && ExpectedView == NULL) ||
        FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE |
            FILE_DELETE_ON_CLOSE | FILE_NO_INTERMEDIATE_BUFFERING) ||
        file->FsContext != NULL || file->FsContext2 != NULL) {
        status = STATUS_NOT_SUPPORTED; goto Exit;
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
        InitializeListHead(&view->OldNames);
        status = SafeUploadStageCaptureSecurity(Data, Objects->Instance, &Name->Name, hiddenStream != NULL,
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
            if (exists || hiddenStream != NULL) {
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
    } else {
        exists = TRUE;
        if (disposition == FILE_CREATE) { status = STATUS_OBJECT_NAME_COLLISION; goto Exit; }
        status = SafeUploadStageCheckAccess(Data, view->Security, desired, &granted);
        if (!NT_SUCCESS(status)) goto Exit;
        stream = view->Current;
        if (stream->RenameExchange != NULL || (stream->ReadOnly && !stream->Sealed)) {
            status = STATUS_SHARING_VIOLATION; goto Exit;
        }
    }
    if (stream == NULL || (Writer && stream->Sealed)) {
        PSTAGE_STREAM previous = stream;
        if (StageStreamCount == STAGE_LIMIT) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
        stream = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*stream), STAGE_TAG);
        if (stream == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
        newStream = TRUE;
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
            hiddenStream != NULL ? &hiddenStream->StageName : NULL, basename, &basenameLength);
        if (!NT_SUCCESS(status)) goto Exit;
        if (newView) {
            status = StageSetIdentity(view, basename);
            if (!NT_SUCCESS(status)) goto Exit;
        }
        status = RtlStringCchPrintfW(stream->StageBuffer, SAFEUPLOAD_MAX_PATH_CHARS,
            L"\\??\\C:\\ProgramData\\SafeUpload\\staging\\%ws", basename);
        if (!NT_SUCCESS(status)) goto Exit;
        RtlInitUnicodeString(&stream->StageName, stream->StageBuffer);
        status = StageOpenBacking(stream, FALSE);
        if (!NT_SUCCESS(status)) goto Exit;
    }
    if (FLT_IS_IRP_OPERATION(Data) && FltIsIoCanceled(Data)) {
        status = STATUS_CANCELLED; goto Exit;
    }
    handle = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*handle), STAGE_TAG);
    if (handle == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    StageAcquire(&stream->Resource);
    status = IoCheckShareAccess(granted, Data->Iopb->Parameters.Create.ShareAccess,
        file, &stream->ShareAccess, FALSE);
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
        file->FsContext = &stream->Header;
        file->FsContext2 = handle;
        file->SectionObjectPointer = &stream->Sections;
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
    if (newStream) {
        KeAcquireSpinLock(&StageListLock, &irql);
        InsertTailList(&StageStreams, &stream->Link);
        KeReleaseSpinLock(&StageListLock, irql);
        StageStreamCount++;
        view->Current = stream;
    }
    if (newView) InsertTailList(&StageViews, &view->Link);
Exit:
    if (!NT_SUCCESS(status)) {
        if (handle != NULL) ExFreePoolWithTag(handle, STAGE_TAG);
        if (newStream) StageFreeStream(stream);
        if (newView) StageFreeView(view);
        /* A durable allocation whose CREATE failed remains unsealed for recovery. */
    }
    StageRelease(&StageNamespaceResource);
    return status;
}


/* Materialize the extended range with ordinary noncached backing writes.
 * Paging writes do not advance NTFS's valid data length. Claiming a larger
 * upper VDL without zeroing could expose old disk contents when Cc advances it.
 * Preserve an existing partial sector; the backing has no second data cache. */
static NTSTATUS StageZeroGrowth(PSTAGE_STREAM Stream, LARGE_INTEGER Size)
{
    PVOID buffer;
    LARGE_INTEGER offset;
    LONGLONG rounded = (Size.QuadPart + Stream->SectorSize - 1) & ~((LONGLONG)Stream->SectorSize - 1);
    ULONG length, transferred, tail;
    NTSTATUS status;
    if (Size.QuadPart <= Stream->Header.FileSize.QuadPart) return STATUS_SUCCESS;
    status = StageFlush(Stream);
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

static NTSTATUS StageResize(PSTAGE_STREAM Stream, PFILE_OBJECT FileObject, LARGE_INTEGER Size)
{
    FILE_END_OF_FILE_INFORMATION end;
    CC_FILE_SIZES sizes;
    NTSTATUS status;
    NT_ASSERT(ExIsResourceAcquiredExclusiveLite(&Stream->Resource));
    if (Stream->ReadOnly || Stream->RenameExchange != NULL) return STATUS_ACCESS_DENIED;
    if (Size.QuadPart < 0 || Size.QuadPart > STAGE_MAX_BYTES) return STATUS_FILE_TOO_LARGE;
    if (Size.QuadPart < Stream->Header.FileSize.QuadPart &&
        !MmCanFileBeTruncated(&Stream->Sections, &Size)) return STATUS_USER_MAPPED_FILE;
    status = StageZeroGrowth(Stream, Size);
    if (!NT_SUCCESS(status)) return status;
    end.EndOfFile = Size;
    status = FltSetInformationFile(Stream->BackingInstance, Stream->BackingObject,
        &end, sizeof(end), FileEndOfFileInformation);
    if (!NT_SUCCESS(status)) return status;
    Stream->Header.FileSize = Size;
    Stream->Header.AllocationSize.QuadPart = (Size.QuadPart + PAGE_SIZE - 1) & ~((LONGLONG)PAGE_SIZE - 1);
    Stream->Header.ValidDataLength = Size; /* Every extended byte was materialized. */
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
            cls == FileNetworkOpenInformation || cls == FileAttributeTagInformation) {
            status = FltQueryInformationFile(Stream->BackingInstance, Stream->BackingObject,
                output, length, cls, &returned);
            Data->IoStatus.Information = returned;
            if (NT_SUCCESS(status) && cls == FileStandardInformation) {
                ((PFILE_STANDARD_INFORMATION)output)->EndOfFile = Stream->Header.FileSize;
                ((PFILE_STANDARD_INFORMATION)output)->AllocationSize = Stream->Header.AllocationSize;
            }
        } else status = STATUS_NOT_SUPPORTED;
    } __except(EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
    StageRelease(&Stream->Resource);
    return status;
}

static BOOLEAN StageExchange(PSAFEUPLOAD_EXCHANGE Exchange)
{
    BOOLEAN answered = FALSE;
    UINT32 verdict;
    NTSTATUS status = SafeUploadRequestVerdict(Exchange, &verdict, &answered);
    return status == STATUS_SUCCESS && answered && verdict == SAFEUPLOAD_VERDICT_ALLOW;
}

/* Retrying uses the SAME request ID. Until acknowledgement, the namespace is
 * frozen and retirement is impossible. A lost prepare becomes an abort. */
static VOID StageFinishRename(PSTAGE_STREAM Stream)
{
    if (Stream->RenameExchange != NULL && StageExchange(Stream->RenameExchange)) {
        PSAFEUPLOAD_EXCHANGE exchange;
        StageAcquire(&Stream->Resource);
        exchange = Stream->RenameExchange;
        Stream->RenameExchange = NULL;
        StageRelease(&Stream->Resource);
        ExFreePoolWithTag(exchange, STAGE_TAG);
    }
}

static NTSTATUS StageRename(PFLT_CALLBACK_DATA Data, PSTAGE_STREAM Stream)
{
    PFILE_RENAME_INFORMATION rename = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    PFLT_FILE_NAME_INFORMATION destination = NULL;
    PSTAGE_VIEW view = Stream->View, target = NULL;
    PSTAGE_OLD_NAME old = NULL;
    PSAFEUPLOAD_EXCHANGE exchange = NULL;
    ULONG length = Data->Iopb->Parameters.SetFileInformation.Length;
    ULONG basename;
    BOOLEAN extended = Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformationEx;
    BOOLEAN replace, posix;
    NTSTATUS status;
    if (!Data->Iopb->TargetFileObject->DeleteAccess) return STATUS_ACCESS_DENIED;
    if (rename == NULL || length < (ULONG)FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName) ||
        rename->FileNameLength == 0 || (rename->FileNameLength & 1) ||
        rename->FileNameLength > length - FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName))
        return STATUS_INVALID_PARAMETER;
    replace = extended ? BooleanFlagOn(*(PULONG)rename, FILE_RENAME_REPLACE_IF_EXISTS) : rename->ReplaceIfExists;
    posix = extended && BooleanFlagOn(*(PULONG)rename, FILE_RENAME_POSIX_SEMANTICS);
    if (extended && FlagOn(*(PULONG)rename, ~(FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS)))
        return STATUS_NOT_SUPPORTED;
    StageAcquire(&StageNamespaceResource);
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
    target = StageFindView(view->Owner, &destination->Name);
    if (target != NULL && !replace) { status = STATUS_OBJECT_NAME_COLLISION; goto Exit; }
    StageAcquire(&Stream->Resource);
    status = Stream->ShareAccess.OpenCount == Stream->ShareAccess.SharedDelete ?
        STATUS_SUCCESS : STATUS_SHARING_VIOLATION;
    StageRelease(&Stream->Resource);
    if (!NT_SUCCESS(status)) goto Exit;
    if (target != NULL) {
        PSTAGE_STREAM replaced = target->Current;
        status = SafeUploadStageCheckSubjectAccess(Data, target->Security, DELETE);
        if (!NT_SUCCESS(status)) goto Exit;
        StageAcquire(&replaced->Resource);
        if (replaced->RenameExchange != NULL || (replaced->ReadOnly && !replaced->Sealed) ||
            (!posix && replaced->ShareAccess.OpenCount != 0) ||
            replaced->ShareAccess.OpenCount != replaced->ShareAccess.SharedDelete ||
            replaced->Sections.ImageSectionObject != NULL)
            status = STATUS_SHARING_VIOLATION;
        StageRelease(&replaced->Resource);
        if (!NT_SUCCESS(status)) goto Exit;
    }
    status = SafeUploadStageCheckRenameAccess(Data, Stream->OriginalInstance, &destination->Name, replace);
    if (!NT_SUCCESS(status)) goto Exit;
    old = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*old) + view->Name.Length, STAGE_TAG);
    exchange = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*exchange), STAGE_TAG);
    if (old == NULL || exchange == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    old->Name.Buffer = (PWCH)(old + 1);
    old->Name.Length = old->Name.MaximumLength = view->Name.Length;
    RtlCopyMemory(old->Name.Buffer, view->Name.Buffer, view->Name.Length);
    exchange->Request.Version = SAFEUPLOAD_PROTOCOL_VERSION;
    exchange->Request.StructSize = sizeof(SAFEUPLOAD_REQUEST);
    exchange->Request.RequestId = (UINT64)InterlockedIncrement64(&SafeUploadData.NextRequestId);
    exchange->Request.Operation = SAFEUPLOAD_OPERATION_STAGE_RENAME;
    exchange->Request.RequestorProcessId = view->OwnerProcessId;
    exchange->Request.Reserved = Stream->Sealed ? 1 : 0;
    exchange->Request.PathLength = destination->Name.Length;
    RtlCopyMemory(exchange->Request.Path, destination->Name.Buffer, destination->Name.Length);
    basename = Stream->StageName.Length / sizeof(WCHAR);
    while (basename > 0 && Stream->StageName.Buffer[basename - 1] != L'\\') --basename;
    exchange->Request.ImageNameLength = 32 * sizeof(WCHAR);
    RtlCopyMemory(exchange->Request.ImageName, Stream->StageName.Buffer + basename, 32 * sizeof(WCHAR));
    StageAcquire(&Stream->Resource);
    Stream->RenameExchange = exchange;
    StageRelease(&Stream->Resource);
    exchange = NULL; /* Stream owns uncertain transactions through disconnect. */
    if (!StageExchange(Stream->RenameExchange)) {
        Stream->RenameExchange->Request.Operation = SAFEUPLOAD_OPERATION_STAGE_RENAME_ABORT;
        status = STATUS_SHARING_VIOLATION; goto Exit;
    }
    StageAcquire(&Stream->Resource);
    if (target != NULL) target->Detached = TRUE;
    RtlCopyUnicodeString(&Stream->Name, &destination->Name);
    RtlCopyUnicodeString(&view->Name, &destination->Name);
    old->Sequence = ++StageNamespaceSequence; /* Caller owns namespace resource. */
    old->Version = Stream;
    InsertTailList(&view->OldNames, &old->Link); old = NULL;
    StageRelease(&Stream->Resource);
    Stream->RenameExchange->Request.Operation = SAFEUPLOAD_OPERATION_STAGE_RENAME_COMMIT;
    StageFinishRename(Stream);
    (VOID)FltPurgeFileNameInformationCache(Stream->OriginalInstance, NULL);
    status = STATUS_SUCCESS;
Exit:
    if (exchange != NULL) ExFreePoolWithTag(exchange, STAGE_TAG);
    if (old != NULL) ExFreePoolWithTag(old, STAGE_TAG);
    if (destination != NULL) FltReleaseFileNameInformation(destination);
    StageRelease(&StageNamespaceResource);
    return status;
}

typedef struct _STAGE_PAGING_IO {
    PSTAGE_STREAM Stream;
    PFLT_CALLBACK_DATA Original;
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
    }
    StageReleasePagingIo(io);
}

static FLT_PREOP_CALLBACK_STATUS StageRoutePaging(PFLT_CALLBACK_DATA Data,
    PSTAGE_STREAM Stream)
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


static FLT_PREOP_CALLBACK_STATUS StagePreOperation(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, PVOID *CompletionContext)
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
            return StageRoutePaging(Data, stream);
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
            return StageRoutePaging(Data, stream);
        }
        if (handle == NULL || handle->Cleaned) {
            status = STATUS_FILE_CLOSED;
            break;
        }
        if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation ||
            Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformationEx)
            status = StageRename(Data, stream);
        else if ((stream->ReadOnly || stream->RenameExchange != NULL) &&
            Data->Iopb->Parameters.SetFileInformation.FileInformationClass != FilePositionInformation) {
            status = STATUS_ACCESS_DENIED;
        }
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
            StageAcquire(&stream->Resource);
            stream->DrainStatus = StageFlush(stream);
            IoRemoveShareAccess(file, &stream->ShareAccess);
            handle->Cleaned = TRUE;
            /* Cleanup can run in a different process from a lock issued via
             * a duplicate. Retain and unlock every participating process. */
            for (index = 0; index < handle->LockOwnerCount; ++index)
                (VOID)FsRtlFastUnlockAll(stream->ByteLocks, file, handle->LockOwners[index], NULL);
            SetFlag(file->Flags, FO_CLEANUP_COMPLETE);
            (VOID)CcUninitializeCacheMap(file, NULL, NULL);
            StageRelease(&stream->Resource);
        }
        status = STATUS_SUCCESS;
        break;
    case IRP_MJ_CLOSE:
        if (handle != NULL) {
            ULONG index;
            for (index = 0; index < handle->LockOwnerCount; ++index)
                ObDereferenceObject(handle->LockOwners[index]);
            ExFreePoolWithTag(handle, STAGE_TAG);
            file->FsContext2 = NULL;
            InterlockedDecrement(&StageFileObjects);
            InterlockedDecrement(&stream->FileObjects);
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
    if (!NT_SUCCESS(status) || Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[SafeUploadStage] op=%u class=%u status=%08x\n", Data->Iopb->MajorFunction,
            Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION ?
                Data->Iopb->Parameters.SetFileInformation.FileInformationClass : 0, status);
    }
    return FLT_PREOP_COMPLETE;
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
        StageAcquire(&stream->Resource);
        status = FltCheckAndGrowNameControl(Output, stream->Name.Length);
        if (NT_SUCCESS(status)) RtlCopyUnicodeString(&Output->Name, &stream->Name);
        StageRelease(&stream->Resource);
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
    if (Stream->ShareAccess.OpenCount != 0 || !MmCanFileBeTruncated(&Stream->Sections, NULL))
        return STATUS_DEVICE_BUSY;
    status = StageFlush(Stream);
    if (!NT_SUCCESS(status)) return status;
    if (!CcPurgeCacheSection(&Stream->Sections, NULL, 0, TRUE) ||
        Stream->Sections.SharedCacheMap != NULL || Stream->Sections.DataSectionObject != NULL ||
        Stream->Sections.ImageSectionObject != NULL ||
        InterlockedCompareExchange(&Stream->FileObjects, 0, 0) != 0) return STATUS_DEVICE_BUSY;
    /* Postoperations, including asynchronous paging and Cc AdvanceOnly, release
     * this rundown. It is forbidden to close the backing before they finish. */
    ExWaitForRundownProtectionRelease(&Stream->PagingRundown);
    status = Stream->ReadOnly ? STATUS_SUCCESS : FltFlushBuffers(Stream->BackingInstance, Stream->BackingObject);
    ExReInitializeRundownProtection(&Stream->PagingRundown);
    return status;
}

static KSTART_ROUTINE StageWorker;
static VOID StageWorker(PVOID Context)
{
    LARGE_INTEGER interval;
    PLIST_ENTRY link;
    UNREFERENCED_PARAMETER(Context);
    interval.QuadPart = -250 * 10000LL;
    while (KeWaitForSingleObject(&StageWorkerStop, Executive, KernelMode, FALSE, &interval) == STATUS_TIMEOUT) {
        StageAcquire(&StageNamespaceResource);
        if (!StageStopping) for (link = StageStreams.Flink; link != &StageStreams; link = link->Flink) {
            PSTAGE_STREAM stream = CONTAINING_RECORD(link, STAGE_STREAM, Link);
            NTSTATUS status = STATUS_SUCCESS;
            if (stream->RenameExchange != NULL) StageFinishRename(stream);
            if (stream->Sealed || stream->RenameExchange != NULL) continue;
            StageAcquire(&stream->Resource);
            if (!stream->ReadOnly) {
                status = StageDrain(stream);
                if (NT_SUCCESS(status)) {
                    StageCloseBacking(stream);
                    stream->ReadOnly = TRUE; /* Irreversible, even if reopen/notification fails. */
                }
            }
            if (NT_SUCCESS(status) && stream->BackingObject == NULL) status = StageOpenBacking(stream, TRUE);
            StageRelease(&stream->Resource);
            if (NT_SUCCESS(status)) {
                status = SafeUploadStageSeal(stream->View->OwnerProcessId, &stream->StageName);
                if (NT_SUCCESS(status)) stream->Sealed = TRUE;
            }
        }
        StageRelease(&StageNamespaceResource);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS SafeUploadStageInitialize(VOID)
{
    NTSTATUS status;
    InitializeListHead(&StageStreams);
    InitializeListHead(&StageViews);
    KeInitializeSpinLock(&StageListLock);
    KeInitializeEvent(&StageWorkerStop, NotificationEvent, FALSE);
    SafeUploadStageInitializeProtocol();
    status = ExInitializeResourceLite(&StageNamespaceResource);
    if (NT_SUCCESS(status)) {
#if SAFEUPLOAD_STAGING_PROTOTYPE
        SafeUploadStageWritersInitialize();
        status = SafeUploadStageFenceInitialize();
        if (!NT_SUCCESS(status)) return status;
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

NTSTATUS SafeUploadStageStartWorker(VOID)
{
    OBJECT_ATTRIBUTES attributes;
    NTSTATUS status;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    status = SafeUploadStageAdmissionStartWorker();
    if (!NT_SUCCESS(status)) return status;
#endif
    InitializeObjectAttributes(&attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = PsCreateSystemThread(&StageWorkerHandle, SYNCHRONIZE, &attributes, NULL, NULL, StageWorker, NULL);
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (!NT_SUCCESS(status)) SafeUploadStageAdmissionStopWorker();
#endif
    return status;
}

VOID SafeUploadStageStopWorker(VOID)
{
    if (StageWorkerHandle != NULL) {
        KeSetEvent(&StageWorkerStop, IO_NO_INCREMENT, FALSE);
        (VOID)ZwWaitForSingleObject(StageWorkerHandle, FALSE, NULL);
        ZwClose(StageWorkerHandle); StageWorkerHandle = NULL;
    }
#if SAFEUPLOAD_STAGING_PROTOTYPE
    SafeUploadStageAdmissionStopWorker();
#endif
}

BOOLEAN SafeUploadStageCanDetach(VOID)
{
    return StageStreamCount == 0;
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

NTSTATUS SafeUploadStagePrepareUnload(VOID)
{
    PLIST_ENTRY link;
    NTSTATUS status = STATUS_SUCCESS;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    /* Rescan to drop stale entries, then refuse while a fenced mapped stream remains: unloading would
     * release its old view's writes. Before any namespace lock, so the scan never nests inside one. */
    SafeUploadStageRecordUnloadVeto(SAFEUPLOAD_UNLOAD_VETO_NONE, STATUS_SUCCESS);
    status = SafeUploadStageFencePrepareUnload();
    if (!NT_SUCCESS(status)) {
        SafeUploadStageRecordUnloadVeto(SAFEUPLOAD_UNLOAD_VETO_FENCE, status);
        return STATUS_FLT_DO_NOT_DETACH;
    }
#endif
    StageAcquire(&StageNamespaceResource);
    StageStopping = TRUE;
    for (link = StageStreams.Flink; link != &StageStreams; link = link->Flink) {
        PSTAGE_STREAM stream = CONTAINING_RECORD(link, STAGE_STREAM, Link);
        StageAcquire(&stream->Resource);
        status = StageDrain(stream);
        StageRelease(&stream->Resource);
        if (!NT_SUCCESS(status)) break;
    }
    if (!NT_SUCCESS(status) || InterlockedCompareExchange(&StageFileObjects, 0, 0) != 0) {
        SafeUploadStageRecordUnloadVeto(!NT_SUCCESS(status) ? SAFEUPLOAD_UNLOAD_VETO_STAGE_DRAIN :
            SAFEUPLOAD_UNLOAD_VETO_STAGE_OBJECTS, !NT_SUCCESS(status) ? status : STATUS_DEVICE_BUSY);
        StageStopping = FALSE;
        StageRelease(&StageNamespaceResource);
        return STATUS_FLT_DO_NOT_DETACH;
    }
    StageRelease(&StageNamespaceResource);
#if SAFEUPLOAD_STAGING_PROTOTYPE
    /* This is the unload's commit point: every fallible stage check has completed, and no setup,
     * scan, or quarantine may appear after it. A veto is still reversible because the worker and
     * backing objects have not yet been stopped or released. */
    if (!SafeUploadStageFenceTryCommitUnload()) {
        SafeUploadStageRecordUnloadVeto(SAFEUPLOAD_UNLOAD_VETO_FENCE_COMMIT, STATUS_DEVICE_BUSY);
        StageAcquire(&StageNamespaceResource);
        StageStopping = FALSE;
        StageRelease(&StageNamespaceResource);
        return STATUS_FLT_DO_NOT_DETACH;
    }
#endif
    SafeUploadStageStopWorker();
    /* Instance references must be dropped BEFORE FltUnregisterFilter. */
    for (link = StageStreams.Flink; link != &StageStreams; link = link->Flink) {
        PSTAGE_STREAM stream = CONTAINING_RECORD(link, STAGE_STREAM, Link);
        ExWaitForRundownProtectionRelease(&stream->PagingRundown);
        StageCloseBacking(stream);
        if (stream->BackingInstance != NULL) FltObjectDereference(stream->BackingInstance);
        stream->BackingInstance = NULL;
        if (stream->OriginalInstance != NULL) FltObjectDereference(stream->OriginalInstance);
        stream->OriginalInstance = NULL;
    }
    return STATUS_SUCCESS;
}

VOID SafeUploadStageFree(VOID)
{
    if (!StageInitialized) return;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    StageAdmissionTraceShutdown();
    SafeUploadStageFenceFree();
#endif
    while (!IsListEmpty(&StageStreams)) {
        PSTAGE_STREAM stream = CONTAINING_RECORD(RemoveHeadList(&StageStreams), STAGE_STREAM, Link);
        FsRtlTeardownPerStreamContexts(&stream->Header);
        StageFreeStream(stream);
    }
    while (!IsListEmpty(&StageViews)) StageFreeView(CONTAINING_RECORD(RemoveHeadList(&StageViews), STAGE_VIEW, Link));
    ExDeleteResourceLite(&StageNamespaceResource);
    StageInitialized = FALSE;
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
/* A directory opened with FILE_DELETE_ON_CLOSE is deleted at cleanup without any SET_INFORMATION. Refuse it when the
 * directory is, or lies above, a protected prefix; a name that cannot be resolved is refused too (the case is rare). */
static FLT_PREOP_CALLBACK_STATUS StageDirectoryDeleteOnClose(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS Objects)
{
    PFLT_FILE_NAME_INFORMATION name = NULL;
    SAFEUPLOAD_VOLUME_KIND kind = StageVolumeKind(Objects->Instance);
    BOOLEAN deny;
    NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name);

    deny = !NT_SUCCESS(status) || SafeUploadStageTouchesProtectedNamespace(name, kind);
    if (name != NULL) FltReleaseFileNameInformation(name);
    if (!deny) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}
#endif

static FLT_PREOP_CALLBACK_STATUS StageAdmit(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects)
{
    PFLT_FILE_NAME_INFORMATION name = NULL;
    PFLT_FILE_NAME_INFORMATION privateName = NULL;
    PSTAGE_VIEW expectedView = NULL;
    PIO_SECURITY_CONTEXT security = Data->Iopb->Parameters.Create.SecurityContext;
    ULONG disposition = Data->Iopb->Parameters.Create.Options >> 24;
    ULONG pid = FltGetRequestorProcessId(Data);
    BOOLEAN service = SafeUploadIsAuthenticatedClient() && pid == SafeUploadData.InspectorProcessId;
    BOOLEAN writer, handled = TRUE, privateNamespace = FALSE;
    UNICODE_STRING relative;
    UNICODE_STRING privatePrefix = RTL_CONSTANT_STRING(L"\\ProgramData\\SafeUpload\\staging\\");
    ULONGLONG zeroId = 0;
    SAFEUPLOAD_VOLUME_KIND kind;
    NTSTATUS status = STATUS_SUCCESS;
    if (security == NULL || Objects->FileObject == NULL ||
        FlagOn(Data->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY) ||
        (Objects->FileObject->FileName.Length == 0 && Objects->FileObject->RelatedFileObject == NULL))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    writer = BooleanFlagOn(security->DesiredAccess, FILE_WRITE_DATA | FILE_APPEND_DATA | MAXIMUM_ALLOWED) ||
        disposition == FILE_CREATE || disposition == FILE_SUPERSEDE || disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF;
    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {
#if SAFEUPLOAD_STAGING_PROTOTYPE
        if (!service && FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE))
            return StageDirectoryDeleteOnClose(Data, Objects);
#endif
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    kind = StageVolumeKind(Objects->Instance);
#if SAFEUPLOAD_STAGING_PROTOTYPE
    /* An open by file ID carries no name, so delete-on-close cannot be judged against the protected namespace. */
    if (!service && FlagOn(Data->Iopb->Parameters.Create.Options, FILE_OPEN_BY_FILE_ID) &&
        FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE)) {
        status = STATUS_ACCESS_DENIED;
        goto Complete;
    }
#endif
    if (!service && FlagOn(Data->Iopb->Parameters.Create.Options, FILE_OPEN_BY_FILE_ID)) {
        UNICODE_STRING id = Objects->FileObject->FileName;
        StageAcquire(&StageNamespaceResource);
        if (!StageStopping) expectedView = StageFindId(FltGetRequestorProcess(Data), Objects->Instance, &id);
        if (expectedView != NULL) {
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
            status = StageCreate(Data, Objects, privateName, kind, writer, expectedView, TRUE, &handled);
            goto Complete;
        }
        /* Unknown writable IDs cannot bypass destination checks. Nonzero high
         * halves are NTFS object IDs, including our private IDs: do not let an
         * unknown private ID fall through into another object's namespace.
         * Legacy physical read-only IDs keep the existing source inspection. */
        if (writer || (id.Length == sizeof(FILE_ID_128) &&
            RtlCompareMemory((PUCHAR)id.Buffer + sizeof(ULONGLONG),
                &zeroId, sizeof(zeroId)) != sizeof(zeroId))) {
            status = STATUS_ACCESS_DENIED; goto Complete;
        }
#if SAFEUPLOAD_STAGING_PROTOTYPE
        /* An open by file ID carries no name to compare with the fence. While a fenced stream exists on this
         * volume it could be that stream, so it is refused instead of served dirty bytes. */
        if (SafeUploadStageFenceVolumeHasEntries(Objects->Volume)) {
            SafeUploadStageFenceCountOpenRefused();
            status = STATUS_SHARING_VIOLATION; goto Complete;
        }
#endif
        handled = FALSE; goto Complete;
    }
    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name);
    if (!NT_SUCCESS(status)) {
#if SAFEUPLOAD_STAGING_PROTOTYPE
        /* A service create is a publication only after the destination has a
         * normalized name and SafeUploadPublicationCreate finds its explicit
         * permit. If this volume may contain a current, pending, or boot
         * scope, an unresolved name cannot be sent through as an ordinary
         * service write, including OBJECT_NAME_NOT_FOUND and resource errors. */
        if (service && SafeUploadPolicyMayMatchVolume(kind, Objects->Volume)) {
            SafeUploadStageFenceCountOpenRefused();
            SafeUploadTrace("service create refused: destination name unresolved on a possibly protected volume\n");
            status = STATUS_ACCESS_DENIED;
            goto Complete;
        }
        /* A name query that failed for lack of resources says nothing about the target, which could be a
         * fenced stream: refuse on a volume that holds one instead of serving dirty bytes. Every other failure
         * (a file that does not exist is the common one: callers probe paths constantly) cannot read bytes and
         * must keep its real status. */
        if ((!writer || service) &&
            ((kind == SafeUploadVolumeUnknown && status != STATUS_OBJECT_NAME_NOT_FOUND &&
                status != STATUS_OBJECT_PATH_NOT_FOUND) ||
             (SafeUploadPolicyMatchesDestination(kind, NULL) && status != STATUS_OBJECT_NAME_NOT_FOUND &&
                status != STATUS_OBJECT_PATH_NOT_FOUND) ||
             (!service && (status == STATUS_INSUFFICIENT_RESOURCES || status == STATUS_NO_MEMORY) &&
                SafeUploadStageFenceVolumeHasEntries(Objects->Volume)))) {
            SafeUploadStageFenceCountOpenRefused();
            status = STATUS_SHARING_VIOLATION; goto Complete;
        }
#endif
        if (!writer || service) return FLT_PREOP_SUCCESS_NO_CALLBACK;
        status = STATUS_ACCESS_DENIED; goto Complete;
    }
    status = FltParseFileNameInformation(name);
    if (!NT_SUCCESS(status)) goto Complete;
    relative.Buffer = (PWCH)((PUCHAR)name->Name.Buffer + name->Volume.Length);
    relative.Length = name->Name.Length - name->Volume.Length;
    relative.MaximumLength = relative.Length;
    if (!service) {
        StageAcquire(&StageNamespaceResource);
        expectedView = StageFindView(FltGetRequestorProcess(Data), &name->Name);
        privateNamespace = expectedView != NULL || StageHiddenName(FltGetRequestorProcess(Data), &name->Name);
        StageRelease(&StageNamespaceResource);
    }
#if SAFEUPLOAD_STAGING_PROTOTYPE
    /* Fence names survive a policy shrink while their old writable mappings remain. Test them before
     * the current-policy fast path and before trusted publication handling; volume quarantine stays
     * below the scope test so unrelated names remain available. */
    if (!privateNamespace && SafeUploadStageFenceNameQuarantined(&name->Name)) {
        SafeUploadStageFenceCountOpenRefused();
        status = STATUS_SHARING_VIOLATION;
        goto Complete;
    }
#endif
    if (RtlPrefixUnicodeString(&privatePrefix, &relative, TRUE)) {
        if (!service) { status = STATUS_ACCESS_DENIED; goto Complete; }
        handled = FALSE; goto Complete;
    }
    if (!privateNamespace && writer && SafeUploadStageProtectedName(name, kind) &&
        (!SafeUploadInstanceTrustGateSatisfied(Objects->Instance) || !SafeUploadIsAuthenticatedClient())) {
        /* Canary results describe the primitive only; trust is assigned from
         * the immutable setup flags and can never be upgraded on this mount. */
        status = STATUS_ACCESS_DENIED;
        goto Complete;
    }
    if (!privateNamespace && !SafeUploadStageProtectedName(name, kind)) {
        BOOLEAN protectedAlias = FALSE;
        if (writer || BooleanFlagOn(security->DesiredAccess,
            FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | DELETE | WRITE_DAC | WRITE_OWNER)) {
            status = SafeUploadStageCheckNamedAliases(Objects->Instance, name, kind, &protectedAlias);
            if (status != STATUS_SUCCESS || protectedAlias) { status = STATUS_ACCESS_DENIED; goto Complete; }
        }
        handled = FALSE; goto Complete;
    }
    if (service) {
#if SAFEUPLOAD_STAGING_PROTOTYPE
        /* Publication must not write a destination whose dirty mapped pages are still quarantined: a later
         * purge would discard the approved bytes together with them. */
        if (writer && SafeUploadStageFenceVolumeQuarantined(Objects->Volume)) {
            SafeUploadStageFenceCountOpenRefused();
            status = STATUS_SHARING_VIOLATION; goto Complete;
        }
#endif
        if (!writer || SafeUploadPublicationCreate(&name->Name, disposition, writer)) handled = FALSE;
        else status = STATUS_ACCESS_DENIED;
        goto Complete;
    }
    if (FLT_IS_IRP_OPERATION(Data) && FltIsIoCanceled(Data)) { status = STATUS_CANCELLED; goto Complete; }
#if SAFEUPLOAD_STAGING_PROTOTYPE
    /* FILE_DELETE_ON_CLOSE on a protected name deletes the physical file at cleanup without any SET_INFORMATION, so
     * the disposition gate never sees it; a DELETE-only open is not a writer and would fall through to NTFS. */
    if (!privateNamespace && FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE)) {
        status = STATUS_ACCESS_DENIED;
        goto Complete;
    }
    /* A stream with a writable mapping that predates its scope cannot be served: a reader would see
     * the dirty mapped bytes. Name check only; no I/O in the create path. */
    if (!privateNamespace && SafeUploadStageFenceVolumeQuarantined(Objects->Volume)) {
        SafeUploadStageFenceCountOpenRefused();
        status = STATUS_SHARING_VIOLATION;
        goto Complete;
    }
#endif
    Data->IoStatus.Information = 0;
    status = StageCreate(Data, Objects, name, kind, writer, expectedView, privateNamespace, &handled);
Complete:
    if (name != NULL) FltReleaseFileNameInformation(name);
    if (privateName != NULL) ExFreePoolWithTag(privateName, STAGE_TAG);
    if (!handled) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    Data->IoStatus.Status = status;
    if (!NT_SUCCESS(status)) Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

static FLT_PREOP_CALLBACK_STATUS StagePhysicalMutationEx(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, BOOLEAN IncludeAncestors);

static FLT_PREOP_CALLBACK_STATUS StagePhysicalMutation(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects)
{
    return StagePhysicalMutationEx(Data, Objects, FALSE);
}

static FLT_PREOP_CALLBACK_STATUS StagePhysicalMutationEx(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, BOOLEAN IncludeAncestors)
{
    PFLT_FILE_NAME_INFORMATION name = NULL;
    SAFEUPLOAD_VOLUME_KIND kind = StageVolumeKind(Objects->Instance);
    BOOLEAN protectedAlias = FALSE;
    BOOLEAN service = SafeUploadIsAuthenticatedClient() &&
        FltGetRequestorProcessId(Data) == SafeUploadData.InspectorProcessId;
    FLT_FILESYSTEM_TYPE fs;
    NTSTATUS status = STATUS_ACCESS_DENIED;
    /* Querying lower metadata is forbidden in fast I/O, paging/section paths
     * or with a top-level IRP. Paging through mappings predating attachment is
     * a separate volume-admission gate, not solved by this snapshot. */
    if (FLT_IS_FASTIO_OPERATION(Data)) return FLT_PREOP_DISALLOW_FASTIO;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || IoGetTopLevelIrp() != NULL) goto Complete;
    status = FltGetFileSystemType(Objects->Instance, &fs);
    if (!NT_SUCCESS(status)) goto Complete;
    if (fs != FLT_FSTYPE_NTFS) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name);
    if (!NT_SUCCESS(status)) goto Complete;
    status = FltParseFileNameInformation(name);
    if (!NT_SUCCESS(status)) goto Complete;
    if (!service && (IncludeAncestors ? SafeUploadStageTouchesProtectedNamespace(name, kind) :
        SafeUploadStageProtectedName(name, kind))) { status = STATUS_ACCESS_DENIED; goto Complete; }
    status = SafeUploadStageCheckObjectAliases(Objects->Instance, Objects->FileObject,
        &name->Volume, kind, &protectedAlias);
    if (protectedAlias) status = STATUS_ACCESS_DENIED;
Complete:
    if (name != NULL) FltReleaseFileNameInformation(name);
    if (status == STATUS_SUCCESS) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

static FLT_PREOP_CALLBACK_STATUS StageExternalRename(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects)
{
    FILE_INFORMATION_CLASS cls = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    PFILE_RENAME_INFORMATION rename = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    PFLT_FILE_NAME_INFORMATION source = NULL, destination = NULL;
    SAFEUPLOAD_VOLUME_KIND kind = StageVolumeKind(Objects->Instance);
    BOOLEAN allow = FALSE;
    BOOLEAN quarantineRefused = FALSE;
    NTSTATUS status;
    ULONG length = Data->Iopb->Parameters.SetFileInformation.Length;
    if (cls != FileRenameInformation && cls != FileRenameInformationEx && cls != FileLinkInformation && cls != FileLinkInformationEx)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || IoGetTopLevelIrp() != NULL) goto Complete;
    if (rename == NULL || length < (ULONG)FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName) ||
        rename->FileNameLength == 0 || (rename->FileNameLength & 1) ||
        rename->FileNameLength > length - FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName)) goto Complete;
    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &source);
    if (!NT_SUCCESS(status)) goto Complete;
    status = FltGetDestinationFileNameInformation(Objects->Instance, Objects->FileObject,
        rename->RootDirectory, rename->FileName, rename->FileNameLength,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &destination);
    if (!NT_SUCCESS(status)) goto Complete;
    allow = !SafeUploadStageTouchesProtectedNamespace(source, kind) &&
        !SafeUploadStageTouchesProtectedNamespace(destination, kind);
    if (allow) {
        BOOLEAN protectedAlias = FALSE;
        status = SafeUploadStageCheckObjectAliases(Objects->Instance, Objects->FileObject,
            &source->Volume, kind, &protectedAlias);
        allow = status == STATUS_SUCCESS && !protectedAlias;
    }
    if (!allow && SafeUploadIsAuthenticatedClient() &&
        FltGetRequestorProcessId(Data) == SafeUploadData.InspectorProcessId &&
        (cls == FileRenameInformation || cls == FileRenameInformationEx)) {
        allow = SafeUploadPublicationRename(Objects->Volume, &source->Name, &destination->Name,
            &quarantineRefused);
#if SAFEUPLOAD_STAGING_PROTOTYPE
        if (quarantineRefused) SafeUploadStageFenceCountOpenRefused();
#endif
    }
Complete:
    if (source != NULL) FltReleaseFileNameInformation(source);
    if (destination != NULL) FltReleaseFileNameInformation(destination);
    if (allow) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    Data->IoStatus.Status = quarantineRefused ? STATUS_SHARING_VIOLATION : STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

#if SAFEUPLOAD_STAGING_PROTOTYPE
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

static FLT_PREOP_CALLBACK_STATUS StageCompleteAccessDenied(_Inout_ PFLT_CALLBACK_DATA Data)
{
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

/* The installed table is nonpaged and keyed by SectionObjectPointer, so this check needs no name query and is safe
 * for paging and elevated-IRQL callbacks. Fast-I/O reads are sent back through the IRP read path, which applies the
 * same identity check before allowing the filesystem to return bytes. */
static FLT_PREOP_CALLBACK_STATUS StageGateUnownedFencedRead(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_opt_ PFILE_OBJECT FileObject)
{
    if (!SafeUploadStageFenceIsFenced(FileObject)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (FLT_IS_FASTIO_OPERATION(Data)) return FLT_PREOP_DISALLOW_FASTIO;
    return StageCompleteAccessDenied(Data);
}

/* A mutating FSCTL through a file object that was never admitted. The service PID is not an exception here: these
 * operations can mutate caller-selected physical objects, so they receive the same scope and alias checks as others.
 * Safe name and alias resolution is supported only for fixed NTFS objects at PASSIVE_LEVEL without a top-level IRP.
 * Reparse-changing FSCTLs also cover ancestors of a protected prefix, because turning a parent into a junction
 * redirects the protected namespace. When a safe alias check is unavailable, fail closed and count the unresolved
 * request; a cache hit naming an out-of-scope path does not prove that another hard-link name is out of scope. */
static FLT_PREOP_CALLBACK_STATUS StageUnownedMutatingFsctl(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS Objects)
{
    PFLT_FILE_NAME_INFORMATION name = NULL;
    ULONG code;
    BOOLEAN ancestors;
    BOOLEAN protectedAlias = FALSE;
    FLT_FILESYSTEM_TYPE fs;
    SAFEUPLOAD_VOLUME_KIND kind;
    NTSTATUS status;

    if (Data->Iopb->MinorFunction != IRP_MN_USER_FS_REQUEST) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    code = Data->Iopb->Parameters.FileSystemControl.Common.FsControlCode;
    if (!StageMutatingFsctl(code)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (SafeUploadStageFenceIsFenced(Objects->FileObject)) {
        if (FLT_IS_FASTIO_OPERATION(Data)) return FLT_PREOP_DISALLOW_FASTIO;
        return StageCompleteAccessDenied(Data);
    }
    if (FLT_IS_FASTIO_OPERATION(Data)) return FLT_PREOP_DISALLOW_FASTIO;            /* retried as an IRP */
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
        if (SafeUploadStageFenceNameQuarantined(&name->Name) ||
            SafeUploadPolicyMatchesCurrentOrPendingDestination(kind, &name->Name, ancestors) ||
            (ancestors ? SafeUploadStageTouchesProtectedNamespace(name, kind) :
                SafeUploadStageProtectedName(name, kind))) {
            FltReleaseFileNameInformation(name);
            return StageCompleteAccessDenied(Data);
        }

        /* The alias scanner intentionally supports NTFS only. Do not let a cached/name-level out-of-scope result
         * stand in for alias coverage on network, removable, unknown, or other filesystem types. */
        status = SafeUploadStageCheckObjectAliases(Objects->Instance, Objects->FileObject,
            &name->Volume, kind, &protectedAlias);
        FltReleaseFileNameInformation(name);
        name = NULL;
        if (!NT_SUCCESS(status) || protectedAlias) goto Unresolved;
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* At APC_LEVEL, in paging I/O, or with a top-level IRP, do not query a name. A cache hit with an out-of-scope
     * name would still not prove that the object has no protected alias, so every selected mutation is denied. */
Unresolved:
    if (name != NULL) FltReleaseFileNameInformation(name);
    SafeUploadStageFenceCountFsctlUnresolved();
    return StageCompleteAccessDenied(Data);
}
#endif

#if SAFEUPLOAD_STAGING_PROTOTYPE
#ifndef SEC_IMAGE
#define SEC_IMAGE 0x01000000
#endif
/* A writable data section created through a file object that was never admitted. Such a handle predates the
 * filter or its policy scope, so its later paging writes could not be redirected; the section-pointer fence
 * can only catch them if a scan happened to see the mapping first. Refusing the section at creation closes
 * the window between a scan and the mapping. Querying a name in a PRE-operation section-synchronization
 * callback is documented as allowed; when no name can be resolved the section is denied and counted. */
static FLT_PREOP_CALLBACK_STATUS StageUnownedWritableSection(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS Objects)
{
    PFLT_FILE_NAME_INFORMATION name = NULL;
    SAFEUPLOAD_VOLUME_KIND kind;
    FLT_FILESYSTEM_TYPE fs;
    NTSTATUS status;

    if (Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType != SyncTypeCreateSection) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!FlagOn(Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection,
            PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (FlagOn(Data->Iopb->Parameters.AcquireForSectionSynchronization.AllocationAttributes, SEC_IMAGE)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    /* The section identity remains definitive across a policy shrink, aliases and service callers. */
    if (SafeUploadStageFenceIsFenced(Objects->FileObject)) goto Deny;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        SafeUploadStageFenceCountSectionUnresolved();
        goto Deny;
    }
    status = FltGetFileSystemType(Objects->Instance, &fs);
    if (!NT_SUCCESS(status)) {
        /* A classification error is not evidence that the file system is outside policy. The normalized
         * name below can still resolve its scope; if that also fails, this writable section is denied. */
        SafeUploadTrace("writable section file-system classification failed; checking protected-name policy\n");
    } else if (fs != FLT_FSTYPE_NTFS) {
        /* Positively unsupported by the mapped-stream scan, but still subject to name/policy admission. */
        SafeUploadTrace("writable section on unscanned file system; checking protected-name policy\n");
    }
    kind = StageVolumeKind(Objects->Instance);
    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name);
    if (!NT_SUCCESS(status)) {
        SafeUploadStageFenceCountSectionUnresolved();
        goto Deny;
    }
    /* The current+pending union is read under one shared policy-lock hold. Separate checks can straddle a shrink:
     * pending misses the old-only scope, then the swap publishes the new current policy before the current check. */
    if (!NT_SUCCESS(FltParseFileNameInformation(name))) {
        SafeUploadStageFenceCountSectionUnresolved();
        goto Deny;
    }
    if (SafeUploadStageFenceNameQuarantined(&name->Name) ||
        SafeUploadPolicyMatchesCurrentOrPendingDestination(kind, &name->Name, FALSE) ||
        SafeUploadStageProtectedName(name, kind)) goto Deny;
    FltReleaseFileNameInformation(name);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
 Deny:
    if (name != NULL) FltReleaseFileNameInformation(name);
    SafeUploadStageFenceCountSectionDenied();
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}
#endif

FLT_PREOP_CALLBACK_STATUS SafeUploadStageDispatch(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, PVOID *CompletionContext)
{
    FLT_PREOP_CALLBACK_STATUS result;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    PVOID sectionInFlight = NULL;
#endif
    *CompletionContext = NULL;
    /* This fence MUST precede all legacy taint/context/policy callbacks. */
    if (StageStreamForObject(Data->Iopb->TargetFileObject) != NULL)
        return StagePreOperation(Data, Objects, CompletionContext);
    switch (Data->Iopb->MajorFunction) {
    case IRP_MJ_CREATE:
        result = StageAdmit(Data, Objects);
        if (result != FLT_PREOP_SUCCESS_NO_CALLBACK) return result;
        result = SafeUploadPreCreate(Data, Objects, CompletionContext);
#if SAFEUPLOAD_STAGING_PROTOTYPE
        /* H(F) must see every write open, including those the legacy pre-create skips: any file may later
         * enter a protected scope. The sentinel tells post-create not to run the legacy handler. */
        if (result == FLT_PREOP_SUCCESS_NO_CALLBACK && SafeUploadStageWritersWantPostCreate(Data)) {
            *CompletionContext = SAFEUPLOAD_WRITERS_ONLY_CONTEXT;
            return FLT_PREOP_SUCCESS_WITH_CALLBACK;
        }
#endif
        return result;
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
        return SafeUploadStageDirectoryQuery(Data, Objects, CompletionContext);
    case IRP_MJ_CLEANUP:
#if SAFEUPLOAD_STAGING_PROTOTYPE
        StageTraceFileLifetime(Data, Objects, SAFEUPLOAD_ADMISSION_TRACE_EVENT_FILE_CLEANUP);
        SafeUploadStageWritersOnCleanup(Data, Objects);
#endif
        return SafeUploadPreCleanup(Data, Objects, CompletionContext);
#if SAFEUPLOAD_STAGING_PROTOTYPE
    case IRP_MJ_CLOSE:
        StageTraceFileLifetime(Data, Objects, SAFEUPLOAD_ADMISSION_TRACE_EVENT_FILE_CLOSE);
        break;
    case IRP_MJ_READ:
    case IRP_MJ_MDL_READ:
        return StageGateUnownedFencedRead(Data, Data->Iopb->TargetFileObject);
    case IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE:
        if (Data->Iopb->Parameters.FastIoCheckIfPossible.CheckForReadOperation &&
            SafeUploadStageFenceIsFenced(Data->Iopb->TargetFileObject)) {
            return FLT_PREOP_DISALLOW_FASTIO;
        }
        break;
    case IRP_MJ_MDL_READ_COMPLETE:
        /* Completion releases a previously returned MDL; do not block the release path. */
        break;
#endif
    case IRP_MJ_WRITE:
#if SAFEUPLOAD_STAGING_PROTOTYPE
        {
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
#if SAFEUPLOAD_STAGING_PROTOTYPE

        //
        //  A stream with a user-writable mapping that predates the filter or its
        //  scope has no admitted file object to redirect, so its paging writes
        //  are refused here, keyed by section pointer (no name lookup in paging
        //  I/O). The check is in memory only.
        //

        if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO) &&
            SafeUploadStageFenceIsFenced(Data->Iopb->TargetFileObject)) {
            SafeUploadStageFenceCountPagingDenied();
            Data->IoStatus.Status = STATUS_MEDIA_WRITE_PROTECTED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
#endif
        if (!FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) {
            result = StagePhysicalMutation(Data, Objects);
            if (result != FLT_PREOP_SUCCESS_NO_CALLBACK) return result;
            return SafeUploadPreWrite(Data, Objects, CompletionContext);
        }
        break;
    case IRP_MJ_SET_INFORMATION:
        result = StageExternalRename(Data, Objects);
        if (result != FLT_PREOP_SUCCESS_NO_CALLBACK) return result;
        if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass != FilePositionInformation) {
            /* Publication rename is checked/consumed by StageExternalRename. */
            FILE_INFORMATION_CLASS cls = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
            if (cls != FileRenameInformation && cls != FileRenameInformationEx &&
                cls != FileLinkInformation && cls != FileLinkInformationEx) {
                result = StagePhysicalMutation(Data, Objects);
                if (result != FLT_PREOP_SUCCESS_NO_CALLBACK) return result;
            }
        }
        *CompletionContext = NULL;
        return SafeUploadPreSetInformation(Data, Objects, CompletionContext);
    case IRP_MJ_SET_EA:
    case IRP_MJ_SET_SECURITY:
        return StagePhysicalMutation(Data, Objects);
    case IRP_MJ_FILE_SYSTEM_CONTROL:
#if SAFEUPLOAD_STAGING_PROTOTYPE
        result = StageUnownedMutatingFsctl(Data, Objects);
        if (result != FLT_PREOP_SUCCESS_NO_CALLBACK) return result;
#endif
        break;
    case IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION:
    case IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION:
#if SAFEUPLOAD_STAGING_PROTOTYPE
        if (Data->Iopb->MajorFunction == IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION) {
            result = StageUnownedWritableSection(Data, Objects);
            if (result != FLT_PREOP_SUCCESS_NO_CALLBACK) return result;
            StageTraceWritableCreateSection(Data, Objects);
            sectionInFlight = SafeUploadStageSectionAcquired(Data);
        } else {
            SafeUploadStageSectionReleased(Data);
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
        if (sectionInFlight) {
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

FLT_POSTOP_CALLBACK_STATUS SafeUploadStagePostOperation(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (Data->Iopb->MajorFunction == IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION && CompletionContext != NULL) {
        if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
            /* Outcome unavailable while draining: keep the entry and make writer state Unknown. */
            SafeUploadStageSectionAcquireDraining();
        } else if (!NT_SUCCESS(Data->IoStatus.Status)) {
            /* The acquire failed below us: no release follows, so drop the in-flight entry here. */
            SafeUploadStageSectionAcquireFailed(CompletionContext);
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
#endif
    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
#if SAFEUPLOAD_STAGING_PROTOTYPE
        SafeUploadStageWritersPostCreate(Data, Objects, Flags);
        if (CompletionContext == SAFEUPLOAD_WRITERS_ONLY_CONTEXT) return FLT_POSTOP_FINISHED_PROCESSING;
#endif
        return SafeUploadPostCreate(Data, Objects, CompletionContext, Flags);
    }
    if (CompletionContext != NULL) {
        PSTAGE_STREAM stream = CompletionContext;
        ExReleaseRundownProtection(&stream->PagingRundown);
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
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
    for (link = StageViews.Flink; link != &StageViews; link = link->Flink)
        if (CONTAINING_RECORD(link, STAGE_VIEW, Link)->Owner == process) { found = TRUE; break; }
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
    NTSTATUS status = PsLookupProcessByProcessId(ULongToHandle(Owner), &process);
    if (!NT_SUCCESS(status)) return status;
    StageAcquire(&StageNamespaceResource);
    for (link = StageViews.Flink; link != &StageViews; link = link->Flink) {
        PSTAGE_VIEW view = CONTAINING_RECORD(link, STAGE_VIEW, Link);
        if (view->Owner != process) continue;
        for (old = view->OldNames.Flink; old != &view->OldNames; old = old->Flink) {
            PSTAGE_OLD_NAME hidden = CONTAINING_RECORD(old, STAGE_OLD_NAME, Link);
            if (StageFindView(process, &hidden->Name) == NULL &&
                StageDirectoryChild(Directory, &hidden->Name, &child)) {
                status = StageAddOverlay(Overlays, &child, NULL);
                if (!NT_SUCCESS(status)) goto Exit;
            }
        }
        if (!view->Detached && StageDirectoryChild(Directory, &view->Name, &child)) {
            status = StageAddOverlay(Overlays, &child, view->Current);
            if (!NT_SUCCESS(status)) goto Exit;
        }
    }
Exit:
    StageRelease(&StageNamespaceResource);
    ObDereferenceObject(process);
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
        if (view->Owner != process) continue;
        found = !view->Detached && StageDirectoryChild(Directory, &view->Name, &child);
        for (old = view->OldNames.Flink; old != &view->OldNames && !found; old = old->Flink)
            found = StageDirectoryChild(Directory, &CONTAINING_RECORD(old, STAGE_OLD_NAME, Link)->Name, &child);
    }
    StageRelease(&StageNamespaceResource);
    ObDereferenceObject(process);
    return found;
}
