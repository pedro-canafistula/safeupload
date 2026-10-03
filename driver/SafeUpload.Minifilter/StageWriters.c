/*++

Module Name:

    StageWriters.c

Abstract:

    H(F) of the writer-state design: for every stream, the number of file objects that were
    opened with write access and have not yet seen IRP_MJ_CLEANUP. Feature build only,
    observe-only in this slice: nothing here changes a status or blocks an operation.

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
#endif

/* Separate node tag permits actual Verifier allocation failures to be attributed
 * without failing stream-context or communication scratch allocations. Poolmon: SUwH. */
#define SAFEUPLOAD_WRITER_NODE_POOL_TAG 'HwUS'

typedef struct _STAGE_WRITER_NODE {
    LIST_ENTRY Link;
    PFILE_OBJECT FileObject;        /* identity token only */
} STAGE_WRITER_NODE, *PSTAGE_WRITER_NODE;

static volatile LONG64 WriterPostCreateRuns;
static volatile LONG64 WriterCounted;
static volatile LONG64 WriterReleased;
static volatile LONG64 WriterUntrackedCreates;
static volatile LONG64 WriterCleanupUnmatched;
static volatile LONG64 WriterDirectoryCreatesSkipped;
static volatile LONG64 WriterPagingCreatesSkipped;
static volatile LONG64 WriterVolumeCreatesSkipped;
static volatile LONG WriterGlobalUnknown;

UINT32 SafeUploadStageWritersGlobalUnknown(VOID)
{
    return (UINT32)InterlockedCompareExchange(&WriterGlobalUnknown, 0, 0);
}

static BOOLEAN StageWritersExcludedObject(_In_ PFILE_OBJECT FileObject)
{
    /* Paging files do not support stream contexts, and volume handles are outside the
     * regular-file writer registry. This does not grant either object admission to a scope. */
    return FlagOn(FileObject->Flags, FO_VOLUME_OPEN) || FsRtlIsPagingFile(FileObject);
}

static VOID StageWritersMarkInstanceUnknown(_In_ PFLT_INSTANCE Instance)
{
    PSAFEUPLOAD_INSTANCE_CONTEXT context = NULL;
    if (Instance != NULL && NT_SUCCESS(FltGetInstanceContext(Instance, (PFLT_CONTEXT *)&context))) {
        InterlockedExchange(&context->WritersUntracked, 1);
        FltReleaseContext(context);
    } else {
        /* No place to retain the failure: every later snapshot must remain conservative. */
        InterlockedExchange(&WriterGlobalUnknown, 1);
    }
}

/* Nonpaged and not inlined: the pageable post-create must not contain a spin-lock acquisition (PREfast C28150,
 * and a paged routine running at raised IRQL faults under Driver Verifier's paged-code trimming). */
__declspec(noinline) static VOID StageWritersInsertNode(
    _In_ PSAFEUPLOAD_STREAM_CONTEXT StreamContext,
    _In_ PSTAGE_WRITER_NODE Node)
{
    KIRQL irql;

    KeAcquireSpinLock(&StreamContext->WriterLock, &irql);
    InsertTailList(&StreamContext->WriterObjects, &Node->Link);
    InterlockedIncrement(&StreamContext->WriteObjects);
    KeReleaseSpinLock(&StreamContext->WriterLock, irql);
}

BOOLEAN SafeUploadStageWritersWantPostCreate(_In_ PFLT_CALLBACK_DATA Data)
{
    PIO_SECURITY_CONTEXT securityContext = Data->Iopb->Parameters.Create.SecurityContext;

    if (securityContext == NULL) return FALSE;
    return (securityContext->DesiredAccess &
        (FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE | GENERIC_WRITE | GENERIC_ALL | MAXIMUM_ALLOWED)) != 0;
}

VOID SafeUploadStageWritersPostCreate(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    PFILE_OBJECT fileObject = FltObjects->FileObject;
    PSAFEUPLOAD_STREAM_CONTEXT streamContext = NULL;
    PSTAGE_WRITER_NODE node;
    BOOLEAN directory = FALSE;
    NTSTATUS status;

    PAGED_CODE();

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        /* Draining permits only completion-context cleanup; the create result is unavailable. */
        InterlockedExchange(&WriterGlobalUnknown, 1);
        return;
    }
    if (!NT_SUCCESS(Data->IoStatus.Status) || Data->IoStatus.Status == STATUS_REPARSE) return;
    if (fileObject == NULL || (!fileObject->WriteAccess && !fileObject->DeleteAccess)) return;
    if (StageWritersExcludedObject(fileObject)) {
        if (FlagOn(fileObject->Flags, FO_VOLUME_OPEN)) InterlockedIncrement64(&WriterVolumeCreatesSkipped);
        else InterlockedIncrement64(&WriterPagingCreatesSkipped);
        return;
    }
    InterlockedIncrement64(&WriterPostCreateRuns);

    /* Create.Options keeps the disposition in its high byte; the option bits are the low 24. */
    if ((Data->Iopb->Parameters.Create.Options & FILE_DIRECTORY_FILE) != 0) {
        InterlockedIncrement64(&WriterDirectoryCreatesSkipped);
        return;
    }
    /* Opening a directory does not require FILE_DIRECTORY_FILE. Avoid treating its unsupported
     * stream context as a lost file writer, including DELETE-only directory handles. */
    status = FltIsDirectory(fileObject, FltObjects->Instance, &directory);
    if (!NT_SUCCESS(status)) {
        StageWritersMarkInstanceUnknown(FltObjects->Instance);
        InterlockedIncrement64(&WriterUntrackedCreates);
        return;
    }
    if (directory) {
        InterlockedIncrement64(&WriterDirectoryCreatesSkipped);
        return;
    }

    status = SafeUploadGetOrCreateStreamContext(FltObjects, fileObject, &streamContext);
    if (!NT_SUCCESS(status)) {
        StageWritersMarkInstanceUnknown(FltObjects->Instance);
        InterlockedIncrement64(&WriterUntrackedCreates);
        return;
    }

    node = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*node), SAFEUPLOAD_WRITER_NODE_POOL_TAG);
    if (node == NULL) {
        InterlockedExchange(&streamContext->WritersUntracked, 1);
        InterlockedIncrement64(&WriterUntrackedCreates);
        FltReleaseContext(streamContext);
        return;
    }
    node->FileObject = fileObject;

    StageWritersInsertNode(streamContext, node);
    InterlockedIncrement64(&WriterCounted);
    FltReleaseContext(streamContext);
}

VOID SafeUploadStageWritersOnCleanup(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects)
{
    PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
    PSAFEUPLOAD_STREAM_CONTEXT streamContext = NULL;
    PSTAGE_WRITER_NODE found = NULL;
    PLIST_ENTRY link;
    KIRQL irql;
    NTSTATUS status;

    if (fileObject == NULL || (!fileObject->WriteAccess && !fileObject->DeleteAccess)) return;
    if (StageWritersExcludedObject(fileObject)) return;

    status = FltGetStreamContext(FltObjects->Instance, fileObject, (PFLT_CONTEXT *)&streamContext);
    if (!NT_SUCCESS(status)) {
        InterlockedIncrement64(&WriterCleanupUnmatched);
        return;
    }

    KeAcquireSpinLock(&streamContext->WriterLock, &irql);
    for (link = streamContext->WriterObjects.Flink; link != &streamContext->WriterObjects; link = link->Flink) {
        PSTAGE_WRITER_NODE node = CONTAINING_RECORD(link, STAGE_WRITER_NODE, Link);
        if (node->FileObject == fileObject) {
            RemoveEntryList(&node->Link);
            InterlockedDecrement(&streamContext->WriteObjects);
            found = node;
            break;
        }
    }
    KeReleaseSpinLock(&streamContext->WriterLock, irql);

    if (found != NULL) {
        ExFreePoolWithTag(found, SAFEUPLOAD_WRITER_NODE_POOL_TAG);
        InterlockedIncrement64(&WriterReleased);
    } else {
        InterlockedIncrement64(&WriterCleanupUnmatched);
    }
    FltReleaseContext(streamContext);
}

VOID SafeUploadStageWritersFreeContext(_Inout_ PSAFEUPLOAD_STREAM_CONTEXT StreamContext)
{
    /* The context is going away, so nothing else can reach its list; free any node left behind. */
    while (!IsListEmpty(&StreamContext->WriterObjects)) {
        PLIST_ENTRY link = RemoveHeadList(&StreamContext->WriterObjects);
        ExFreePoolWithTag(CONTAINING_RECORD(link, STAGE_WRITER_NODE, Link), SAFEUPLOAD_WRITER_NODE_POOL_TAG);
    }
}

/* A missing stream context proves zero only when no writer-context failure was recorded for this
 * attachment. Allocation failure must survive a later successful allocation on the same stream. */
UINT32 SafeUploadStageWritersSnapshot(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT FileObject)
{
    PSAFEUPLOAD_STREAM_CONTEXT streamContext = NULL;
    PSAFEUPLOAD_INSTANCE_CONTEXT instanceContext = NULL;
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
    result |= (UINT32)InterlockedCompareExchange(&streamContext->WriteObjects, 0, 0) & ~SAFEUPLOAD_WRITERS_UNTRACKED_BIT;
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
    LONGLONG Time;
    ULONGLONG Sequence;
    BOOLEAN Writable;
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

VOID SafeUploadStageWritersInitialize(VOID)
{
    KeInitializeSpinLock(&SectionLock);
}

static BOOLEAN StageSectionWritable(_In_ PFLT_CALLBACK_DATA Data)
{
    UINT32 protection;

    if (Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType != SyncTypeCreateSection) return FALSE;
    protection = Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection;
    return (protection & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

PVOID SafeUploadStageSectionAcquired(_In_ PFLT_CALLBACK_DATA Data)
{
    PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
    PVOID sop, thread;
    BOOLEAN writable;
    STAGE_SECTION_SLOT *record = NULL;
    ULONG index;
    KIRQL irql;
    LONGLONG now;

    if (fileObject == NULL) return NULL;
    sop = fileObject->SectionObjectPointer;
    thread = PsGetCurrentThread();
    writable = StageSectionWritable(Data);
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
        if (writable) {
            SectionInserted += 1;
            SectionNow += 1;
            if (SectionNow > SectionMaxDepth) SectionMaxDepth = SectionNow;
        }
        record = slot;
        break;
    }
    if (record == NULL) SectionOverflow += 1;
    KeReleaseSpinLock(&SectionLock, irql);
    return record;
}

/* Caller holds SectionLock. Failed callbacks own this exact slot until they remove it; a successful
 * acquisition retains it until the matching release. Read-only slots affect pairing, never C(F). */
static VOID StageSectionRemoveSlot(_Inout_ STAGE_SECTION_SLOT *Slot, _In_ BOOLEAN Failed)
{
    if (Slot->Writable) {
        SectionNow -= 1;
        if (Failed) SectionRemovedOnFailure += 1;
        else SectionReleased += 1;
    }
    RtlZeroMemory(Slot, sizeof(*Slot));
}

VOID SafeUploadStageSectionReleased(_In_ PFLT_CALLBACK_DATA Data)
{
    PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
    PVOID thread = PsGetCurrentThread();
    STAGE_SECTION_SLOT *record = NULL;
    ULONG index;
    KIRQL irql;

    if (fileObject == NULL) return;
    KeAcquireSpinLock(&SectionLock, &irql);
    /* After an unrecorded acquisition, a release could belong to it rather than to an older slot.
     * Keep the recorded entries conservatively; overflow already makes all snapshots unknown. */
    if (SectionOverflow == 0) {
        for (index = 0; index < STAGE_SECTION_SLOTS; index += 1) {
            STAGE_SECTION_SLOT *slot = &SectionSlots[index];
            if (slot->FileObject == fileObject && slot->Thread == thread &&
                (record == NULL || slot->Sequence > record->Sequence)) record = slot;
        }
        if (record != NULL) StageSectionRemoveSlot(record, FALSE);
    }
    KeReleaseSpinLock(&SectionLock, irql);
}

VOID SafeUploadStageSectionAcquireFailed(_In_ PVOID CompletionContext)
{
    STAGE_SECTION_SLOT *slot = (STAGE_SECTION_SLOT *)CompletionContext;
    KIRQL irql;

    KeAcquireSpinLock(&SectionLock, &irql);
    StageSectionRemoveSlot(slot, TRUE);
    KeReleaseSpinLock(&SectionLock, irql);
}

UINT32 SafeUploadStageSectionsInFlight(_In_opt_ PVOID SectionObjectPointer)
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
    if (SectionOverflow != 0) count |= SAFEUPLOAD_SECTIONS_UNTRACKED_BIT;
    KeReleaseSpinLock(&SectionLock, irql);
    return count;
}

VOID SafeUploadStageWritersGetStatus(_Out_ PSAFEUPLOAD_WRITER_STATE_STATUS Status)
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

#endif
