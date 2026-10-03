/*++

Module Name:

    StageWriters.c

Abstract:

    H(F) of the writer-state design: for every stream, the number of file objects that were
    opened with write access and have not yet seen IRP_MJ_CLEANUP. Feature build only,
    observe-only in this slice: nothing here changes a status or blocks an operation.

    Design rules (see evidence/2026-10-03/writer-state-design-v2.txt):

    - Count at post-create of a successful physical open whose file object has WriteAccess.
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
        (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE | GENERIC_ALL | MAXIMUM_ALLOWED)) != 0;
}

VOID SafeUploadStageWritersPostCreate(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    PFILE_OBJECT fileObject = FltObjects->FileObject;
    PSAFEUPLOAD_STREAM_CONTEXT streamContext = NULL;
    PSTAGE_WRITER_NODE node;
    NTSTATUS status;

    PAGED_CODE();

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) return;
    if (!NT_SUCCESS(Data->IoStatus.Status) || Data->IoStatus.Status == STATUS_REPARSE) return;
    if (fileObject == NULL || !fileObject->WriteAccess) return;
    InterlockedIncrement64(&WriterPostCreateRuns);

    /* Create.Options keeps the disposition in its high byte; the option bits are the low 24. */
    if ((Data->Iopb->Parameters.Create.Options & FILE_DIRECTORY_FILE) != 0) {
        InterlockedIncrement64(&WriterDirectoryCreatesSkipped);
        return;
    }

    status = SafeUploadGetOrCreateStreamContext(FltObjects, fileObject, &streamContext);
    if (!NT_SUCCESS(status)) {
        InterlockedIncrement64(&WriterUntrackedCreates);
        return;
    }

    node = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*node), SAFEUPLOAD_POOL_TAG);
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

    if (fileObject == NULL || !fileObject->WriteAccess) return;

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
        ExFreePoolWithTag(found, SAFEUPLOAD_POOL_TAG);
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
        ExFreePoolWithTag(CONTAINING_RECORD(link, STAGE_WRITER_NODE, Link), SAFEUPLOAD_POOL_TAG);
    }
}

/* The probe's lower file object belongs to the same stream as every other open of it, so its stream
 * context carries the count. No context means no write open has been seen since the stream appeared. */
UINT32 SafeUploadStageWritersSnapshot(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT FileObject)
{
    PSAFEUPLOAD_STREAM_CONTEXT streamContext = NULL;
    UINT32 result = 0;

    if (FileObject == NULL || !NT_SUCCESS(FltGetStreamContext(Instance, FileObject, (PFLT_CONTEXT *)&streamContext))) {
        return 0;
    }
    result = (UINT32)InterlockedCompareExchange(&streamContext->WriteObjects, 0, 0) & ~SAFEUPLOAD_WRITERS_UNTRACKED_BIT;
    if (InterlockedCompareExchange(&streamContext->WritersUntracked, 0, 0) != 0) {
        result |= SAFEUPLOAD_WRITERS_UNTRACKED_BIT;
    }
    FltReleaseContext(streamContext);
    return result;
}

/* ---- C(F): writable CreateSections in flight ----------------------------------------------------
 * The section-synchronization acquire/release callbacks arrive paired on one thread and one file object (seen in
 * every trace). A writable CreateSection that passes the existing policy check is entered here and removed by the
 * matching release, or by the post-operation callback when the acquire itself fails (no release follows then).
 * Interlocked operations only, so it is safe in the callbacks' context.
 *
 * The slot's FileObject pointer IS its state: NULL = free, FILLING/RELEASING = a marker while one thread owns the
 * slot, anything else = an active entry for that file object. Claims are compare-exchanges on that pointer, so
 * identity and ownership are checked atomically and an entry is never invisible while it is still in flight.
 * A full table is counted and must be read as "unknown"; an entry older than the stuck threshold is counted,
 * never silently expired. */

#define STAGE_SECTION_SLOTS 64
#define STAGE_SECTION_STUCK_100NS (20LL * 1000 * 1000)     /* 2 s */
#define STAGE_SECTION_FILLING ((PVOID)(ULONG_PTR)1)
#define STAGE_SECTION_RELEASING ((PVOID)(ULONG_PTR)2)
#define STAGE_SECTION_IS_ENTRY(P) ((P) != NULL && (P) != STAGE_SECTION_FILLING && (P) != STAGE_SECTION_RELEASING)

typedef struct _STAGE_SECTION_SLOT {
    volatile PVOID FileObject;
    PVOID Thread;
    PVOID SectionObjectPointer;
    LONGLONG Time;
} STAGE_SECTION_SLOT;

static STAGE_SECTION_SLOT SectionSlots[STAGE_SECTION_SLOTS];
static volatile LONG SectionNow;
static volatile LONG SectionMaxDepth;
static volatile LONG64 SectionInserted;
static volatile LONG64 SectionReleased;
static volatile LONG64 SectionOverflow;
static volatile LONG64 SectionRemovedOnFailure;

static BOOLEAN StageSectionWritable(_In_ PFLT_CALLBACK_DATA Data)
{
    UINT32 protection;

    if (Data->Iopb->TargetFileObject == NULL) return FALSE;
    if (Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType != SyncTypeCreateSection) return FALSE;
    protection = Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection;
    return (protection & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

BOOLEAN SafeUploadStageSectionAcquired(_In_ PFLT_CALLBACK_DATA Data)
{
    PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
    ULONG index;
    LONG depth, observed;

    if (!StageSectionWritable(Data)) return FALSE;
    for (index = 0; index < STAGE_SECTION_SLOTS; index += 1) {
        STAGE_SECTION_SLOT *slot = &SectionSlots[index];
        if (InterlockedCompareExchangePointer(&slot->FileObject, STAGE_SECTION_FILLING, NULL) != NULL) continue;
        slot->Thread = PsGetCurrentThread();
        slot->SectionObjectPointer = fileObject->SectionObjectPointer;
        slot->Time = (LONGLONG)KeQueryInterruptTime();
        KeMemoryBarrier();
        InterlockedExchangePointer(&slot->FileObject, fileObject);      /* publish last */
        InterlockedIncrement64(&SectionInserted);
        depth = InterlockedIncrement(&SectionNow);
        for (;;) {
            observed = InterlockedCompareExchange(&SectionMaxDepth, 0, 0);
            if (depth <= observed || InterlockedCompareExchange(&SectionMaxDepth, depth, observed) == observed) break;
        }
        return TRUE;
    }
    InterlockedIncrement64(&SectionOverflow);
    return FALSE;
}

/* Removes the newest entry of this thread and file object; falls back to any thread when none matches. */
static BOOLEAN StageSectionRemove(_In_ PFILE_OBJECT FileObject)
{
    PVOID thread = PsGetCurrentThread();
    LONG pass, attempt;
    ULONG index;

    if (InterlockedCompareExchange(&SectionNow, 0, 0) == 0) return FALSE;     /* common case: nothing in flight */
    for (pass = 0; pass < 2; pass += 1) {
        for (attempt = 0; attempt < 4; attempt += 1) {
            LONG best = -1;
            LONGLONG bestTime = -1;

            for (index = 0; index < STAGE_SECTION_SLOTS; index += 1) {
                STAGE_SECTION_SLOT *slot = &SectionSlots[index];
                if (slot->FileObject != (PVOID)FileObject) continue;
                if (pass == 0 && slot->Thread != thread) continue;
                if (slot->Time > bestTime) { bestTime = slot->Time; best = (LONG)index; }
            }
            if (best < 0) break;
            /* Succeeds only if the slot still holds this file object: nothing else can have taken it over. */
            if (InterlockedCompareExchangePointer(&SectionSlots[best].FileObject, STAGE_SECTION_RELEASING, FileObject) !=
                (PVOID)FileObject) continue;
            SectionSlots[best].Thread = NULL;
            SectionSlots[best].SectionObjectPointer = NULL;
            KeMemoryBarrier();
            InterlockedExchangePointer(&SectionSlots[best].FileObject, NULL);
            InterlockedDecrement(&SectionNow);
            return TRUE;
        }
    }
    return FALSE;
}

VOID SafeUploadStageSectionReleased(_In_ PFLT_CALLBACK_DATA Data)
{
    if (Data->Iopb->TargetFileObject != NULL && StageSectionRemove(Data->Iopb->TargetFileObject)) {
        InterlockedIncrement64(&SectionReleased);
    }
}

VOID SafeUploadStageSectionAcquireFailed(_In_ PFLT_CALLBACK_DATA Data)
{
    if (Data->Iopb->TargetFileObject != NULL && StageSectionRemove(Data->Iopb->TargetFileObject)) {
        InterlockedIncrement64(&SectionRemovedOnFailure);
    }
}

/* Counts active entries of one stream. An entry being filled or released is not yet or no longer in flight; the
 * pointer is re-read after the data so a slot refilled in between is not counted by mistake. */
UINT32 SafeUploadStageSectionsInFlight(_In_opt_ PVOID SectionObjectPointer)
{
    UINT32 count = 0;
    ULONG index;

    if (SectionObjectPointer == NULL) return 0;
    for (index = 0; index < STAGE_SECTION_SLOTS; index += 1) {
        STAGE_SECTION_SLOT *slot = &SectionSlots[index];
        PVOID before = slot->FileObject;
        PVOID sop;

        if (!STAGE_SECTION_IS_ENTRY(before)) continue;
        sop = slot->SectionObjectPointer;
        KeMemoryBarrier();
        if (slot->FileObject == before && sop == SectionObjectPointer) count += 1;
    }
    return count;
}

VOID SafeUploadStageWritersGetStatus(_Out_ PSAFEUPLOAD_WRITER_STATE_STATUS Status)
{
    RtlZeroMemory(Status, sizeof(*Status));
    Status->StructSize = sizeof(*Status);
    Status->PostCreateRuns = (UINT64)InterlockedCompareExchange64(&WriterPostCreateRuns, 0, 0);
    Status->WriteObjectsCounted = (UINT64)InterlockedCompareExchange64(&WriterCounted, 0, 0);
    Status->WriteObjectsReleased = (UINT64)InterlockedCompareExchange64(&WriterReleased, 0, 0);
    Status->UntrackedCreates = (UINT64)InterlockedCompareExchange64(&WriterUntrackedCreates, 0, 0);
    Status->CleanupUnmatched = (UINT64)InterlockedCompareExchange64(&WriterCleanupUnmatched, 0, 0);
    Status->DirectoryCreatesSkipped = (UINT64)InterlockedCompareExchange64(&WriterDirectoryCreatesSkipped, 0, 0);
    Status->SectionInFlightNow = (UINT32)InterlockedCompareExchange(&SectionNow, 0, 0);
    Status->SectionInFlightMaxDepth = (UINT32)InterlockedCompareExchange(&SectionMaxDepth, 0, 0);
    Status->SectionInFlightInserted = (UINT64)InterlockedCompareExchange64(&SectionInserted, 0, 0);
    Status->SectionInFlightReleased = (UINT64)InterlockedCompareExchange64(&SectionReleased, 0, 0);
    Status->SectionInFlightOverflow = (UINT64)InterlockedCompareExchange64(&SectionOverflow, 0, 0);
    Status->SectionInFlightRemovedOnFailure = (UINT64)InterlockedCompareExchange64(&SectionRemovedOnFailure, 0, 0);
    {
        LONGLONG now = (LONGLONG)KeQueryInterruptTime();
        ULONG index;
        UINT64 stuck = 0;

        for (index = 0; index < STAGE_SECTION_SLOTS; index += 1) {
            STAGE_SECTION_SLOT *slot = &SectionSlots[index];
            PVOID entry = slot->FileObject;
            if (STAGE_SECTION_IS_ENTRY(entry) && now - slot->Time > STAGE_SECTION_STUCK_100NS) stuck += 1;
        }
        Status->SectionInFlightStuck = stuck;
    }
}

#endif
