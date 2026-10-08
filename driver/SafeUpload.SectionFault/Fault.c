/* Qualification only: the harness must prove manual attachment below SafeUpload on the disposable VM. A SYSTEM client
 * arms one referenced FILE_OBJECT. Only writable CreateSection on that exact object can fail or
 * pause. No paths, raw pointers, production policy, or destination bytes are accepted or modified. */
#include <fltKernel.h>
#include "Protocol.h"

static PFLT_FILTER FaultFilter;
static PFLT_PORT FaultServer, FaultClient;
static KMUTEX FaultControl;
static KSPIN_LOCK FaultLock;
static EX_RUNDOWN_REF FaultCallbacks;
static KEVENT FaultRelease;
static PFILE_OBJECT FaultFile;
static PFLT_VOLUME FaultVolume;
static ULONG FaultMode;
static BOOLEAN FaultStopping;
static volatile LONG FaultCurrentHeld;
static volatile LONG64 FaultArmGeneration;
static volatile LONG64 FaultMatched, FaultFailed, FaultHeld, FaultTimedOut, FaultInvalidIrql;
/* W01 is a separate, single-instance IRP queue. It never shares or changes the
 * legacy section-fault arm/state. Only one exact file object can be armed. */
static PFLT_INSTANCE FaultWriteInstance;
static FLT_CALLBACK_DATA_QUEUE FaultWriteQueue;
static LIST_ENTRY FaultWriteQueueList;
static KSPIN_LOCK FaultWriteQueueLock;
static BOOLEAN FaultWriteQueueInitialized;
static PFILE_OBJECT FaultWriteFile;
static PFLT_VOLUME FaultWriteVolume;
static ULONG FaultWriteMode;
static KEVENT FaultWriteRelease;
static KEVENT FaultWriteQueued;
static HANDLE FaultWriteWorkerHandle;
static volatile LONG FaultWriteCurrentHeld;
static volatile LONG FaultWriteOutstanding;
static volatile LONG FaultWriteSyntheticFailure;
static volatile LONG64 FaultWriteArmGeneration;
static volatile LONG64 FaultWriteMatched, FaultWriteHeld, FaultWriteReleased;
static volatile LONG64 FaultWriteLowerPosts, FaultWriteCanceled, FaultWriteTimedOut;
static volatile LONG64 FaultWriteSyntheticFailures;
static volatile LONG FaultWritePostFlags;
static volatile LONG FaultWriteLowerStatus;
static volatile LONG64 FaultWriteLowerInformation, FaultWriteLowerCallbackData;
static volatile LONG64 FaultWriteOffset;
static volatile LONG FaultWriteLength, FaultWriteIrpFlags;
static EX_RUNDOWN_REF FaultWriteCallbacks;
static BOOLEAN FaultWriteRundownClosed;

static NTSTATUS FaultCbdqInsertIo(_Inout_ PFLT_CALLBACK_DATA_QUEUE Cbdq,
    _In_ PFLT_CALLBACK_DATA Data, _In_opt_ PVOID InsertContext);
static VOID FaultCbdqRemoveIo(_Inout_ PFLT_CALLBACK_DATA_QUEUE Cbdq, _In_ PFLT_CALLBACK_DATA Data);
static PFLT_CALLBACK_DATA FaultCbdqPeekNextIo(_In_ PFLT_CALLBACK_DATA_QUEUE Cbdq,
    _In_opt_ PFLT_CALLBACK_DATA Data, _In_opt_ PVOID PeekContext);
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_raises_(DISPATCH_LEVEL)
static VOID FaultCbdqAcquire(_Inout_ PFLT_CALLBACK_DATA_QUEUE Cbdq,
    _Out_ _At_(*Irql, _IRQL_saves_) PKIRQL Irql);
_IRQL_requires_(DISPATCH_LEVEL)
static VOID FaultCbdqRelease(_Inout_ PFLT_CALLBACK_DATA_QUEUE Cbdq, _In_ _IRQL_restores_ KIRQL Irql);
static KSTART_ROUTINE FaultWriteWorker;
static VOID FaultCbdqCompleteCanceledIo(_Inout_ PFLT_CALLBACK_DATA_QUEUE Cbdq,
    _In_ PFLT_CALLBACK_DATA Data);
static VOID FaultWriteDisarmLocked(VOID);
static FLT_PREOP_CALLBACK_STATUS FaultPreWrite(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);
static FLT_POSTOP_CALLBACK_STATUS FaultPostWrite(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

static NTSTATUS FaultCbdqInsertIo(_Inout_ PFLT_CALLBACK_DATA_QUEUE Cbdq,
    _In_ PFLT_CALLBACK_DATA Data, _In_opt_ PVOID InsertContext)
{
    UNREFERENCED_PARAMETER(Cbdq); UNREFERENCED_PARAMETER(InsertContext);
    InsertTailList(&FaultWriteQueueList, &Data->QueueLinks);
    return STATUS_SUCCESS;
}

static VOID FaultCbdqRemoveIo(_Inout_ PFLT_CALLBACK_DATA_QUEUE Cbdq, _In_ PFLT_CALLBACK_DATA Data)
{
    UNREFERENCED_PARAMETER(Cbdq);
    RemoveEntryList(&Data->QueueLinks);
    InitializeListHead(&Data->QueueLinks);
}

static PFLT_CALLBACK_DATA FaultCbdqPeekNextIo(_In_ PFLT_CALLBACK_DATA_QUEUE Cbdq,
    _In_opt_ PFLT_CALLBACK_DATA Data, _In_opt_ PVOID PeekContext)
{
    PLIST_ENTRY entry;
    UNREFERENCED_PARAMETER(Cbdq); UNREFERENCED_PARAMETER(PeekContext);
    entry = Data == NULL ? FaultWriteQueueList.Flink : Data->QueueLinks.Flink;
    if (entry == &FaultWriteQueueList) return NULL;
    return CONTAINING_RECORD(entry, FLT_CALLBACK_DATA, QueueLinks);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_raises_(DISPATCH_LEVEL)
static VOID FaultCbdqAcquire(_Inout_ PFLT_CALLBACK_DATA_QUEUE Cbdq,
    _Out_ _At_(*Irql, _IRQL_saves_) PKIRQL Irql)
{
    UNREFERENCED_PARAMETER(Cbdq);
    KeAcquireSpinLock(&FaultWriteQueueLock, Irql);
}

_IRQL_requires_(DISPATCH_LEVEL)
static VOID FaultCbdqRelease(_Inout_ PFLT_CALLBACK_DATA_QUEUE Cbdq, _In_ _IRQL_restores_ KIRQL Irql)
{
    UNREFERENCED_PARAMETER(Cbdq);
    KeReleaseSpinLock(&FaultWriteQueueLock, Irql);
}

/* Filter Manager removes the canceled item before invoking this callback. */
static VOID FaultCbdqCompleteCanceledIo(_Inout_ PFLT_CALLBACK_DATA_QUEUE Cbdq,
    _In_ PFLT_CALLBACK_DATA Data)
{
    UNREFERENCED_PARAMETER(Cbdq);
    Data->IoStatus.Status = STATUS_CANCELLED;
    Data->IoStatus.Information = 0;
    InterlockedExchange(&FaultWriteLowerStatus, STATUS_CANCELLED);
    InterlockedExchange64(&FaultWriteLowerInformation, 0);
    InterlockedIncrement64(&FaultWriteCanceled);
    InterlockedExchange(&FaultWriteCurrentHeld, 0);
    KeSetEvent(&FaultWriteRelease, IO_NO_INCREMENT, FALSE);
    /* Complete through SafeUpload so its real post path retires the W ticket. */
    FltCompletePendedPreOperation(Data, FLT_PREOP_COMPLETE, NULL);
    InterlockedDecrement(&FaultWriteOutstanding);
    ExReleaseRundownProtection(&FaultWriteCallbacks);
}

static VOID FaultWriteWorker(_In_ PVOID Context)
{
    LARGE_INTEGER timeout;
    PFLT_CALLBACK_DATA data;
    NTSTATUS waitStatus;
    ULONG_PTR generation;
    UNREFERENCED_PARAMETER(Context);
    timeout.QuadPart = -30LL * 1000 * 1000 * 10;
    waitStatus = KeWaitForSingleObject(&FaultWriteQueued, Executive, KernelMode, FALSE, &timeout);
    if (waitStatus == STATUS_TIMEOUT) {
        KIRQL irql;
        InterlockedIncrement64(&FaultWriteTimedOut);
        KeAcquireSpinLock(&FaultLock, &irql);
        if (InterlockedCompareExchange(&FaultWriteCurrentHeld, 0, 0) == 0) {
            FaultWriteMode = 0;
            KeSetEvent(&FaultWriteRelease, IO_NO_INCREMENT, FALSE);
        }
        KeReleaseSpinLock(&FaultLock, irql);
    }
    timeout.QuadPart = -30LL * 1000 * 1000 * 10;
    waitStatus = KeWaitForSingleObject(&FaultWriteRelease, Executive, KernelMode, FALSE, &timeout);
    if (waitStatus == STATUS_TIMEOUT) InterlockedIncrement64(&FaultWriteTimedOut);
    if (FaultWriteQueueInitialized) {
        data = FltCbdqRemoveNextIo(&FaultWriteQueue, NULL);
        if (data != NULL) {
            generation = (ULONG_PTR)InterlockedCompareExchange64(&FaultWriteArmGeneration, 0, 0);
            InterlockedExchange(&FaultWriteCurrentHeld, 0);
            InterlockedIncrement64(&FaultWriteReleased);
            if (InterlockedCompareExchange(&FaultWriteSyntheticFailure, 0, 0) != 0) {
                /* Explicit synthetic pre-dispatch failure; it has no lower FS post receipt. */
                data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                data->IoStatus.Information = 0;
                InterlockedExchange(&FaultWriteLowerStatus, STATUS_INSUFFICIENT_RESOURCES);
                InterlockedExchange64(&FaultWriteLowerInformation, 0);
                InterlockedIncrement64(&FaultWriteSyntheticFailures);
                FltCompletePendedPreOperation(data, FLT_PREOP_COMPLETE, NULL);
                InterlockedDecrement(&FaultWriteOutstanding);
                ExReleaseRundownProtection(&FaultWriteCallbacks);
            } else {
                /* Resume this same queued IRP below the test filter, now with a post receipt. */
                FltCompletePendedPreOperation(data, FLT_PREOP_SUCCESS_WITH_CALLBACK,
                    (PVOID)generation);
            }
        }
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static FLT_PREOP_CALLBACK_STATUS FaultPreWrite(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    PFILE_OBJECT file = NULL;
    ULONG mode;
    KIRQL irql;
    NTSTATUS status = STATUS_SUCCESS;
    LARGE_INTEGER writeOffset;
    ULONG writeLength, writeIrpFlags;
    BOOLEAN preCallbackReference = FALSE;
    BOOLEAN queuedOperationReference = FALSE;
    UNREFERENCED_PARAMETER(Objects);
    *CompletionContext = NULL;
    if (!FLT_IS_IRP_OPERATION(Data) || Data->Iopb->MajorFunction != IRP_MJ_WRITE ||
        FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO) ||
        !FlagOn(Data->Iopb->IrpFlags, IRP_NOCACHE) || Data->Iopb->TargetFileObject == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    file = Data->Iopb->TargetFileObject;
    if (KeGetCurrentIrql() > APC_LEVEL) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (FsRtlIsPagingFile(file)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    KeEnterCriticalRegion();
    if (!ExAcquireRundownProtection(&FaultWriteCallbacks)) {
        KeLeaveCriticalRegion();
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    preCallbackReference = TRUE;
    KeLeaveCriticalRegion();
    /* Snapshot callback data before queue publication. An already-canceled IRP
     * may complete from the CBDQ cancellation callback as insertion returns. */
    writeOffset = Data->Iopb->Parameters.Write.ByteOffset;
    writeLength = Data->Iopb->Parameters.Write.Length;
    writeIrpFlags = Data->Iopb->IrpFlags;
    KeAcquireSpinLock(&FaultLock, &irql);
    mode = FaultWriteMode;
    if (mode != SECTION_FAULT_WRITE_ARM || FaultWriteFile != file ||
        InterlockedCompareExchange(&FaultWriteCurrentHeld, 0, 0) != 0) {
        mode = 0;
    } else {
        /* Keep the pre-callback and queued operation as distinct rundown owners.
         * Cancellation may complete synchronously while FltCbdqInsertIo returns;
         * its callback may release only the queued-operation reference. */
        if (!ExAcquireRundownProtection(&FaultWriteCallbacks)) {
            mode = 0;
            KeReleaseSpinLock(&FaultLock, irql);
            ExReleaseRundownProtection(&FaultWriteCallbacks);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        queuedOperationReference = TRUE;
        /* One-shot arm: only this exact nonpaging IRP is admitted to the queue. */
        FaultWriteMode = 0;
        InterlockedExchange(&FaultWriteCurrentHeld, 1);
        InterlockedIncrement(&FaultWriteOutstanding);
        /* Publish the accepted request snapshot before queue publication: a
         * synchronous cancel callback must not be overwritten on return. */
        InterlockedIncrement64(&FaultWriteMatched);
        InterlockedIncrement64(&FaultWriteHeld);
        InterlockedExchange64(&FaultWriteOffset, writeOffset.QuadPart);
        InterlockedExchange(&FaultWriteLength, writeLength);
        InterlockedExchange(&FaultWriteIrpFlags, writeIrpFlags);
        /* Keep arm-claim and queue insertion under FaultLock. The watchdog
         * uses this same lock before disarming an unmatched arm. CBDQ callbacks
         * use only the separate queue spin lock, never FaultLock. */
        status = FltCbdqInsertIo(&FaultWriteQueue, Data, NULL, NULL);
        if (NT_SUCCESS(status)) {
            /* Transfer the queued reference to the cancel/post owner. */
            queuedOperationReference = FALSE;
            KeSetEvent(&FaultWriteQueued, IO_NO_INCREMENT, FALSE);
        } else {
            InterlockedExchange(&FaultWriteCurrentHeld, 0);
            InterlockedDecrement(&FaultWriteOutstanding);
            InterlockedDecrement64(&FaultWriteHeld);
            InterlockedDecrement64(&FaultWriteMatched);
            InterlockedExchange64(&FaultWriteOffset, 0);
            InterlockedExchange(&FaultWriteLength, 0);
            InterlockedExchange(&FaultWriteIrpFlags, 0);
            KeSetEvent(&FaultWriteQueued, IO_NO_INCREMENT, FALSE);
        }
    }
    KeReleaseSpinLock(&FaultLock, irql);
    if (mode == 0) {
        if (preCallbackReference) ExReleaseRundownProtection(&FaultWriteCallbacks);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (!NT_SUCCESS(status)) {
        KeSetEvent(&FaultWriteRelease, IO_NO_INCREMENT, FALSE);
        if (queuedOperationReference) ExReleaseRundownProtection(&FaultWriteCallbacks);
        if (preCallbackReference) ExReleaseRundownProtection(&FaultWriteCallbacks);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (preCallbackReference) ExReleaseRundownProtection(&FaultWriteCallbacks);
    return FLT_PREOP_PENDING;
}

static FLT_POSTOP_CALLBACK_STATUS FaultPostWrite(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Objects);
    InterlockedExchange(&FaultWriteLowerStatus, Data->IoStatus.Status);
    InterlockedExchange64(&FaultWriteLowerInformation, (LONG64)Data->IoStatus.Information);
    InterlockedExchange(&FaultWritePostFlags, (LONG)Flags);
    InterlockedExchange64(&FaultWriteLowerCallbackData, (LONG64)(ULONG_PTR)Data);
    if ((ULONG_PTR)CompletionContext ==
        (ULONG_PTR)InterlockedCompareExchange64(&FaultWriteArmGeneration, 0, 0)) {
        InterlockedIncrement64(&FaultWriteLowerPosts);
        InterlockedExchange(&FaultWriteCurrentHeld, 0);
        InterlockedDecrement(&FaultWriteOutstanding);
    }
    ExReleaseRundownProtection(&FaultWriteCallbacks);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

/* Caller owns FaultControl. Wake held lower callbacks before waiting for their rundown. */
static VOID FaultDisarmLocked(VOID)
{
    PFILE_OBJECT file;
    PFLT_VOLUME volume;
    KIRQL irql;
    KeAcquireSpinLock(&FaultLock, &irql);
    FaultMode = 0;
    file = FaultFile; FaultFile = NULL;
    volume = FaultVolume; FaultVolume = NULL;
    KeReleaseSpinLock(&FaultLock, irql);
    KeSetEvent(&FaultRelease, IO_NO_INCREMENT, FALSE);
    ExWaitForRundownProtectionRelease(&FaultCallbacks);
    if (file != NULL) ObDereferenceObject(file);
    if (volume != NULL) FltObjectDereference(volume);
}

static VOID FaultDisarm(VOID)
{
    KeWaitForSingleObject(&FaultControl, Executive, KernelMode, FALSE, NULL);
    FaultDisarmLocked();
    KeReleaseMutex(&FaultControl, FALSE);
}

static FLT_PREOP_CALLBACK_STATUS FaultPreSection(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    ULONG mode = 0, protection = Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection;
    KIRQL irql;
    LARGE_INTEGER timeout;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(Objects);
    *CompletionContext = NULL;
    if (Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType != SyncTypeCreateSection ||
        !FlagOn(protection, PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (KeGetCurrentIrql() > APC_LEVEL) {
        InterlockedIncrement64(&FaultInvalidIrql);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    KeEnterCriticalRegion();
    if (!ExAcquireRundownProtection(&FaultCallbacks)) {
        KeLeaveCriticalRegion();
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    KeAcquireSpinLock(&FaultLock, &irql);
    if (FaultFile != NULL && FaultFile == Data->Iopb->TargetFileObject) mode = FaultMode;
    KeReleaseSpinLock(&FaultLock, irql);
    if (mode != 0) InterlockedIncrement64(&FaultMatched);
    if (mode == SECTION_FAULT_ARM_HOLD) {
        InterlockedIncrement(&FaultCurrentHeld);
        InterlockedIncrement64(&FaultHeld);
        timeout.QuadPart = -30LL * 1000 * 1000 * 10; /* bounded watchdog; timeout invalidates the test */
        status = KeWaitForSingleObject(&FaultRelease, Executive, KernelMode, FALSE, &timeout);
        if (status != STATUS_SUCCESS) InterlockedIncrement64(&FaultTimedOut);
        InterlockedDecrement(&FaultCurrentHeld);
    }
    if (mode == SECTION_FAULT_ARM_FAILURE) {
        /* Explicit synthetic lower-stack resource failure, exercising upper post-acquire cleanup. */
        InterlockedIncrement64(&FaultFailed);
        Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Data->IoStatus.Information = 0;
    }
    ExReleaseRundownProtection(&FaultCallbacks);
    KeLeaveCriticalRegion();
    return mode == SECTION_FAULT_ARM_FAILURE ? FLT_PREOP_COMPLETE : FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static BOOLEAN FaultCallerIsSystem(VOID)
{
    SECURITY_SUBJECT_CONTEXT subject;
    PTOKEN_USER user = NULL;
    NTSTATUS status;
    BOOLEAN system;
    SeCaptureSubjectContext(&subject);
    SeLockSubjectContext(&subject);
    status = SeQueryInformationToken(SeQuerySubjectContextToken(&subject), TokenUser, (PVOID *)&user);
    system = NT_SUCCESS(status) && user != NULL && RtlEqualSid(user->User.Sid, SeExports->SeLocalSystemSid);
    SeUnlockSubjectContext(&subject);
    SeReleaseSubjectContext(&subject);
    if (user != NULL) ExFreePool(user);
    return system;
}

static NTSTATUS FaultConnect(_In_ PFLT_PORT ClientPort, _In_opt_ PVOID ServerCookie,
    _In_reads_bytes_opt_(ContextBytes) PVOID Context, _In_ ULONG ContextBytes, _Outptr_result_maybenull_ PVOID *Cookie)
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(ServerCookie); UNREFERENCED_PARAMETER(Context); UNREFERENCED_PARAMETER(ContextBytes);
    *Cookie = NULL;
    if (!FaultCallerIsSystem()) return STATUS_ACCESS_DENIED;
    KeWaitForSingleObject(&FaultControl, Executive, KernelMode, FALSE, NULL);
    status = FaultStopping ? STATUS_DELETE_PENDING : STATUS_SUCCESS;
    if (NT_SUCCESS(status)) {
        FaultClient = ClientPort;
        *Cookie = PsGetCurrentProcess();
        ObReferenceObject(*Cookie);
    }
    KeReleaseMutex(&FaultControl, FALSE);
    return status;
}

static VOID FaultDisconnect(_In_opt_ PVOID Cookie)
{
    PFLT_PORT client;
    KeWaitForSingleObject(&FaultControl, Executive, KernelMode, FALSE, NULL);
    FaultDisarmLocked();
    FaultWriteDisarmLocked();
    client = FaultClient; FaultClient = NULL;
    KeReleaseMutex(&FaultControl, FALSE);
    FltCloseClientPort(FaultFilter, &client);
    if (Cookie != NULL) ObDereferenceObject(Cookie);
}

/* Caller owns FaultControl. The watchdog bounds time in the queue; rundown
 * still waits until released I/O returns through the lower post callback. */
static VOID FaultWriteJoinLocked(VOID)
{
    if (FaultWriteWorkerHandle != NULL) {
        (VOID)ZwWaitForSingleObject(FaultWriteWorkerHandle, FALSE, NULL);
        ZwClose(FaultWriteWorkerHandle);
        FaultWriteWorkerHandle = NULL;
    }
}

static VOID FaultWriteDisarmLocked(VOID)
{
    PFILE_OBJECT file;
    PFLT_VOLUME volume;
    KIRQL irql;
    KeAcquireSpinLock(&FaultLock, &irql);
    FaultWriteMode = 0;
    file = FaultWriteFile; FaultWriteFile = NULL;
    volume = FaultWriteVolume; FaultWriteVolume = NULL;
    KeReleaseSpinLock(&FaultLock, irql);
    KeSetEvent(&FaultWriteQueued, IO_NO_INCREMENT, FALSE);
    KeSetEvent(&FaultWriteRelease, IO_NO_INCREMENT, FALSE);
    FaultWriteJoinLocked();
    if (!FaultWriteRundownClosed) {
        ExWaitForRundownProtectionRelease(&FaultWriteCallbacks);
        FaultWriteRundownClosed = TRUE;
    }
    if (file != NULL) ObDereferenceObject(file);
    if (volume != NULL) FltObjectDereference(volume);
}

static VOID FaultWriteFillReply(_Out_ SECTION_FAULT_WRITE_REPLY *Reply)
{
    KIRQL irql;
    RtlZeroMemory(Reply, sizeof(*Reply));
    Reply->Version = SECTION_FAULT_WRITE_VERSION;
    KeAcquireSpinLock(&FaultLock, &irql);
    Reply->Mode = FaultWriteMode;
    Reply->ArmedFileObject = (UINT64)(ULONG_PTR)FaultWriteFile;
    KeReleaseSpinLock(&FaultLock, irql);
    Reply->CurrentHeld = (ULONG)InterlockedCompareExchange(&FaultWriteCurrentHeld, 0, 0);
    Reply->PostFlags = (ULONG)InterlockedCompareExchange(&FaultWritePostFlags, 0, 0);
    Reply->ArmGeneration = (UINT64)InterlockedCompareExchange64(&FaultWriteArmGeneration, 0, 0);
    Reply->Matched = (UINT64)InterlockedCompareExchange64(&FaultWriteMatched, 0, 0);
    Reply->Held = (UINT64)InterlockedCompareExchange64(&FaultWriteHeld, 0, 0);
    Reply->Released = (UINT64)InterlockedCompareExchange64(&FaultWriteReleased, 0, 0);
    Reply->LowerPosts = (UINT64)InterlockedCompareExchange64(&FaultWriteLowerPosts, 0, 0);
    Reply->Canceled = (UINT64)InterlockedCompareExchange64(&FaultWriteCanceled, 0, 0);
    Reply->TimedOut = (UINT64)InterlockedCompareExchange64(&FaultWriteTimedOut, 0, 0);
    Reply->LowerStatus = (INT32)InterlockedCompareExchange(&FaultWriteLowerStatus, 0, 0);
    Reply->LowerInformation = (UINT64)InterlockedCompareExchange64(&FaultWriteLowerInformation, 0, 0);
    Reply->LowerCallbackData = (UINT64)InterlockedCompareExchange64(&FaultWriteLowerCallbackData, 0, 0);
    Reply->SyntheticFailures = (UINT64)InterlockedCompareExchange64(&FaultWriteSyntheticFailures, 0, 0);
    Reply->WriteOffset = (UINT64)InterlockedCompareExchange64(&FaultWriteOffset, 0, 0);
    Reply->WriteLength = (UINT32)InterlockedCompareExchange(&FaultWriteLength, 0, 0);
    Reply->IrpFlags = (UINT32)InterlockedCompareExchange(&FaultWriteIrpFlags, 0, 0);
}

static NTSTATUS FaultWriteMessage(_In_ SECTION_FAULT_WRITE_REQUEST *Request,
    _Out_ SECTION_FAULT_WRITE_REPLY *Reply)
{
    PFILE_OBJECT file = NULL;
    PFLT_VOLUME volume = NULL, attachedVolume = NULL;
    OBJECT_ATTRIBUTES attributes;
    NTSTATUS status = STATUS_SUCCESS;
    KIRQL irql;
    if (Request->Version != SECTION_FAULT_WRITE_VERSION || Request->Reserved != 0 ||
        Request->Command < SECTION_FAULT_WRITE_ARM || Request->Command > SECTION_FAULT_WRITE_SYNTHETIC_FAILURE)
        return STATUS_INVALID_PARAMETER;
    KeWaitForSingleObject(&FaultControl, Executive, KernelMode, FALSE, NULL);
    if (FaultStopping) { status = STATUS_DELETE_PENDING; goto Done; }
    if (Request->Command == SECTION_FAULT_WRITE_ARM) {
        if (!FaultWriteQueueInitialized || FaultWriteInstance == NULL || FaultWriteWorkerHandle != NULL ||
            InterlockedCompareExchange(&FaultWriteCurrentHeld, 0, 0) != 0 ||
            InterlockedCompareExchange(&FaultWriteOutstanding, 0, 0) != 0) {
            status = STATUS_DEVICE_BUSY; goto Done;
        }
        status = ObReferenceObjectByHandle((HANDLE)(ULONG_PTR)Request->FileHandle,
            FILE_READ_DATA | FILE_WRITE_DATA, *IoFileObjectType, UserMode, (PVOID *)&file, NULL);
        if (!NT_SUCCESS(status)) goto Done;
        if (file->SectionObjectPointer == NULL || FlagOn(file->Flags, FO_VOLUME_OPEN) || FsRtlIsPagingFile(file)) {
            status = STATUS_INVALID_PARAMETER; goto Done;
        }
        status = FltGetVolumeFromFileObject(FaultFilter, file, &volume);
        if (!NT_SUCCESS(status)) goto Done;
        status = FltGetVolumeFromInstance(FaultWriteInstance, &attachedVolume);
        if (!NT_SUCCESS(status)) goto Done;
        if (volume != attachedVolume) { status = STATUS_INVALID_PARAMETER; goto Done; }
        if (FaultWriteRundownClosed) {
            ExReInitializeRundownProtection(&FaultWriteCallbacks);
            FaultWriteRundownClosed = FALSE;
        }
        KeClearEvent(&FaultWriteRelease);
        KeClearEvent(&FaultWriteQueued);
        InterlockedExchange64(&FaultWriteMatched, 0);
        InterlockedExchange64(&FaultWriteHeld, 0);
        InterlockedExchange64(&FaultWriteReleased, 0);
        InterlockedExchange64(&FaultWriteLowerPosts, 0);
        InterlockedExchange64(&FaultWriteCanceled, 0);
        InterlockedExchange64(&FaultWriteTimedOut, 0);
        InterlockedExchange64(&FaultWriteSyntheticFailures, 0);
        InterlockedExchange(&FaultWriteSyntheticFailure, 0);
        InterlockedExchange(&FaultWritePostFlags, 0);
        InterlockedExchange(&FaultWriteLowerStatus, STATUS_PENDING);
        InterlockedExchange64(&FaultWriteLowerInformation, 0);
        InterlockedExchange64(&FaultWriteLowerCallbackData, 0);
        InterlockedExchange64(&FaultWriteOffset, 0);
        InterlockedExchange(&FaultWriteLength, 0);
        InterlockedExchange(&FaultWriteIrpFlags, 0);
        KeAcquireSpinLock(&FaultLock, &irql);
        FaultWriteFile = file; file = NULL;
        FaultWriteVolume = volume; volume = NULL;
        FaultWriteMode = SECTION_FAULT_WRITE_ARM;
        InterlockedIncrement64(&FaultWriteArmGeneration);
        KeReleaseSpinLock(&FaultLock, irql);
        InitializeObjectAttributes(&attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
        status = PsCreateSystemThread(&FaultWriteWorkerHandle, SYNCHRONIZE, &attributes,
            NULL, NULL, FaultWriteWorker, NULL);
        if (!NT_SUCCESS(status)) FaultWriteDisarmLocked();
    } else if (Request->Command == SECTION_FAULT_WRITE_RELEASE) {
        if (InterlockedCompareExchange(&FaultWriteCurrentHeld, 0, 0) == 0) {
            status = STATUS_NOT_FOUND; goto Done;
        }
        KeSetEvent(&FaultWriteRelease, IO_NO_INCREMENT, FALSE);
        FaultWriteJoinLocked();
    } else if (Request->Command == SECTION_FAULT_WRITE_SYNTHETIC_FAILURE) {
        if (InterlockedCompareExchange(&FaultWriteCurrentHeld, 0, 0) == 0) {
            status = STATUS_NOT_FOUND; goto Done;
        }
        InterlockedExchange(&FaultWriteSyntheticFailure, 1);
        KeSetEvent(&FaultWriteRelease, IO_NO_INCREMENT, FALSE);
        FaultWriteJoinLocked();
    } else if (Request->Command == SECTION_FAULT_WRITE_DISARM) {
        FaultWriteDisarmLocked();
    }
    if (NT_SUCCESS(status)) FaultWriteFillReply(Reply);
Done:
    if (file != NULL) ObDereferenceObject(file);
    if (volume != NULL) FltObjectDereference(volume);
    if (attachedVolume != NULL) FltObjectDereference(attachedVolume);
    KeReleaseMutex(&FaultControl, FALSE);
    return status;
}

static NTSTATUS FaultMessage(_In_opt_ PVOID Cookie, _In_reads_bytes_opt_(InputBytes) PVOID Input,
    _In_ ULONG InputBytes, _Out_writes_bytes_to_opt_(OutputBytes, *Returned) PVOID Output,
    _In_ ULONG OutputBytes, _Out_ PULONG Returned)
{
    SECTION_FAULT_REQUEST request;
    SECTION_FAULT_REPLY reply = {0};
    PFILE_OBJECT file = NULL;
    PFLT_VOLUME volume = NULL;
    PFLT_INSTANCE instance = NULL;
    KIRQL irql;
    NTSTATUS status = STATUS_SUCCESS;
    *Returned = 0;
    if (Cookie == NULL || Cookie != PsGetCurrentProcess() || !FaultCallerIsSystem()) return STATUS_ACCESS_DENIED;
    if (Input != NULL && InputBytes >= sizeof(ULONG) && Output != NULL) {
        ULONG version = 0;
        __try { RtlCopyMemory(&version, Input, sizeof(version)); }
        __except(EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
        if (version == SECTION_FAULT_WRITE_VERSION) {
            SECTION_FAULT_WRITE_REQUEST writeRequest;
            SECTION_FAULT_WRITE_REPLY writeReply;
            if (InputBytes != sizeof(writeRequest) || OutputBytes < sizeof(writeReply))
                return STATUS_INVALID_PARAMETER;
            __try { RtlCopyMemory(&writeRequest, Input, sizeof(writeRequest)); }
            __except(EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
            status = FaultWriteMessage(&writeRequest, &writeReply);
            if (NT_SUCCESS(status)) {
                __try { RtlCopyMemory(Output, &writeReply, sizeof(writeReply)); *Returned = sizeof(writeReply); }
                __except(EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
            }
            return status;
        }
    }
    if (Input == NULL || InputBytes != sizeof(request) || Output == NULL || OutputBytes < sizeof(reply))
        return STATUS_INVALID_PARAMETER;
    __try { RtlCopyMemory(&request, Input, sizeof(request)); }
    __except(EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
    if (request.Version != SECTION_FAULT_VERSION || request.Command > SECTION_FAULT_DISARM)
        return STATUS_INVALID_PARAMETER;
    KeWaitForSingleObject(&FaultControl, Executive, KernelMode, FALSE, NULL);
    if (FaultStopping) { status = STATUS_DELETE_PENDING; goto Done; }
    if (request.Command == SECTION_FAULT_ARM_FAILURE || request.Command == SECTION_FAULT_ARM_HOLD) {
        FaultDisarmLocked();
        status = ObReferenceObjectByHandle((HANDLE)(ULONG_PTR)request.FileHandle,
            FILE_READ_DATA | FILE_WRITE_DATA, *IoFileObjectType, UserMode, (PVOID *)&file, NULL);
        if (!NT_SUCCESS(status)) goto Done;
        if (file->SectionObjectPointer == NULL || FlagOn(file->Flags, FO_VOLUME_OPEN) || FsRtlIsPagingFile(file)) {
            status = STATUS_INVALID_PARAMETER; goto Done;
        }
        status = FltGetVolumeFromFileObject(FaultFilter, file, &volume);
        if (!NT_SUCCESS(status)) goto Done;
        status = FltGetVolumeInstanceFromName(FaultFilter, volume, NULL, &instance);
        if (!NT_SUCCESS(status)) goto Done; /* only a volume manually qualified by InstanceSetup */
        FltObjectDereference(instance); instance = NULL;
        ExReInitializeRundownProtection(&FaultCallbacks);
        KeClearEvent(&FaultRelease);
        KeAcquireSpinLock(&FaultLock, &irql);
        FaultFile = file; file = NULL;
        FaultVolume = volume; volume = NULL;
        FaultMode = request.Command;
        InterlockedIncrement64(&FaultArmGeneration);
        KeReleaseSpinLock(&FaultLock, irql);
    } else if (request.Command == SECTION_FAULT_RELEASE) {
        KeSetEvent(&FaultRelease, IO_NO_INCREMENT, FALSE);
    } else if (request.Command == SECTION_FAULT_DISARM) {
        FaultDisarmLocked();
    }
    reply.Version = SECTION_FAULT_VERSION;
    KeAcquireSpinLock(&FaultLock, &irql);
    reply.Mode = FaultMode;
    reply.ArmedFileObject = (UINT64)(ULONG_PTR)FaultFile;
    reply.ArmGeneration = (UINT64)InterlockedCompareExchange64(&FaultArmGeneration, 0, 0);
    KeReleaseSpinLock(&FaultLock, irql);
    reply.Matched = (UINT64)InterlockedCompareExchange64(&FaultMatched, 0, 0);
    reply.Failed = (UINT64)InterlockedCompareExchange64(&FaultFailed, 0, 0);
    reply.Held = (UINT64)InterlockedCompareExchange64(&FaultHeld, 0, 0);
    reply.TimedOut = (UINT64)InterlockedCompareExchange64(&FaultTimedOut, 0, 0);
    reply.InvalidIrql = (UINT64)InterlockedCompareExchange64(&FaultInvalidIrql, 0, 0);
    reply.CurrentHeld = (ULONG)InterlockedCompareExchange(&FaultCurrentHeld, 0, 0);
Done:
    if (file != NULL) ObDereferenceObject(file);
    if (volume != NULL) FltObjectDereference(volume);
    if (instance != NULL) FltObjectDereference(instance);
    KeReleaseMutex(&FaultControl, FALSE);
    if (NT_SUCCESS(status)) {
        __try { RtlCopyMemory(Output, &reply, sizeof(reply)); *Returned = sizeof(reply); }
        __except(EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
    }
    return status;
}

static NTSTATUS FaultSetup(_In_ PCFLT_RELATED_OBJECTS Objects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE DeviceType, _In_ FLT_FILESYSTEM_TYPE FileSystem)
{
    FLT_VOLUME_PROPERTIES properties;
    ULONG bytes;
    NTSTATUS status;
    if (!FlagOn(Flags, FLTFL_INSTANCE_SETUP_MANUAL_ATTACHMENT) ||
        DeviceType != FILE_DEVICE_DISK_FILE_SYSTEM || FileSystem != FLT_FSTYPE_NTFS) return STATUS_FLT_DO_NOT_ATTACH;
    status = FltGetVolumeProperties(Objects->Volume, &properties, sizeof(properties), &bytes);
    if (NT_ERROR(status) || FlagOn(properties.DeviceCharacteristics, FILE_REMOVABLE_MEDIA)) return STATUS_FLT_DO_NOT_ATTACH;
    /* This qualification filter intentionally supports one manually attached
     * volume at a time, keeping its one bounded W queue tied to one instance. */
    KeWaitForSingleObject(&FaultControl, Executive, KernelMode, FALSE, NULL);
    if (FaultWriteInstance != NULL) {
        status = STATUS_FLT_DO_NOT_ATTACH;
    } else {
        RtlZeroMemory(&FaultWriteQueue, sizeof(FaultWriteQueue));
        InitializeListHead(&FaultWriteQueueList);
        status = FltCbdqInitialize(Objects->Instance, &FaultWriteQueue,
            FaultCbdqInsertIo, FaultCbdqRemoveIo, FaultCbdqPeekNextIo,
            FaultCbdqAcquire, FaultCbdqRelease, FaultCbdqCompleteCanceledIo);
        if (NT_SUCCESS(status)) {
            status = FltObjectReference(Objects->Instance);
            if (NT_SUCCESS(status)) {
                FaultWriteInstance = Objects->Instance;
                FaultWriteQueueInitialized = TRUE;
            }
        }
    }
    KeReleaseMutex(&FaultControl, FALSE);
    if (!NT_SUCCESS(status)) return status;
    return STATUS_SUCCESS;
}

static VOID FaultTeardown(_In_ PCFLT_RELATED_OBJECTS Objects, _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags)
{
    PFLT_INSTANCE instance = NULL;
    UNREFERENCED_PARAMETER(Flags);
    KeWaitForSingleObject(&FaultControl, Executive, KernelMode, FALSE, NULL);
    FaultDisarmLocked();
    if (FaultWriteInstance == Objects->Instance) {
        instance = FaultWriteInstance;
        FltCbdqDisable(&FaultWriteQueue);
        FaultWriteDisarmLocked();
        FaultWriteQueueInitialized = FALSE;
        FaultWriteInstance = NULL;
    }
    KeReleaseMutex(&FaultControl, FALSE);
    if (instance != NULL) FltObjectDereference(instance);
}

static NTSTATUS FaultUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    FltCloseCommunicationPort(FaultServer); FaultServer = NULL;
    KeWaitForSingleObject(&FaultControl, Executive, KernelMode, FALSE, NULL);
    FaultStopping = TRUE;
    FaultDisarmLocked();
    FaultWriteDisarmLocked();
    KeReleaseMutex(&FaultControl, FALSE);
    FltUnregisterFilter(FaultFilter);
    return STATUS_SUCCESS;
}

static CONST FLT_OPERATION_REGISTRATION FaultOperations[] = {
    {IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION, 0, FaultPreSection, NULL},
    {IRP_MJ_WRITE, 0, FaultPreWrite, FaultPostWrite},
    {IRP_MJ_OPERATION_END}
};
static CONST FLT_REGISTRATION FaultRegistration = {
    sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION, 0, NULL, FaultOperations,
    FaultUnload, FaultSetup, NULL, FaultTeardown, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};
DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING name = RTL_CONSTANT_STRING(SECTION_FAULT_PORT);
    OBJECT_ATTRIBUTES attributes;
    PSECURITY_DESCRIPTOR security = NULL;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(RegistryPath);
    KeInitializeMutex(&FaultControl, 0); KeInitializeSpinLock(&FaultLock);
    KeInitializeSpinLock(&FaultWriteQueueLock);
    ExInitializeRundownProtection(&FaultWriteCallbacks);
    KeInitializeEvent(&FaultWriteRelease, NotificationEvent, TRUE);
    KeInitializeEvent(&FaultWriteQueued, NotificationEvent, FALSE);
    ExInitializeRundownProtection(&FaultCallbacks);
    KeInitializeEvent(&FaultRelease, NotificationEvent, TRUE);
    status = FltRegisterFilter(DriverObject, &FaultRegistration, &FaultFilter);
    if (!NT_SUCCESS(status)) return status;
    status = FltBuildDefaultSecurityDescriptor(&security, FLT_PORT_ALL_ACCESS);
    if (NT_SUCCESS(status)) {
        InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, security);
        status = FltCreateCommunicationPort(FaultFilter, &FaultServer, &attributes, NULL,
            FaultConnect, FaultDisconnect, FaultMessage, 1);
        FltFreeSecurityDescriptor(security);
    }
    if (NT_SUCCESS(status)) status = FltStartFiltering(FaultFilter);
    if (!NT_SUCCESS(status)) {
        if (FaultServer != NULL) FltCloseCommunicationPort(FaultServer);
        KeWaitForSingleObject(&FaultControl, Executive, KernelMode, FALSE, NULL);
        FaultStopping = TRUE;
        FaultDisarmLocked();
        FaultWriteDisarmLocked();
        KeReleaseMutex(&FaultControl, FALSE);
        FltUnregisterFilter(FaultFilter);
    }
    return status;
}
