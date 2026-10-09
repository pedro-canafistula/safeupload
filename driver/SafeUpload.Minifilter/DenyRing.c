#include "Filter.h"

#if SAFEUPLOAD_STAGING_PROTOTYPE

#include "Stage.h"

/*
 *  Deny ring: an always-on record of the operations SafeUpload completes with an error status.
 *
 *  It exists because the port accepts one client and the service holds it, so the Inspector cannot read a driver
 *  trace while the product runs, and because a refusal outside every protected scope (a new user's profile cannot be
 *  created) left no evidence of what was refused. Everything here is built for the I/O path: a fixed ring, one short
 *  spin lock, no allocation, no name query. Refusals are exceptional, so the lock is cold.
 *
 *  The choke point is SafeUploadStageDispatch (every operation is registered through it). A shared refusal helper
 *  may call SafeUploadDenySiteHint first, so the record names the code that chose the refusal instead of only the
 *  dispatcher.
 */

#define DENY_HINT_SLOTS 128

static KSPIN_LOCK DenyLock;
static SAFEUPLOAD_DENY_RECORD DenyRing[SAFEUPLOAD_DENY_RING_SLOTS];
static UINT64 DenyNext = 1;                       /* DenyLock */
static ULONG_PTR DenyImageBase;
static volatile LONG64 DenyHints[DENY_HINT_SLOTS];
static volatile LONG64 DenyRecorded;
static volatile LONG64 DenyAccessDenied;
static volatile LONG64 DenyRetry;
static volatile LONG64 DenyOtherStatus;
static volatile LONG64 DenyBenignIgnored;
static volatile LONG64 DenyNotRecorded;

_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_raises_(DISPATCH_LEVEL)
__declspec(noinline) static VOID DenyAcquire(
    _Out_ _At_(*OldIrql, _IRQL_saves_) PKIRQL OldIrql)
{
    KeAcquireSpinLock(&DenyLock, OldIrql);
}

_IRQL_requires_(DISPATCH_LEVEL)
__declspec(noinline) static VOID DenyRelease(_In_ _IRQL_restores_ KIRQL OldIrql)
{
    KeReleaseSpinLock(&DenyLock, OldIrql);
}

/* The linker places this symbol at the image base. DRIVER_OBJECT.DriverStart is off limits to a driver (C28175). */
extern UCHAR __ImageBase;

VOID SafeUploadDenyRingInitialize(VOID)
{
    KeInitializeSpinLock(&DenyLock);
    DenyNext = 1;
    DenyImageBase = (ULONG_PTR)&__ImageBase;
}

static ULONG DenyHintIndex(VOID)
{
    return KeGetCurrentProcessorNumberEx(NULL) % DENY_HINT_SLOTS;
}

static ULONG DenyDataKey(_In_ PFLT_CALLBACK_DATA Data)
{
    return (ULONG)((ULONG_PTR)Data >> 4);
}

VOID SafeUploadDenySiteHint(_In_ PFLT_CALLBACK_DATA Data, _In_ PVOID Site)
{
    ULONG_PTR offset = (ULONG_PTR)Site - DenyImageBase;
    LONG64 hint;

    if ((ULONG_PTR)Site < DenyImageBase || offset > MAXULONG) offset = 0;
    hint = (LONG64)(((ULONG64)DenyDataKey(Data) << 32) | (ULONG64)offset);
    InterlockedExchange64(&DenyHints[DenyHintIndex()], hint);
}

static UINT32 DenyTakeHint(_In_ PFLT_CALLBACK_DATA Data)
{
    LONG64 hint = InterlockedExchange64(&DenyHints[DenyHintIndex()], 0);

    if (hint != 0 && (ULONG)((ULONG64)hint >> 32) == DenyDataKey(Data)) return (UINT32)(ULONG64)hint;
    return 0;
}

static BOOLEAN DenyStatusIsBenign(_In_ NTSTATUS Status)
{
    return Status == STATUS_END_OF_FILE || Status == STATUS_NO_MORE_FILES ||
        Status == STATUS_NO_MORE_ENTRIES || Status == STATUS_BUFFER_OVERFLOW;
}

static VOID DenyCopyNameTail(_Inout_ PSAFEUPLOAD_DENY_RECORD Record, _In_reads_(Chars) const WCHAR *Name,
    _In_ ULONG Chars, _In_ UINT32 NameFlag)
{
    ULONG count = Chars;

    if (count > SAFEUPLOAD_DENY_NAME_CHARS) {
        Name += count - SAFEUPLOAD_DENY_NAME_CHARS;
        count = SAFEUPLOAD_DENY_NAME_CHARS;
        Record->Flags |= SAFEUPLOAD_DENY_FLAG_NAME_TRUNCATED;
    }
    RtlCopyMemory(Record->Name, Name, count * sizeof(WCHAR));
    Record->NameChars = count;
    Record->Flags |= NameFlag;
}

/* What the request itself carries, nothing resolved: a create's requested path, a rename's or link's target. */
static VOID DenyCaptureRequest(_In_ PFLT_CALLBACK_DATA Data, _Inout_ PSAFEUPLOAD_DENY_RECORD Record)
{
    PFLT_PARAMETERS parameters = &Data->Iopb->Parameters;

    switch (Data->Iopb->MajorFunction) {
    case IRP_MJ_CREATE:
        {
            PIO_SECURITY_CONTEXT security = parameters->Create.SecurityContext;
            PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;

            Record->Options = parameters->Create.Options;
            if (security != NULL) Record->Access = security->DesiredAccess;
            if (fileObject != NULL && fileObject->FileName.Buffer != NULL &&
                fileObject->FileName.Length != 0 && (fileObject->FileName.Length & 1) == 0 &&
                fileObject->FileName.Length <= 0x8000) {
                DenyCopyNameTail(Record, fileObject->FileName.Buffer,
                    fileObject->FileName.Length / sizeof(WCHAR), SAFEUPLOAD_DENY_FLAG_NAME_IS_CREATE_NAME);
            }
            break;
        }
    case IRP_MJ_SET_INFORMATION:
        {
            FILE_INFORMATION_CLASS information = parameters->SetFileInformation.FileInformationClass;

            Record->Access = (UINT32)information;
            if (information == FileRenameInformation || information == FileRenameInformationEx ||
                information == FileLinkInformation || information == FileLinkInformationEx) {
                PFILE_RENAME_INFORMATION rename = parameters->SetFileInformation.InfoBuffer;
                ULONG length = parameters->SetFileInformation.Length;

                if (rename != NULL && length >= (ULONG)FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName) &&
                    rename->FileNameLength != 0 && (rename->FileNameLength & 1) == 0 &&
                    rename->FileNameLength <= length - (ULONG)FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName)) {
                    DenyCopyNameTail(Record, rename->FileName, rename->FileNameLength / sizeof(WCHAR),
                        SAFEUPLOAD_DENY_FLAG_NAME_IS_RENAME_TARGET);
                }
            }
            break;
        }
    case IRP_MJ_WRITE:
        Record->Access = parameters->Write.Length;
        Record->Options = parameters->Write.ByteOffset.LowPart;
        break;
    case IRP_MJ_FILE_SYSTEM_CONTROL:
        Record->Access = parameters->FileSystemControl.Common.FsControlCode;
        break;
    case IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION:
        Record->Access = parameters->AcquireForSectionSynchronization.PageProtection;
        break;
    default:
        break;
    }
}

VOID SafeUploadDenyNote(_In_ PFLT_CALLBACK_DATA Data, _In_opt_ PCFLT_RELATED_OBJECTS Objects,
    _In_ NTSTATUS Status, _In_ BOOLEAN PostOperation)
{
    SAFEUPLOAD_DENY_RECORD record;
    KIRQL irql;
    KIRQL level = KeGetCurrentIrql();

    if (NT_SUCCESS(Status)) return;
    if (DenyStatusIsBenign(Status)) {
        InterlockedIncrement64(&DenyBenignIgnored);
        return;
    }
    if (level > DISPATCH_LEVEL) {
        InterlockedIncrement64(&DenyNotRecorded);
        return;
    }

    if (Status == STATUS_ACCESS_DENIED) InterlockedIncrement64(&DenyAccessDenied);
    else if (Status == STATUS_RETRY) InterlockedIncrement64(&DenyRetry);
    else InterlockedIncrement64(&DenyOtherStatus);

    RtlZeroMemory(&record, sizeof(record));
    record.Status = (UINT32)Status;
    record.Irql = (UINT32)level;
    record.MajorFunction = Data->Iopb->MajorFunction;
    record.MinorFunction = Data->Iopb->MinorFunction;
    record.ProcessId = FltGetRequestorProcessId(Data);
    if (Data->Thread != NULL) record.ThreadId = HandleToULong(PsGetThreadId(Data->Thread));
    if (IoGetTopLevelIrp() != NULL) record.Flags |= SAFEUPLOAD_DENY_FLAG_TOP_LEVEL_IRP;
    if (Objects != NULL && Objects->Transaction != NULL) record.Flags |= SAFEUPLOAD_DENY_FLAG_TRANSACTION;
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) record.Flags |= SAFEUPLOAD_DENY_FLAG_PAGING_IO;
    if (FLT_IS_FASTIO_OPERATION(Data)) record.Flags |= SAFEUPLOAD_DENY_FLAG_FAST_IO;
    if (PostOperation) record.Flags |= SAFEUPLOAD_DENY_FLAG_POST_OPERATION;
    if (Data->RequestorMode == KernelMode) record.Flags |= SAFEUPLOAD_DENY_FLAG_KERNEL_MODE;
    if (record.ProcessId != 0 && record.ProcessId == SafeUploadData.InspectorProcessId)
        record.Flags |= SAFEUPLOAD_DENY_FLAG_SERVICE_PROCESS;
    record.SiteOffset = DenyTakeHint(Data);

    __try {
        DenyCaptureRequest(Data, &record);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* A request buffer that cannot be read costs the name, never the record. */
        record.NameChars = 0;
        RtlZeroMemory(record.Name, sizeof(record.Name));
    }

    KeQuerySystemTimePrecise((PLARGE_INTEGER)&record.SystemTime);
    DenyAcquire(&irql);
    record.Sequence = DenyNext;
    DenyNext += 1;
    DenyRing[record.Sequence % SAFEUPLOAD_DENY_RING_SLOTS] = record;
    DenyRelease(irql);
    InterlockedIncrement64(&DenyRecorded);
}

NTSTATUS SafeUploadDenyRingReadBatch(_In_ UINT64 AfterSequence, _Out_ PSAFEUPLOAD_DENY_RING_BATCH Batch)
{
    KIRQL irql;
    UINT64 next, first, start, sequence;
    UINT32 count = 0;

    RtlZeroMemory(Batch, sizeof(*Batch));
    Batch->StructSize = sizeof(*Batch);
    Batch->ProtocolVersion = SAFEUPLOAD_PROTOCOL_VERSION;
    Batch->ImageBase = (UINT64)DenyImageBase;

    DenyAcquire(&irql);
    next = DenyNext;
    first = next > SAFEUPLOAD_DENY_RING_SLOTS ? next - SAFEUPLOAD_DENY_RING_SLOTS : 1;
    if (AfterSequence >= next - 1) {
        start = next;      /* caught up, or a cursor from before a driver reload: the reader sees NextSequence */
    } else if (AfterSequence + 1 < first) {
        start = first;
        Batch->Flags |= SAFEUPLOAD_DENY_BATCH_FLAG_GAP;
    } else {
        start = AfterSequence + 1;
    }
    for (sequence = start; sequence < next && count < SAFEUPLOAD_DENY_BATCH_ENTRIES; sequence += 1) {
        Batch->Entries[count] = DenyRing[sequence % SAFEUPLOAD_DENY_RING_SLOTS];
        count += 1;
    }
    Batch->Count = count;
    Batch->NextSequence = next;
    DenyRelease(irql);
    return STATUS_SUCCESS;
}

VOID SafeUploadDenyGetCounters(_Out_ PSAFEUPLOAD_DIAG_COUNTERS Counters)
{
    KIRQL irql;

    RtlZeroMemory(Counters, sizeof(*Counters));
    Counters->StructSize = sizeof(*Counters);
    Counters->ProtocolVersion = SAFEUPLOAD_PROTOCOL_VERSION;
    Counters->DenyRecorded = (UINT64)InterlockedCompareExchange64(&DenyRecorded, 0, 0);
    Counters->DenyAccessDenied = (UINT64)InterlockedCompareExchange64(&DenyAccessDenied, 0, 0);
    Counters->DenyRetry = (UINT64)InterlockedCompareExchange64(&DenyRetry, 0, 0);
    Counters->DenyOtherStatus = (UINT64)InterlockedCompareExchange64(&DenyOtherStatus, 0, 0);
    Counters->DenyBenignIgnored = (UINT64)InterlockedCompareExchange64(&DenyBenignIgnored, 0, 0);
    Counters->DenyNotRecorded = (UINT64)InterlockedCompareExchange64(&DenyNotRecorded, 0, 0);
    Counters->VolumeWideQueries = (UINT64)InterlockedCompareExchange64(&SafeUploadVolumeWideQueries, 0, 0);
    Counters->VolumeWideAnswers = (UINT64)InterlockedCompareExchange64(&SafeUploadVolumeWideAnswers, 0, 0);
    Counters->ImageBase = (UINT64)DenyImageBase;
    DenyAcquire(&irql);
    Counters->NextDenySequence = DenyNext;
    DenyRelease(irql);
}

#endif
