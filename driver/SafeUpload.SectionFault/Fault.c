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
    client = FaultClient; FaultClient = NULL;
    KeReleaseMutex(&FaultControl, FALSE);
    FltCloseClientPort(FaultFilter, &client);
    if (Cookie != NULL) ObDereferenceObject(Cookie);
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
    return STATUS_SUCCESS;
}

static VOID FaultTeardown(_In_ PCFLT_RELATED_OBJECTS Objects, _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Objects); UNREFERENCED_PARAMETER(Flags);
    FaultDisarm();
}

static NTSTATUS FaultUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    FltCloseCommunicationPort(FaultServer); FaultServer = NULL;
    KeWaitForSingleObject(&FaultControl, Executive, KernelMode, FALSE, NULL);
    FaultStopping = TRUE;
    FaultDisarmLocked();
    KeReleaseMutex(&FaultControl, FALSE);
    FltUnregisterFilter(FaultFilter);
    return STATUS_SUCCESS;
}

static CONST FLT_OPERATION_REGISTRATION FaultOperations[] = {
    {IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION, 0, FaultPreSection, NULL}, {IRP_MJ_OPERATION_END}
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
        KeReleaseMutex(&FaultControl, FALSE);
        FltUnregisterFilter(FaultFilter);
    }
    return status;
}
