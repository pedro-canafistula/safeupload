/*
 * SafeUpload gate minifilter.
 *
 * One job: only the SafeUpload agent may write to protected places. Users reach those places through the agent's
 * SafeUpload drives, where every file is inspected before the agent copies it in. The driver refuses, for every other
 * user-mode process:
 *   - opens with write intent (write/append/attributes/EA/delete/ACL rights, create or overwrite, delete-on-close)
 *     under a protected folder, or anywhere on a removable or network volume when the policy says so;
 *   - renames and hard links whose target is in such a place.
 * The agent is the process holding the driver's communication port. Before the first policy arrives nothing is
 * refused; once a policy is set it stays until unload, so if the agent dies its places stay closed (fail closed).
 * Reads are never refused. There is no content inspection, staging or process tracking in the kernel.
 */
#include <fltKernel.h>
#include "GateProtocol.h"

#define GATE_TAG 'tGuS'

#define GATE_WRITE_ACCESS (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE | \
                           WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL)

typedef struct _GATE_POLICY {
    ULONG Flags;
    ULONG Count;
    UNICODE_STRING Paths[SAFEUPLOAD_GATE_MAX_PATHS];
    WCHAR Buffers[SAFEUPLOAD_GATE_MAX_PATHS][SAFEUPLOAD_GATE_MAX_PATH_CHARS];
} GATE_POLICY, *PGATE_POLICY;

typedef struct _GATE_INSTANCE_CONTEXT {
    BOOLEAN Removable;
    BOOLEAN Network;
    UNICODE_STRING VolumeName;      /* \Device\HarddiskVolume3 */
} GATE_INSTANCE_CONTEXT, *PGATE_INSTANCE_CONTEXT;

static struct {
    PFLT_FILTER Filter;
    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort;
    PVOID AgentProcessId;           /* HANDLE of the connected agent, NULL when none */
    EX_PUSH_LOCK PolicyLock;
    PGATE_POLICY Policy;
    volatile LONG64 Refused;
    volatile LONG64 RenamesRefused;
} Gate;

DRIVER_INITIALIZE DriverEntry;

static NTSTATUS GateUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
static NTSTATUS GateInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);
static NTSTATUS GateInstanceQueryTeardown(_In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);
static VOID GateInstanceContextCleanup(_In_ PFLT_CONTEXT Context, _In_ FLT_CONTEXT_TYPE ContextType);
static FLT_PREOP_CALLBACK_STATUS GatePreCreate(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);
static FLT_POSTOP_CALLBACK_STATUS GatePostCreate(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);
static FLT_PREOP_CALLBACK_STATUS GatePreSetInformation(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);
static NTSTATUS GateConnect(_In_ PFLT_PORT ClientPort, _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext, _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie);
static VOID GateDisconnect(_In_opt_ PVOID ConnectionCookie);
static NTSTATUS GateMessage(_In_opt_ PVOID PortCookie, _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength, _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength, _Out_ PULONG ReturnOutputBufferLength);

static const FLT_OPERATION_REGISTRATION GateCallbacks[] = {
    { IRP_MJ_CREATE, 0, GatePreCreate, GatePostCreate },
    { IRP_MJ_SET_INFORMATION, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, GatePreSetInformation, NULL },
    { IRP_MJ_OPERATION_END }
};

static const FLT_CONTEXT_REGISTRATION GateContexts[] = {
    { FLT_INSTANCE_CONTEXT, 0, GateInstanceContextCleanup, sizeof(GATE_INSTANCE_CONTEXT), GATE_TAG },
    { FLT_CONTEXT_END }
};

static const FLT_REGISTRATION GateRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    GateContexts,
    GateCallbacks,
    GateUnload,
    GateInstanceSetup,
    GateInstanceQueryTeardown,
    NULL, NULL, NULL, NULL, NULL
};

/* ------------------------------------------------------------------------------------------------ helpers */

static BOOLEAN
GateHasPolicy(VOID)
{
    return InterlockedCompareExchangePointer((PVOID volatile *)&Gate.Policy, NULL, NULL) != NULL;
}

static BOOLEAN
GateIsAgent(_In_ PFLT_CALLBACK_DATA Data)
{
    PVOID agent = InterlockedCompareExchangePointer(&Gate.AgentProcessId, NULL, NULL);
    return agent != NULL && (ULONG_PTR)agent == (ULONG_PTR)FltGetRequestorProcessId(Data);
}

/* Write intent of a create; MAXIMUM_ALLOWED is reported separately. */
static BOOLEAN
GateCreateWrites(_In_ PFLT_CALLBACK_DATA Data, _Out_ PBOOLEAN MaximumAllowed)
{
    ACCESS_MASK access = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    ULONG disposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;
    ULONG options = Data->Iopb->Parameters.Create.Options & 0x00FFFFFF;

    *MaximumAllowed = BooleanFlagOn(access, MAXIMUM_ALLOWED);
    return FlagOn(access, GATE_WRITE_ACCESS) || disposition != FILE_OPEN || FlagOn(options, FILE_DELETE_ON_CLOSE);
}

static BOOLEAN
GateUnder(_In_ PCUNICODE_STRING Prefix, _In_ PCUNICODE_STRING Name)
{
    if (Prefix->Length == 0 || Name->Length < Prefix->Length || !RtlPrefixUnicodeString(Prefix, Name, TRUE)) {
        return FALSE;
    }
    return Name->Length == Prefix->Length || Name->Buffer[Prefix->Length / sizeof(WCHAR)] == L'\\';
}

/* Caller holds the policy lock. */
static BOOLEAN
GatePathProtected(_In_ PGATE_POLICY Policy, _In_ PCUNICODE_STRING Name)
{
    for (ULONG i = 0; i < Policy->Count; i++) {
        if (GateUnder(&Policy->Paths[i], Name)) {
            return TRUE;
        }
    }
    return FALSE;
}

/* Caller holds the policy lock. True when some protected folder is on this volume. */
static BOOLEAN
GateVolumeHasPaths(_In_ PGATE_POLICY Policy, _In_ PCUNICODE_STRING Volume)
{
    for (ULONG i = 0; i < Policy->Count; i++) {
        if (GateUnder(Volume, &Policy->Paths[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * Decides whether a write-capable access by a non-agent process is refused. NameInfo is the target's normalized
 * name when the caller already has it (renames), otherwise it is queried for the create in Data.
 */
static BOOLEAN
GateRefuses(_In_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ BOOLEAN Writes,
    _In_ BOOLEAN MaximumAllowed, _In_opt_ PFLT_FILE_NAME_INFORMATION NameInfo)
{
    PGATE_INSTANCE_CONTEXT context = NULL;
    PFLT_FILE_NAME_INFORMATION queried = NULL;
    BOOLEAN refuse = FALSE;
    BOOLEAN checkName = FALSE;

    if (!NT_SUCCESS(FltGetInstanceContext(FltObjects->Instance, (PFLT_CONTEXT *)&context))) {
        return FALSE;
    }

    FltAcquirePushLockShared(&Gate.PolicyLock);
    if (Gate.Policy != NULL) {
        /* Volumes without ACLs (FAT sticks) can grant write access to MAXIMUM_ALLOWED: count it as a write there. */
        if (context->Removable && FlagOn(Gate.Policy->Flags, SAFEUPLOAD_GATE_FLAG_REMOVABLE) && (Writes || MaximumAllowed)) {
            refuse = TRUE;
        } else if (context->Network && FlagOn(Gate.Policy->Flags, SAFEUPLOAD_GATE_FLAG_NETWORK) && (Writes || MaximumAllowed)) {
            refuse = TRUE;
        } else if (Writes && context->VolumeName.Length != 0 && GateVolumeHasPaths(Gate.Policy, &context->VolumeName)) {
            checkName = TRUE;
        }
    }
    FltReleasePushLock(&Gate.PolicyLock);

    if (checkName) {
        if (NameInfo == NULL &&
            NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &queried))) {
            NameInfo = queried;
        }
        if (NameInfo != NULL) {
            FltAcquirePushLockShared(&Gate.PolicyLock);
            refuse = Gate.Policy != NULL && GatePathProtected(Gate.Policy, &NameInfo->Name);
            FltReleasePushLock(&Gate.PolicyLock);
        }
        if (queried != NULL) {
            FltReleaseFileNameInformation(queried);
        }
    }

    FltReleaseContext(context);
    return refuse;
}

/* ------------------------------------------------------------------------------------------------ operations */

static FLT_PREOP_CALLBACK_STATUS
GatePreCreate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    PFILE_OBJECT fileObject = FltObjects->FileObject;
    BOOLEAN maximumAllowed;
    BOOLEAN writes;

    *CompletionContext = NULL;
    if (Data->RequestorMode == KernelMode || FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE) ||
        fileObject == NULL || (fileObject->FileName.Length == 0 && fileObject->RelatedFileObject == NULL) ||
        !GateHasPolicy() || GateIsAgent(Data)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    writes = GateCreateWrites(Data, &maximumAllowed);
    if (!writes && !maximumAllowed) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* An open by file ID has no usable name before the file system resolves it: decide after the open. */
    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_OPEN_BY_FILE_ID)) {
        *CompletionContext = (PVOID)1;
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    if (GateRefuses(Data, FltObjects, writes, maximumAllowed, NULL)) {
        InterlockedIncrement64(&Gate.Refused);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_POSTOP_CALLBACK_STATUS
GatePostCreate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    BOOLEAN maximumAllowed;
    BOOLEAN writes;

    if (CompletionContext == NULL || FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) ||
        !NT_SUCCESS(Data->IoStatus.Status) || Data->IoStatus.Status == STATUS_REPARSE) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    writes = GateCreateWrites(Data, &maximumAllowed);
    if (GateRefuses(Data, FltObjects, writes, maximumAllowed, NULL)) {
        FltCancelFileOpen(FltObjects->Instance, FltObjects->FileObject);
        InterlockedIncrement64(&Gate.Refused);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static FLT_PREOP_CALLBACK_STATUS
GatePreSetInformation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    FILE_INFORMATION_CLASS infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    PFILE_RENAME_INFORMATION info;
    PFLT_FILE_NAME_INFORMATION target = NULL;
    BOOLEAN refuse;

    *CompletionContext = NULL;
    if (infoClass != FileRenameInformation && infoClass != FileRenameInformationEx &&
        infoClass != FileLinkInformation && infoClass != FileLinkInformationEx) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (Data->RequestorMode == KernelMode || !GateHasPolicy() || GateIsAgent(Data)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* FILE_LINK_INFORMATION has the same layout as FILE_RENAME_INFORMATION. */
    info = (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    if (!NT_SUCCESS(FltGetDestinationFileNameInformation(FltObjects->Instance, FltObjects->FileObject,
            info->RootDirectory, info->FileName, info->FileNameLength,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &target))) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* A rename stays on its volume: the volume flags apply to the target as well. */
    refuse = GateRefuses(Data, FltObjects, TRUE, FALSE, target);
    FltReleaseFileNameInformation(target);
    if (refuse) {
        InterlockedIncrement64(&Gate.RenamesRefused);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* ------------------------------------------------------------------------------------------------ instances */

static NTSTATUS
GateInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    PGATE_INSTANCE_CONTEXT context = NULL;
    UCHAR propertiesBuffer[sizeof(FLT_VOLUME_PROPERTIES) + 256];
    PFLT_VOLUME_PROPERTIES properties = (PFLT_VOLUME_PROPERTIES)propertiesBuffer;
    UNICODE_STRING empty = { 0 };
    ULONG length = 0;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Flags);
    if (VolumeFilesystemType == FLT_FSTYPE_RAW) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    status = FltAllocateContext(Gate.Filter, FLT_INSTANCE_CONTEXT, sizeof(GATE_INSTANCE_CONTEXT), PagedPool,
        (PFLT_CONTEXT *)&context);
    if (!NT_SUCCESS(status)) {
        return STATUS_SUCCESS;  /* attach without context: nothing on this volume is refused */
    }
    RtlZeroMemory(context, sizeof(GATE_INSTANCE_CONTEXT));
    context->Network = (VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM);

    status = FltGetVolumeProperties(FltObjects->Volume, properties, sizeof(propertiesBuffer), &length);
    if (NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW) {
        context->Removable = BooleanFlagOn(properties->DeviceCharacteristics, FILE_REMOVABLE_MEDIA);
    }

    status = FltGetVolumeName(FltObjects->Volume, &empty, &length);
    if (status == STATUS_BUFFER_TOO_SMALL && length > 0 && length <= MAXUSHORT) {
        context->VolumeName.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_PAGED, length, GATE_TAG);
        if (context->VolumeName.Buffer != NULL) {
            context->VolumeName.MaximumLength = (USHORT)length;
            if (!NT_SUCCESS(FltGetVolumeName(FltObjects->Volume, &context->VolumeName, NULL))) {
                ExFreePoolWithTag(context->VolumeName.Buffer, GATE_TAG);
                RtlZeroMemory(&context->VolumeName, sizeof(UNICODE_STRING));
            }
        }
    }

    (VOID)FltSetInstanceContext(FltObjects->Instance, FLT_SET_CONTEXT_KEEP_IF_EXISTS, context, NULL);
    FltReleaseContext(context);
    return STATUS_SUCCESS;
}

static NTSTATUS
GateInstanceQueryTeardown(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

static VOID
GateInstanceContextCleanup(_In_ PFLT_CONTEXT Context, _In_ FLT_CONTEXT_TYPE ContextType)
{
    PGATE_INSTANCE_CONTEXT context = (PGATE_INSTANCE_CONTEXT)Context;

    UNREFERENCED_PARAMETER(ContextType);
    if (context->VolumeName.Buffer != NULL) {
        ExFreePoolWithTag(context->VolumeName.Buffer, GATE_TAG);
    }
}

/* ------------------------------------------------------------------------------------------------ agent port */

static NTSTATUS
GateConnect(_In_ PFLT_PORT ClientPort, _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext, _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    /* The port accepts one connection and only SYSTEM and administrators may open it. */
    Gate.ClientPort = ClientPort;
    InterlockedExchangePointer(&Gate.AgentProcessId, PsGetCurrentProcessId());
    *ConnectionPortCookie = NULL;
    return STATUS_SUCCESS;
}

static VOID
GateDisconnect(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    /* The policy stays: without the agent nobody may write to the protected places. */
    InterlockedExchangePointer(&Gate.AgentProcessId, NULL);
    FltCloseClientPort(Gate.Filter, &Gate.ClientPort);
}

static NTSTATUS
GateSetPolicy(_In_reads_bytes_(Length) PVOID Buffer, _In_ ULONG Length)
{
    SAFEUPLOAD_GATE_POLICY *message;
    PGATE_POLICY policy;
    PGATE_POLICY previous;
    NTSTATUS status = STATUS_SUCCESS;

    if (Length != sizeof(SAFEUPLOAD_GATE_POLICY)) {
        return STATUS_INVALID_PARAMETER;
    }
    message = (SAFEUPLOAD_GATE_POLICY *)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(SAFEUPLOAD_GATE_POLICY), GATE_TAG);
    policy = (PGATE_POLICY)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(GATE_POLICY), GATE_TAG);
    if (message == NULL || policy == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Done;
    }

    __try {
        ProbeForRead(Buffer, Length, sizeof(ULONG));
        RtlCopyMemory(message, Buffer, sizeof(SAFEUPLOAD_GATE_POLICY));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        goto Done;
    }

    if (message->PathCount > SAFEUPLOAD_GATE_MAX_PATHS ||
        (message->Flags & ~(SAFEUPLOAD_GATE_FLAG_REMOVABLE | SAFEUPLOAD_GATE_FLAG_NETWORK)) != 0) {
        status = STATUS_INVALID_PARAMETER;
        goto Done;
    }
    policy->Flags = message->Flags;
    for (ULONG i = 0; i < message->PathCount; i++) {
        SIZE_T chars = 0;
        while (chars < SAFEUPLOAD_GATE_MAX_PATH_CHARS && message->Paths[i][chars] != L'\0') {
            chars++;
        }
        while (chars > 0 && message->Paths[i][chars - 1] == L'\\') {
            chars--;
        }
        if (chars == 0 || chars >= SAFEUPLOAD_GATE_MAX_PATH_CHARS || message->Paths[i][0] != L'\\') {
            status = STATUS_INVALID_PARAMETER;
            goto Done;
        }
        RtlCopyMemory(policy->Buffers[i], message->Paths[i], chars * sizeof(WCHAR));
        policy->Paths[i].Buffer = policy->Buffers[i];
        policy->Paths[i].Length = (USHORT)(chars * sizeof(WCHAR));
        policy->Paths[i].MaximumLength = (USHORT)(SAFEUPLOAD_GATE_MAX_PATH_CHARS * sizeof(WCHAR));
        policy->Count++;
    }

    FltAcquirePushLockExclusive(&Gate.PolicyLock);
    previous = Gate.Policy;
    Gate.Policy = policy;
    FltReleasePushLock(&Gate.PolicyLock);
    policy = previous;      /* freed below */

Done:
    if (message != NULL) {
        ExFreePoolWithTag(message, GATE_TAG);
    }
    if (policy != NULL) {
        ExFreePoolWithTag(policy, GATE_TAG);
    }
    return status;
}

static NTSTATUS
GateMessage(_In_opt_ PVOID PortCookie, _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength, _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength, _Out_ PULONG ReturnOutputBufferLength)
{
    SAFEUPLOAD_GATE_HEADER header;
    SAFEUPLOAD_GATE_COUNTERS counters;

    UNREFERENCED_PARAMETER(PortCookie);
    *ReturnOutputBufferLength = 0;
    if (InputBuffer == NULL || InputBufferLength < sizeof(SAFEUPLOAD_GATE_HEADER)) {
        return STATUS_INVALID_PARAMETER;
    }

    /* The buffers belong to the calling (user-mode) agent. */
    __try {
        ProbeForRead(InputBuffer, sizeof(header), sizeof(ULONG));
        RtlCopyMemory(&header, InputBuffer, sizeof(header));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    if (header.Version != SAFEUPLOAD_GATE_VERSION) {
        return STATUS_REVISION_MISMATCH;
    }

    switch (header.Command) {
    case SafeUploadGateSetPolicy:
        return GateSetPolicy(InputBuffer, InputBufferLength);

    case SafeUploadGateGetCounters:
        if (OutputBuffer == NULL || OutputBufferLength < sizeof(counters)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        counters.Refused = (ULONGLONG)Gate.Refused;
        counters.RenamesRefused = (ULONGLONG)Gate.RenamesRefused;
        __try {
            ProbeForWrite(OutputBuffer, sizeof(counters), sizeof(ULONG));
            RtlCopyMemory(OutputBuffer, &counters, sizeof(counters));
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
        *ReturnOutputBufferLength = sizeof(counters);
        return STATUS_SUCCESS;

    default:
        return STATUS_INVALID_PARAMETER;
    }
}

/* ------------------------------------------------------------------------------------------------ load / unload */

static NTSTATUS
GateCreatePort(VOID)
{
    PSECURITY_DESCRIPTOR descriptor = NULL;
    UNICODE_STRING name = RTL_CONSTANT_STRING(SAFEUPLOAD_GATE_PORT_NAME);
    OBJECT_ATTRIBUTES attributes;
    NTSTATUS status;

    status = FltBuildDefaultSecurityDescriptor(&descriptor, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, descriptor);
    status = FltCreateCommunicationPort(Gate.Filter, &Gate.ServerPort, &attributes, NULL,
        GateConnect, GateDisconnect, GateMessage, 1);
    FltFreeSecurityDescriptor(descriptor);
    return status;
}

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);
    RtlZeroMemory(&Gate, sizeof(Gate));
    FltInitializePushLock(&Gate.PolicyLock);

    status = FltRegisterFilter(DriverObject, &GateRegistration, &Gate.Filter);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = GateCreatePort();
    if (NT_SUCCESS(status)) {
        status = FltStartFiltering(Gate.Filter);
    }
    if (!NT_SUCCESS(status)) {
        if (Gate.ServerPort != NULL) {
            FltCloseCommunicationPort(Gate.ServerPort);
        }
        FltUnregisterFilter(Gate.Filter);
    }
    return status;
}

static NTSTATUS
GateUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    FltCloseCommunicationPort(Gate.ServerPort);
    FltUnregisterFilter(Gate.Filter);   /* waits for every callback to finish */
    if (Gate.Policy != NULL) {
        ExFreePoolWithTag(Gate.Policy, GATE_TAG);
        Gate.Policy = NULL;
    }
    FltDeletePushLock(&Gate.PolicyLock);
    return STATUS_SUCCESS;
}
