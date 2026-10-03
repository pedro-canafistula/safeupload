/* Passive worker helpers for the observe-only writer-state primitives. */
#include "Stage.h"
#include <ntstrsafe.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SafeUploadStageOpenByIdentity)
#endif

NTSTATUS SafeUploadStageOpenByIdentity(
    _In_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING VolumeName,
    _In_ PFILE_OBJECT SourceObject,
    _Out_ PHANDLE Handle,
    _Outptr_result_nullonfailure_ PFILE_OBJECT *Object,
    _Out_ PUINT32 ProbeStage)
{
    FILE_INTERNAL_INFORMATION internal;
    FILE_ID_INFORMATION expected, actual;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io = {0};
    UNICODE_STRING name;
    PWCHAR buffer = NULL;
    HANDLE handle = NULL;
    PFILE_OBJECT object = NULL;
    ULONG bytes, returned;
    NTSTATUS status;

    PAGED_CODE();
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    *Handle = NULL;
    *Object = NULL;
    *ProbeStage = SAFEUPLOAD_ADMISSION_PROBE_STAGE_IDENTITY_QUERY;
    RtlZeroMemory(&internal, sizeof(internal));
    RtlZeroMemory(&expected, sizeof(expected));
    returned = 0;
    status = FltQueryInformationFile(Instance, SourceObject, &internal, sizeof(internal),
        FileInternalInformation, &returned);
    if (status != STATUS_SUCCESS) goto Exit;
    if (returned != sizeof(internal)) { status = STATUS_INFO_LENGTH_MISMATCH; goto Exit; }
    returned = 0;
    status = FltQueryInformationFile(Instance, SourceObject, &expected, sizeof(expected),
        FileIdInformation, &returned);
    if (status != STATUS_SUCCESS) goto Exit;
    if (returned != sizeof(expected)) { status = STATUS_INFO_LENGTH_MISMATCH; goto Exit; }

    /* Keep SourceObject and its handle alive in the caller until this open is closed. This prevents
     * file-ID reuse while the pathname may be renamed/replaced by another process. */
    bytes = VolumeName->Length + sizeof(WCHAR) + sizeof(internal.IndexNumber);
    if (bytes > MAXUSHORT) { status = STATUS_NAME_TOO_LONG; goto Exit; }
    buffer = ExAllocatePool2(POOL_FLAG_PAGED, bytes, SAFEUPLOAD_POOL_TAG);
    if (buffer == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    RtlCopyMemory(buffer, VolumeName->Buffer, VolumeName->Length);
    buffer[VolumeName->Length / sizeof(WCHAR)] = L'\\';
    RtlCopyMemory((PUCHAR)buffer + VolumeName->Length + sizeof(WCHAR),
        &internal.IndexNumber, sizeof(internal.IndexNumber));
    name.Buffer = buffer;
    name.Length = name.MaximumLength = (USHORT)bytes;
    InitializeObjectAttributes(&attributes, &name, OBJ_KERNEL_HANDLE, NULL, NULL);
    *ProbeStage = SAFEUPLOAD_ADMISSION_PROBE_STAGE_IDENTITY_OPEN;
    status = FltCreateFileEx2(SafeUploadData.Filter, Instance, &handle, &object,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attributes, &io, NULL, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
        FILE_OPEN_BY_FILE_ID | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
            FILE_COMPLETE_IF_OPLOCKED,
        NULL, 0, 0, NULL);
    if (status != STATUS_SUCCESS) goto Exit;
    if (object == NULL || handle == NULL) { status = STATUS_INVALID_HANDLE; goto Exit; }
    *ProbeStage = SAFEUPLOAD_ADMISSION_PROBE_STAGE_IDENTITY_VERIFY;
    RtlZeroMemory(&actual, sizeof(actual));
    returned = 0;
    status = FltQueryInformationFile(Instance, object, &actual, sizeof(actual),
        FileIdInformation, &returned);
    if (status != STATUS_SUCCESS) goto Exit;
    if (returned != sizeof(actual)) { status = STATUS_INFO_LENGTH_MISMATCH; goto Exit; }
    if (actual.VolumeSerialNumber != expected.VolumeSerialNumber ||
        !RtlEqualMemory(&actual.FileId, &expected.FileId, sizeof(actual.FileId))) {
        status = STATUS_FILE_INVALID;
        goto Exit;
    }
    *Handle = handle; handle = NULL;
    *Object = object; object = NULL;
Exit:
    /* Positive completion codes that did not produce a verified open are not successful probes. */
    if (status != STATUS_SUCCESS && NT_SUCCESS(status)) status = STATUS_UNSUCCESSFUL;
    if (object != NULL) ObDereferenceObject(object);
    if (handle != NULL) FltClose(handle);
    if (buffer != NULL) ExFreePoolWithTag(buffer, SAFEUPLOAD_POOL_TAG);
    return status;
}

static volatile LONG AdmissionFilteringReady;
static KEVENT CanaryStop;
static HANDLE CanaryThreadHandle;

VOID SafeUploadStageAdmissionReady(VOID)
{
    InterlockedExchange(&AdmissionFilteringReady, 1);
}

static NTSTATUS StageCanarySecurity(_Out_ SECURITY_DESCRIPTOR *Descriptor, _Out_ PACL Acl,
    _In_ ULONG AclBytes)
{
    NTSTATUS status;
    status = RtlCreateSecurityDescriptor(Descriptor, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status)) return status;
    status = RtlCreateAcl(Acl, AclBytes, ACL_REVISION);
    if (!NT_SUCCESS(status)) return status;
    status = RtlAddAccessAllowedAce(Acl, ACL_REVISION, FILE_ALL_ACCESS, SeExports->SeLocalSystemSid);
    if (!NT_SUCCESS(status)) return status;
    status = RtlSetDaclSecurityDescriptor(Descriptor, TRUE, Acl, FALSE);
    if (!NT_SUCCESS(status)) return status;
    status = RtlSetOwnerSecurityDescriptor(Descriptor, SeExports->SeLocalSystemSid, FALSE);
    if (!NT_SUCCESS(status)) return status;
    status = RtlSetGroupSecurityDescriptor(Descriptor, SeExports->SeLocalSystemSid, FALSE);
    if (!NT_SUCCESS(status)) return status;
    /* This is our private absolute SECURITY_DESCRIPTOR, initialized above. Suppress inherited
     * directory ACEs so the new canary is writable only by the trusted SYSTEM principal. */
    Descriptor->Control |= SE_DACL_PROTECTED;
    return STATUS_SUCCESS;
}

static NTSTATUS StageCanaryCheckRemoved(_In_ PFLT_INSTANCE Instance, _In_ PUNICODE_STRING Name)
{
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io;
    HANDLE handle;
    PFILE_OBJECT object;
    LARGE_INTEGER delay;
    ULONG attempt;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    delay.QuadPart = -100 * 10000LL;
    InitializeObjectAttributes(&attributes, Name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    for (attempt = 0; attempt < 20; ++attempt) {
        RtlZeroMemory(&io, sizeof(io));
        handle = NULL; object = NULL;
        status = FltCreateFileEx2(SafeUploadData.Filter, Instance, &handle, &object,
            FILE_READ_ATTRIBUTES, &attributes, &io, NULL, 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_COMPLETE_IF_OPLOCKED,
            NULL, 0, 0, NULL);
        if (object != NULL) ObDereferenceObject(object);
        if (handle != NULL) FltClose(handle);
        if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND)
            return STATUS_SUCCESS;
        if (status != STATUS_DELETE_PENDING) return NT_SUCCESS(status) ? STATUS_OBJECT_NAME_COLLISION : status;
        (VOID)KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }
    return status;
}

static VOID StageCanaryRun(_In_ PFLT_INSTANCE Instance, _Inout_ PSAFEUPLOAD_INSTANCE_CONTEXT Context)
{
    PFLT_VOLUME volume = NULL;
    UNICODE_STRING volumeName, name;
    PWCHAR buffer = NULL;
    WCHAR suffix[80];
    GUID id;
    SECURITY_DESCRIPTOR descriptor;
    union { ACL Header; UCHAR Bytes[128]; } acl;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io = {0};
    FILE_END_OF_FILE_INFORMATION eof;
    FILE_DISPOSITION_INFORMATION disposition;
    FILE_DISPOSITION_INFORMATION_EX onClose;
    HANDLE fileHandle = NULL, probeHandle = NULL, sectionHandle = NULL;
    PFILE_OBJECT fileObject = NULL, probeObject = NULL;
    LARGE_INTEGER delay;
    UINT32 probeStage, checks = 0;
    ULONG attempt;
    NTSTATUS status, cleanupStatus = STATUS_SUCCESS;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    status = FltGetVolumeFromInstance(Instance, &volume);
    if (!NT_SUCCESS(status)) goto Exit;
    buffer = ExAllocatePool2(POOL_FLAG_PAGED, SAFEUPLOAD_MAX_PATH_CHARS * sizeof(WCHAR), SAFEUPLOAD_POOL_TAG);
    if (buffer == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    volumeName.Buffer = buffer;
    volumeName.Length = 0;
    volumeName.MaximumLength = (USHORT)(SAFEUPLOAD_MAX_PATH_CHARS * sizeof(WCHAR));
    status = FltGetVolumeName(volume, &volumeName, NULL);
    if (!NT_SUCCESS(status)) goto Exit;
    status = ExUuidCreate(&id);
    if (!NT_SUCCESS(status)) goto Exit;
    status = RtlStringCchPrintfW(suffix, RTL_NUMBER_OF(suffix),
        L"\\SafeUpload-canary-%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X.tmp",
        id.Data1, id.Data2, id.Data3, id.Data4[0], id.Data4[1], id.Data4[2], id.Data4[3],
        id.Data4[4], id.Data4[5], id.Data4[6], id.Data4[7]);
    if (!NT_SUCCESS(status)) goto Exit;
    name = volumeName;
    status = RtlAppendUnicodeToString(&name, suffix);
    if (!NT_SUCCESS(status)) goto Exit;
    status = StageCanarySecurity(&descriptor, &acl.Header, sizeof(acl));
    if (!NT_SUCCESS(status)) goto Exit;
    InitializeObjectAttributes(&attributes, &name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, &descriptor);
    status = FltCreateFileEx2(SafeUploadData.Filter, Instance, &fileHandle, &fileObject,
        FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | DELETE | SYNCHRONIZE,
        &attributes, &io, NULL, FILE_ATTRIBUTE_TEMPORARY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_CREATE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_COMPLETE_IF_OPLOCKED,
        NULL, 0, 0, NULL);
    if (status != STATUS_SUCCESS) goto Exit;
    if (fileObject == NULL || fileHandle == NULL) { status = STATUS_INVALID_HANDLE; goto Exit; }
    eof.EndOfFile.QuadPart = PAGE_SIZE;
    status = FltSetInformationFile(Instance, fileObject, &eof, sizeof(eof), FileEndOfFileInformation);
    if (!NT_SUCCESS(status)) goto Exit;
    /* An attribute-only ID reopen samples the same stream even if its name changes. */
    status = SafeUploadStageOpenByIdentity(Instance, &volumeName, fileObject,
        &probeHandle, &probeObject, &probeStage);
    if (!NT_SUCCESS(status)) goto Exit;
    if (probeObject->SectionObjectPointer == NULL) { status = STATUS_INVALID_FILE_FOR_SECTION; goto Exit; }
    /* Arm deletion only after the ID reopen: NTFS rejects new opens of a delete-pending file.
     * Closing our source handle then remains a cleanup fallback even if the explicit delete fails. */
    onClose.Flags = FILE_DISPOSITION_DELETE | FILE_DISPOSITION_ON_CLOSE;
    status = FltSetInformationFile(Instance, fileObject, &onClose, sizeof(onClose), FileDispositionInformationEx);
    if (!NT_SUCCESS(status)) goto Exit;
    InitializeObjectAttributes(&attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwCreateSection(&sectionHandle, SECTION_QUERY | SECTION_MAP_READ | SECTION_MAP_WRITE,
        &attributes, NULL, PAGE_READWRITE, SEC_COMMIT, fileHandle);
    if (!NT_SUCCESS(status)) goto Exit;
    /* Retain the section handle without creating a view, the admission-critical case. */
    if (!MmDoesFileHaveUserWritableReferences(probeObject->SectionObjectPointer)) {
        status = STATUS_NOT_SUPPORTED; goto Exit;
    }
    checks |= SAFEUPLOAD_CANARY_RETAINED_YES;
    ZwClose(sectionHandle); sectionHandle = NULL;
    delay.QuadPart = -100 * 10000LL;
    for (attempt = 0; attempt < 20; ++attempt) {
        if (!MmDoesFileHaveUserWritableReferences(probeObject->SectionObjectPointer)) {
            checks |= SAFEUPLOAD_CANARY_RELEASED_NO;
            break;
        }
        (VOID)KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }
    status = (checks & SAFEUPLOAD_CANARY_RELEASED_NO) != 0 ? STATUS_SUCCESS : STATUS_IO_TIMEOUT;
Exit:
    if (sectionHandle != NULL) ZwClose(sectionHandle);
    if (probeHandle != NULL) FltClose(probeHandle);
    if (probeObject != NULL) ObDereferenceObject(probeObject);
    if (fileObject != NULL) {
        disposition.DeleteFile = TRUE;
        cleanupStatus = FltSetInformationFile(Instance, fileObject, &disposition,
            sizeof(disposition), FileDispositionInformation);
    }
    if (fileHandle != NULL) FltClose(fileHandle);
    if (fileObject != NULL) {
        ObDereferenceObject(fileObject);
        if (NT_SUCCESS(cleanupStatus)) cleanupStatus = StageCanaryCheckRemoved(Instance, &name);
        if (NT_SUCCESS(cleanupStatus)) checks |= SAFEUPLOAD_CANARY_REMOVED;
    }
    if (buffer != NULL) ExFreePoolWithTag(buffer, SAFEUPLOAD_POOL_TAG);
    if (volume != NULL) FltObjectDereference(volume);
    Context->CanaryStatus = status;
    Context->CanaryCleanupStatus = cleanupStatus;
    Context->CanaryChecks = checks;
    /* Published last; consumers must treat Pending/Running/Failed/Unsupported as untrusted. */
    InterlockedExchange(&Context->CanaryState,
        status == STATUS_SUCCESS && cleanupStatus == STATUS_SUCCESS && checks == 7 ?
            SAFEUPLOAD_CANARY_PASSED : SAFEUPLOAD_CANARY_FAILED);
}

VOID SafeUploadStageCanaryTick(VOID)
{
    PFLT_INSTANCE instances[64];
    PSAFEUPLOAD_INSTANCE_CONTEXT context;
    FLT_FILESYSTEM_TYPE fs;
    ULONG count = 0, index;
    NTSTATUS status;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (InterlockedCompareExchange(&AdmissionFilteringReady, 0, 0) == 0) return;
    /* Called only by the separate, joined canary worker. InstanceSetup never waits or issues
     * canary I/O. Unload joins this worker before FltUnregisterFilter; all references drop here. */
    status = FltEnumerateInstances(NULL, SafeUploadData.Filter, instances,
        RTL_NUMBER_OF(instances), &count);
    if (!NT_SUCCESS(status)) return; /* Unvisited instances stay Pending, never trusted. */
    for (index = 0; index < count; ++index) {
        context = NULL;
        if (KeReadStateEvent(&CanaryStop) == 0 &&
            NT_SUCCESS(FltGetInstanceContext(instances[index], (PFLT_CONTEXT *)&context))) {
            if (InterlockedCompareExchange(&context->CanaryState,
                    SAFEUPLOAD_CANARY_RUNNING, SAFEUPLOAD_CANARY_PENDING) == SAFEUPLOAD_CANARY_PENDING) {
                status = FltGetFileSystemType(instances[index], &fs);
                if (context->VolumeKind == SafeUploadVolumeFixed && NT_SUCCESS(status) && fs == FLT_FSTYPE_NTFS) {
                    StageCanaryRun(instances[index], context);
                } else {
                    context->CanaryStatus = NT_SUCCESS(status) ? STATUS_NOT_SUPPORTED : status;
                    context->CanaryCleanupStatus = STATUS_SUCCESS;
                    InterlockedExchange(&context->CanaryState, SAFEUPLOAD_CANARY_UNSUPPORTED);
                }
            }
            FltReleaseContext(context);
        }
        FltObjectDereference(instances[index]);
    }
}

static VOID StageCanaryWorker(_In_opt_ PVOID Context)
{
    LARGE_INTEGER interval;
    UNREFERENCED_PARAMETER(Context);
    interval.QuadPart = -250 * 10000LL;
    while (KeWaitForSingleObject(&CanaryStop, Executive, KernelMode, FALSE, &interval) == STATUS_TIMEOUT)
        SafeUploadStageCanaryTick();
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS SafeUploadStageAdmissionStartWorker(VOID)
{
    OBJECT_ATTRIBUTES attributes;
    KeInitializeEvent(&CanaryStop, NotificationEvent, FALSE);
    InitializeObjectAttributes(&attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    return PsCreateSystemThread(&CanaryThreadHandle, SYNCHRONIZE, &attributes,
        NULL, NULL, StageCanaryWorker, NULL);
}

VOID SafeUploadStageAdmissionStopWorker(VOID)
{
    if (CanaryThreadHandle != NULL) {
        KeSetEvent(&CanaryStop, IO_NO_INCREMENT, FALSE);
        (VOID)ZwWaitForSingleObject(CanaryThreadHandle, FALSE, NULL);
        ZwClose(CanaryThreadHandle);
        CanaryThreadHandle = NULL;
    }
}
