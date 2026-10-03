/* Passive worker helpers for the observe-only writer-state primitives. */
#include "Stage.h"
#include <ntstrsafe.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SafeUploadStageOpenByIdentity)
#pragma alloc_text(PAGE, SafeUploadStageAdmissionVolumeStatus)
#pragma alloc_text(PAGE, SafeUploadStageVolumeFlags)
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
    /* File IDs identify the file; the pinned section-pointer identity identifies its stream.
     * A future caller passing an ADS must not silently sample the unnamed stream. */
    if (SourceObject->SectionObjectPointer == NULL || object->SectionObjectPointer == NULL ||
        SourceObject->SectionObjectPointer != object->SectionObjectPointer) {
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

NTSTATUS SafeUploadStageVolumeFlags(_In_ PFLT_VOLUME Volume, _Out_ PUINT32 Flags)
{
    PFILTER_VOLUME_STANDARD_INFORMATION information;
    ULONG bytes = sizeof(*information) + SAFEUPLOAD_MAX_PATH_CHARS * sizeof(WCHAR), returned = 0;
    NTSTATUS status;
    PAGED_CODE();
    C_ASSERT(FLTFL_VSI_DETACHED_VOLUME == SAFEUPLOAD_VOLUME_DETACHED_FLAG);
    *Flags = 0;
    information = ExAllocatePool2(POOL_FLAG_PAGED, bytes, SAFEUPLOAD_POOL_TAG);
    if (information == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    status = FltGetVolumeInformation(Volume, FilterVolumeStandardInformation, information, bytes, &returned);
    if (status == STATUS_SUCCESS) {
        if (returned < (ULONG)FIELD_OFFSET(FILTER_VOLUME_STANDARD_INFORMATION, FilterVolumeName) || returned > bytes ||
            (information->FilterVolumeNameLength % sizeof(WCHAR)) != 0 ||
            information->FilterVolumeNameLength > returned - FIELD_OFFSET(FILTER_VOLUME_STANDARD_INFORMATION, FilterVolumeName)) {
            status = STATUS_INFO_LENGTH_MISMATCH;
        } else if ((information->Flags & ~FLTFL_VSI_DETACHED_VOLUME) != 0) {
            status = STATUS_NOT_SUPPORTED;
        } else {
            *Flags = information->Flags;
        }
    }
    ExFreePoolWithTag(information, SAFEUPLOAD_POOL_TAG);
    if (status != STATUS_SUCCESS && NT_SUCCESS(status)) status = STATUS_UNSUCCESSFUL;
    return status;
}

NTSTATUS SafeUploadStageAdmissionVolumeStatus(_Out_ PSAFEUPLOAD_ADMISSION_VOLUME_STATUS Status)
{
    PFLT_INSTANCE instances[SAFEUPLOAD_ADMISSION_VOLUME_MAX_ENTRIES];
    ULONG count = 0, index;
    NTSTATUS status;
    PAGED_CODE();
    RtlZeroMemory(Status, sizeof(*Status));
    Status->StructSize = sizeof(*Status);
    Status->WriterGlobalUnknown = SafeUploadStageWritersGlobalUnknown();
    if (!ExAcquireRundownProtection(&SafeUploadData.ChannelRundown)) return STATUS_FLT_DELETING_OBJECT;
    status = FltEnumerateInstances(NULL, SafeUploadData.Filter, instances,
        RTL_NUMBER_OF(instances), &count);
    if (NT_SUCCESS(status)) {
        Status->EntryCount = count;
        for (index = 0; index < count; ++index) {
            PSAFEUPLOAD_INSTANCE_CONTEXT context = NULL;
            PFLT_VOLUME volume = NULL;
            PSAFEUPLOAD_ADMISSION_VOLUME_ENTRY entry = &Status->Entries[index];
            entry->Instance = (UINT64)(ULONG_PTR)instances[index];
            entry->ContextStatus = (UINT32)FltGetInstanceContext(instances[index], (PFLT_CONTEXT *)&context);
            entry->CanaryStatus = entry->CanaryCleanupStatus = (UINT32)STATUS_PENDING;
            entry->FileSystemStatus = entry->VolumeGuidStatus = entry->ContextStatus;
            entry->InstanceWritersUntracked = 1;
            entry->VolumeInfoStatus = (UINT32)FltGetVolumeFromInstance(instances[index], &volume);
            if (NT_SUCCESS((NTSTATUS)entry->VolumeInfoStatus)) {
                entry->VolumeInfoStatus = (UINT32)SafeUploadStageVolumeFlags(volume, &entry->VolumeFlags);
                FltObjectDereference(volume);
            }
            if (NT_SUCCESS((NTSTATUS)entry->ContextStatus)) {
                entry->VolumeKind = (UINT32)context->VolumeKind;
                entry->FileSystemType = (UINT32)context->FileSystemType;
                entry->FileSystemStatus = (UINT32)context->FileSystemStatus;
                entry->SetupFlags = (UINT32)context->SetupFlags;
                entry->VolumeGuidStatus = (UINT32)context->VolumeGuidStatus;
                entry->VolumeGuidChars = context->VolumeGuidChars;
                RtlCopyMemory(entry->VolumeGuid, context->VolumeGuid, sizeof(entry->VolumeGuid));
                entry->InstanceWritersUntracked = (UINT32)InterlockedCompareExchange(&context->WritersUntracked, 0, 0);
                /* Final state is published last. Pending/Running reports no partial results. */
                entry->CanaryState = (UINT32)InterlockedCompareExchange(&context->CanaryState, 0, 0);
                if (entry->CanaryState >= SAFEUPLOAD_CANARY_PASSED) {
                    entry->CanaryStatus = (UINT32)context->CanaryStatus;
                    entry->CanaryChecks = context->CanaryChecks;
                    entry->CanaryCleanupStatus = (UINT32)context->CanaryCleanupStatus;
                }
                FltReleaseContext(context);
            }
            FltObjectDereference(instances[index]);
        }
    }
    /* Too many instances returns an error rather than partial success. */
    Status->WriterGlobalUnknown |= SafeUploadStageWritersGlobalUnknown();
    ExReleaseRundownProtection(&SafeUploadData.ChannelRundown);
    return status;
}

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
    FILE_ID_INFORMATION identity;
    HANDLE fileHandle = NULL, sectionHandle = NULL;
    PFILE_OBJECT fileObject = NULL;
    LARGE_INTEGER delay;
    UINT32 checks = 0, step = 1;
    ULONG returned = 0;
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
    step = 2;
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
    step = 3;
    status = StageCanarySecurity(&descriptor, &acl.Header, sizeof(acl));
    if (!NT_SUCCESS(status)) goto Exit;
    InitializeObjectAttributes(&attributes, &name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, &descriptor);
    step = 4;
    status = FltCreateFileEx2(SafeUploadData.Filter, Instance, &fileHandle, &fileObject,
        FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | DELETE | SYNCHRONIZE,
        &attributes, &io, NULL, FILE_ATTRIBUTE_TEMPORARY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_CREATE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_COMPLETE_IF_OPLOCKED |
            FILE_DELETE_ON_CLOSE,
        NULL, 0, 0, NULL);
    if (status != STATUS_SUCCESS) goto Exit;
    if (fileObject == NULL || fileHandle == NULL) { status = STATUS_INVALID_HANDLE; goto Exit; }
    if (io.Information != FILE_CREATED) { status = STATUS_DATA_ERROR; goto Exit; }
    eof.EndOfFile.QuadPart = PAGE_SIZE;
    step = 5;
    status = FltSetInformationFile(Instance, fileObject, &eof, sizeof(eof), FileEndOfFileInformation);
    if (!NT_SUCCESS(status)) goto Exit;
    /* The canary owns this newly created lower object for its entire lifetime. Its delete-pending
     * name cannot be reopened; actual S(F) diagnostics use the verified attribute-only ID helper.
     * Here the referenced source object supplies the same NTFS per-stream section-pointer state. */
    step = 6;
    RtlZeroMemory(&identity, sizeof(identity));
    status = FltQueryInformationFile(Instance, fileObject, &identity, sizeof(identity),
        FileIdInformation, &returned);
    if (!NT_SUCCESS(status)) goto Exit;
    if (returned != sizeof(identity)) { status = STATUS_INFO_LENGTH_MISMATCH; goto Exit; }
    if (fileObject->SectionObjectPointer == NULL) { status = STATUS_INVALID_FILE_FOR_SECTION; goto Exit; }
    InitializeObjectAttributes(&attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    step = 8;
    status = ZwCreateSection(&sectionHandle, SECTION_QUERY | SECTION_MAP_READ | SECTION_MAP_WRITE,
        &attributes, NULL, PAGE_READWRITE, SEC_COMMIT, fileHandle);
    if (!NT_SUCCESS(status)) goto Exit;
    /* Retain the section handle without creating a view, the admission-critical case. */
    step = 9;
    if (!MmDoesFileHaveUserWritableReferences(fileObject->SectionObjectPointer)) {
        status = STATUS_NOT_SUPPORTED; goto Exit;
    }
    checks |= SAFEUPLOAD_CANARY_RETAINED_YES;
    ZwClose(sectionHandle); sectionHandle = NULL;
    delay.QuadPart = -100 * 10000LL;
    step = 10;
    for (attempt = 0; attempt < 20; ++attempt) {
        if (!MmDoesFileHaveUserWritableReferences(fileObject->SectionObjectPointer)) {
            checks |= SAFEUPLOAD_CANARY_RELEASED_NO;
            break;
        }
        (VOID)KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }
    status = (checks & SAFEUPLOAD_CANARY_RELEASED_NO) != 0 ? STATUS_SUCCESS : STATUS_IO_TIMEOUT;
Exit:
    if (sectionHandle != NULL) ZwClose(sectionHandle);
    if (fileHandle != NULL) FltClose(fileHandle);
    if (fileObject != NULL) {
        ObDereferenceObject(fileObject);
        cleanupStatus = StageCanaryCheckRemoved(Instance, &name);
        if (NT_SUCCESS(cleanupStatus)) checks |= SAFEUPLOAD_CANARY_REMOVED;
    }
    if (buffer != NULL) ExFreePoolWithTag(buffer, SAFEUPLOAD_POOL_TAG);
    if (volume != NULL) FltObjectDereference(volume);
    Context->CanaryStatus = status;
    Context->CanaryCleanupStatus = cleanupStatus;
    /* Failure phase in bits 8..15: volume/name/security/create/EOF/ID/delete-on-close/section/
     * retained/released. The three low bits remain the individual checks; passed stays exactly 7. */
    Context->CanaryChecks = checks | (status == STATUS_SUCCESS ? 0 : step << 8);
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
        PFLT_VOLUME volume = NULL;
        UINT32 volumeFlags = 0;
        context = NULL;
        if (KeReadStateEvent(&CanaryStop) == 0 &&
            NT_SUCCESS(FltGetInstanceContext(instances[index], (PFLT_CONTEXT *)&context))) {
            if (InterlockedCompareExchange(&context->CanaryState,
                    SAFEUPLOAD_CANARY_RUNNING, SAFEUPLOAD_CANARY_PENDING) == SAFEUPLOAD_CANARY_PENDING) {
                status = FltGetFileSystemType(instances[index], &fs);
                if (context->VolumeKind == SafeUploadVolumeFixed && NT_SUCCESS(status) && fs == FLT_FSTYPE_NTFS) {
                    status = FltGetVolumeFromInstance(instances[index], &volume);
                    if (NT_SUCCESS(status)) status = SafeUploadStageVolumeFlags(volume, &volumeFlags);
                    if (volume != NULL) FltObjectDereference(volume);
                    if (status == STATUS_SUCCESS && !FlagOn(volumeFlags, SAFEUPLOAD_VOLUME_DETACHED_FLAG)) {
                        StageCanaryRun(instances[index], context);
                    } else {
                        context->CanaryStatus = status == STATUS_SUCCESS ? STATUS_VOLUME_DISMOUNTED : status;
                        context->CanaryCleanupStatus = STATUS_SUCCESS;
                        InterlockedExchange(&context->CanaryState, status == STATUS_SUCCESS ?
                            SAFEUPLOAD_CANARY_DETACHED : SAFEUPLOAD_CANARY_FAILED);
                    }
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

static KSTART_ROUTINE StageCanaryWorker;

static VOID StageCanaryWorker(_In_ PVOID Context)
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
        NULL, NULL, StageCanaryWorker, &CanaryStop);
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
