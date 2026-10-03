/* Passive worker helpers for the observe-only writer-state primitives. */
#include "Stage.h"

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
