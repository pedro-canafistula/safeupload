/* T5 caller-checked public capability. App-facing proxies, journal RPCs,
 * service-only exports and one-use disposition permits are wired separately.
 * This module never sets disposition, writes data, or changes a public name.
 * See T5-DELETES.md sections 4.1/4.2. */
#include "StagePublic.h"

#if SAFEUPLOAD_STAGING_PROTOTYPE
#define STAGE_PUBLIC_TAG 'pUpS'

struct _SAFEUPLOAD_STAGE_PUBLIC_BACKEND {
    volatile LONG References;
    EX_RUNDOWN_REF Operations;
    volatile LONG Closing;
    KEVENT Closed;
    BOOLEAN Counted;
    PFLT_INSTANCE Instance;
    HANDLE PublicHandle;
    PFILE_OBJECT PublicObject;
    HANDLE RootHandle;
    PFILE_OBJECT RootObject;
    HANDLE ParentHandle;
    PFILE_OBJECT ParentObject;
    SAFEUPLOAD_STAGE_PUBLIC_BINDING Binding;
};

/* ZwQueryObject's documented public ObjectBasicInformation layout. */
typedef struct _STAGE_PUBLIC_OBJECT_BASIC_INFORMATION {
    ULONG Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG HandleCount;
    ULONG PointerCount;
    ULONG Reserved[10];
} STAGE_PUBLIC_OBJECT_BASIC_INFORMATION;

static volatile LONG StagePublicBackendCount;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SafeUploadStagePublicCaptureSubject)
#pragma alloc_text(PAGE, SafeUploadStagePublicOpenBackend)
#pragma alloc_text(PAGE, SafeUploadStagePublicCloseBackend)
#pragma alloc_text(PAGE, SafeUploadStagePublicDereferenceBackend)
#pragma alloc_text(PAGE, SafeUploadStagePublicReleaseOperation)
#endif

NTSTATUS SafeUploadStagePublicCaptureSubject(PFLT_CALLBACK_DATA Data,
    PSECURITY_CLIENT_CONTEXT Subject)
{
    PIO_SECURITY_CONTEXT security;
    PSECURITY_SUBJECT_CONTEXT source;
    SECURITY_QUALITY_OF_SERVICE qos;
    PAGED_CODE();
    if (Subject == NULL) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Subject, sizeof(*Subject));
    if (Data == NULL || Data->Iopb == NULL || Data->Iopb->MajorFunction != IRP_MJ_CREATE)
        return STATUS_INVALID_PARAMETER;
    security = Data->Iopb->Parameters.Create.SecurityContext;
    if (security == NULL || security->AccessState == NULL) return STATUS_ACCESS_DENIED;
    source = &security->AccessState->SubjectSecurityContext;
    if (source->ClientToken == NULL && source->PrimaryToken == NULL) return STATUS_ACCESS_DENIED;
    if (source->ClientToken != NULL && source->ImpersonationLevel < SecurityImpersonation)
        return STATUS_BAD_IMPERSONATION_LEVEL;
    RtlZeroMemory(&qos, sizeof(qos));
    qos.Length = sizeof(qos);
    qos.ImpersonationLevel = source->ClientToken != NULL ? source->ImpersonationLevel : SecurityImpersonation;
    qos.ContextTrackingMode = SECURITY_STATIC_TRACKING;
    /* IO_SECURITY_CONTEXT.SecurityQos is reserved for system use. Preserve
     * the effective subject's enabled rights instead of reading that field
     * or enabling a disabled privilege while copying the token. */
    qos.EffectiveOnly = TRUE;
    /* The original AccessState owns these subject token references. STATIC
     * tracking copies the effective token, including restricted-token state;
     * a later PID/thread-token lookup is neither needed nor authorization.
     * https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/nf-ntifs-secreateclientsecurityfromsubjectcontext */
    return SeCreateClientSecurityFromSubjectContext(source, &qos, FALSE, Subject);
}

static VOID StagePublicCloseObject(PHANDLE Handle, PFILE_OBJECT *FileObject)
{
    PFILE_OBJECT object = *FileObject;
    HANDLE handle = *Handle;
    *FileObject = NULL;
    *Handle = NULL;
    /* The handle still pins the FILE_OBJECT while its extra reference is
     * dropped. Closing it then permits normal NTFS cleanup/last close. */
    if (object != NULL) ObDereferenceObject(object);
    if (handle != NULL) FltClose(handle);
}

VOID SafeUploadStagePublicReferenceBackend(PSAFEUPLOAD_STAGE_PUBLIC_BACKEND Backend)
{
    NT_ASSERT(Backend != NULL && Backend->References > 0);
    InterlockedIncrement(&Backend->References);
}

VOID SafeUploadStagePublicCloseBackend(PSAFEUPLOAD_STAGE_PUBLIC_BACKEND Backend)
{
    PAGED_CODE();
    if (InterlockedCompareExchange(&Backend->Closing, 1, 0) != 0) {
        KeWaitForSingleObject(&Backend->Closed, Executive, KernelMode, FALSE, NULL);
        return;
    }
    /* Local I/O only. Never wait on the service or leave the driver's own
     * public hold preventing the last close which deletion is waiting for. */
    ExWaitForRundownProtectionRelease(&Backend->Operations);
    StagePublicCloseObject(&Backend->PublicHandle, &Backend->PublicObject);
    KeSetEvent(&Backend->Closed, IO_NO_INCREMENT, FALSE);
}

VOID SafeUploadStagePublicDereferenceBackend(PSAFEUPLOAD_STAGE_PUBLIC_BACKEND Backend)
{
    PAGED_CODE();
    if (Backend == NULL || InterlockedDecrement(&Backend->References) != 0) return;
    SafeUploadStagePublicCloseBackend(Backend);
    StagePublicCloseObject(&Backend->ParentHandle, &Backend->ParentObject);
    StagePublicCloseObject(&Backend->RootHandle, &Backend->RootObject);
    if (Backend->Instance != NULL) FltObjectDereference(Backend->Instance);
    if (Backend->Counted) InterlockedDecrement(&StagePublicBackendCount);
    ExFreePoolWithTag(Backend, STAGE_PUBLIC_TAG);
}

BOOLEAN SafeUploadStagePublicAcquireOperation(PSAFEUPLOAD_STAGE_PUBLIC_BACKEND Backend,
    PFLT_INSTANCE *Instance, PFILE_OBJECT *FileObject)
{
    *Instance = NULL;
    *FileObject = NULL;
    SafeUploadStagePublicReferenceBackend(Backend);
    if (!ExAcquireRundownProtection(&Backend->Operations)) {
        InterlockedDecrement(&Backend->References); /* caller's owned reference remains */
        return FALSE;
    }
    if (InterlockedCompareExchange(&Backend->Closing, 0, 0) != 0) {
        ExReleaseRundownProtection(&Backend->Operations);
        InterlockedDecrement(&Backend->References);
        return FALSE;
    }
    *Instance = Backend->Instance;
    *FileObject = Backend->PublicObject;
    return TRUE;
}

VOID SafeUploadStagePublicReleaseOperation(PSAFEUPLOAD_STAGE_PUBLIC_BACKEND Backend)
{
    PAGED_CODE();
    ExReleaseRundownProtection(&Backend->Operations);
    SafeUploadStagePublicDereferenceBackend(Backend);
}

VOID SafeUploadStagePublicGetBinding(PSAFEUPLOAD_STAGE_PUBLIC_BACKEND Backend,
    PSAFEUPLOAD_STAGE_PUBLIC_BINDING Binding)
{
    RtlCopyMemory(Binding, &Backend->Binding, sizeof(*Binding));
}

LONG SafeUploadStagePublicBackendCount(VOID)
{
    return InterlockedCompareExchange(&StagePublicBackendCount, 0, 0);
}

static NTSTATUS StagePublicReadIdentity(PFLT_INSTANCE Instance, PFILE_OBJECT FileObject,
    BOOLEAN Directory, PFILE_ID_INFORMATION Identity, PBOOLEAN CaseSensitive)
{
    FILE_ATTRIBUTE_TAG_INFORMATION tag;
    FILE_CASE_SENSITIVE_INFORMATION caseInfo;
    ULONG returned = 0;
    NTSTATUS status;
    RtlZeroMemory(Identity, sizeof(*Identity));
    if (CaseSensitive != NULL) *CaseSensitive = FALSE;
    status = FltQueryInformationFile(Instance, FileObject, &tag, sizeof(tag), FileAttributeTagInformation, &returned);
    if (!NT_SUCCESS(status)) return status;
    if (returned != sizeof(tag)) return STATUS_INVALID_BUFFER_SIZE;
    if (FlagOn(tag.FileAttributes, FILE_ATTRIBUTE_REPARSE_POINT) ||
        BooleanFlagOn(tag.FileAttributes, FILE_ATTRIBUTE_DIRECTORY) != Directory)
        return STATUS_REPARSE_POINT_ENCOUNTERED;
    status = FltQueryInformationFile(Instance, FileObject, Identity, sizeof(*Identity), FileIdInformation, &returned);
    if (!NT_SUCCESS(status)) return status;
    if (returned != sizeof(*Identity)) return STATUS_INVALID_BUFFER_SIZE;
    {
        static const FILE_ID_128 zeroId = {0};
        if (RtlEqualMemory(&Identity->FileId, &zeroId, sizeof(zeroId))) return STATUS_FILE_INVALID;
    }
    if (Directory && CaseSensitive != NULL) {
        status = FltQueryInformationFile(Instance, FileObject, &caseInfo, sizeof(caseInfo), FileCaseSensitiveInformation, &returned);
        if (!NT_SUCCESS(status)) return status;
        if (returned != sizeof(caseInfo)) return STATUS_INVALID_BUFFER_SIZE;
        if (FlagOn(caseInfo.Flags, ~FILE_CS_FLAG_CASE_SENSITIVE_DIR)) return STATUS_NOT_SUPPORTED;
        *CaseSensitive = BooleanFlagOn(caseInfo.Flags, FILE_CS_FLAG_CASE_SENSITIVE_DIR);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS StagePublicOpenMetadataDirectory(PFLT_INSTANCE Instance,
    HANDLE Root, PUNICODE_STRING Name, BOOLEAN CaseSensitive,
    PHANDLE Handle, PFILE_OBJECT *FileObject)
{
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io = {0};
    NTSTATUS status;
    *Handle = NULL;
    *FileObject = NULL;
    InitializeObjectAttributes(&attributes, Name, OBJ_KERNEL_HANDLE | OBJ_DONT_REPARSE |
        (CaseSensitive ? 0 : OBJ_CASE_INSENSITIVE), Root, NULL);
    /* This metadata-only system open does not grant caller authority. The
     * public capability was independently checked by NTFS first. Metadata
     * anchors may not require new directory-list rights from that caller. */
    status = FltCreateFileEx2(SafeUploadData.Filter, Instance, Handle, FileObject,
        FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY, &attributes, &io, NULL, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT, NULL, 0, IO_STOP_ON_SYMLINK, NULL);
    if (status == STATUS_STOPPED_ON_SYMLINK && io.Information != 0) ExFreePool((PVOID)io.Information);
    return status;
}

static NTSTATUS StagePublicBindAnchoredName(PSAFEUPLOAD_STAGE_PUBLIC_BACKEND Backend,
    PFLT_FILE_NAME_INFORMATION Name)
{
    UNICODE_STRING root = Name->Name;
    UNICODE_STRING component;
    USHORT cursor, end, parentEnd;
    BOOLEAN sensitive = FALSE;
    FILE_ID_INFORMATION parentIdentity;
    PFILE_ID_EXTD_DIR_INFORMATION entry = NULL;
    ULONG returned = 0;
    ULONG bytes = FIELD_OFFSET(FILE_ID_EXTD_DIR_INFORMATION, FileName) + sizeof(Backend->Binding.CanonicalLeaf);
    NTSTATUS status;
    if (Name->Stream.Length != 0 || Name->FinalComponent.Length == 0 ||
        Name->FinalComponent.Length > 255 * sizeof(WCHAR) || Name->Volume.Length == 0 ||
        Name->Volume.Length + sizeof(WCHAR) >= Name->Name.Length ||
        Name->Name.Buffer[Name->Volume.Length / sizeof(WCHAR)] != L'\\')
        return STATUS_OBJECT_PATH_INVALID;
    parentEnd = (Name->Name.Length - Name->FinalComponent.Length) / sizeof(WCHAR);
    if (parentEnd == 0 || Name->Name.Buffer[parentEnd - 1] != L'\\') return STATUS_OBJECT_PATH_INVALID;
    --parentEnd;
    root.Length = Name->Volume.Length + sizeof(WCHAR); /* trailing slash: NTFS root, never a raw-volume open */
    root.MaximumLength = root.Length;
    status = StagePublicOpenMetadataDirectory(Backend->Instance, NULL, &root, FALSE,
        &Backend->RootHandle, &Backend->RootObject);
    if (!NT_SUCCESS(status)) return status;
    status = StagePublicReadIdentity(Backend->Instance, Backend->RootObject, TRUE,
        &Backend->Binding.VolumeRootIdentity, &sensitive);
    if (!NT_SUCCESS(status)) return status;
    Backend->ParentObject = Backend->RootObject;
    ObReferenceObject(Backend->ParentObject);
    parentIdentity = Backend->Binding.VolumeRootIdentity;
    cursor = root.Length / sizeof(WCHAR);
    while (cursor < parentEnd) {
        HANDLE nextHandle = NULL;
        PFILE_OBJECT nextObject = NULL;
        end = cursor;
        while (end < parentEnd && Name->Name.Buffer[end] != L'\\') ++end;
        if (end == cursor) return STATUS_OBJECT_PATH_INVALID;
        component.Buffer = &Name->Name.Buffer[cursor];
        component.Length = (end - cursor) * sizeof(WCHAR);
        component.MaximumLength = component.Length;
        status = StagePublicOpenMetadataDirectory(Backend->Instance,
            Backend->ParentHandle != NULL ? Backend->ParentHandle : Backend->RootHandle,
            &component, sensitive, &nextHandle, &nextObject);
        if (!NT_SUCCESS(status)) return status;
        StagePublicCloseObject(&Backend->ParentHandle, &Backend->ParentObject);
        Backend->ParentHandle = nextHandle;
        Backend->ParentObject = nextObject;
        status = StagePublicReadIdentity(Backend->Instance, nextObject, TRUE, &parentIdentity, &sensitive);
        if (!NT_SUCCESS(status)) return status;
        if (parentIdentity.VolumeSerialNumber != Backend->Binding.VolumeRootIdentity.VolumeSerialNumber)
            return STATUS_NOT_SAME_DEVICE;
        cursor = end + 1;
    }
    Backend->Binding.ParentIdentity = parentIdentity;
    Backend->Binding.ParentCaseSensitive = sensitive;
    entry = ExAllocatePool2(POOL_FLAG_PAGED, bytes, STAGE_PUBLIC_TAG);
    if (entry == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    /* Verify the exact link from the retained parent, not from a second
     * privileged public-file open or a pathname equality guess. The returned
     * native long leaf also unifies short-name aliases in the durable key. */
    status = FltQueryDirectoryFile(Backend->Instance, Backend->ParentObject, entry,
        bytes, FileIdExtdDirectoryInformation, TRUE, &Name->FinalComponent, TRUE, &returned);
    if (NT_SUCCESS(status)) {
        UNICODE_STRING actual;
        ULONG prefix = FIELD_OFFSET(FILE_ID_EXTD_DIR_INFORMATION, FileName);
        if (returned < prefix || returned > bytes || entry->NextEntryOffset != 0 || entry->FileNameLength == 0 ||
            (entry->FileNameLength & 1) != 0 || entry->FileNameLength > returned - prefix ||
            entry->FileNameLength > 255 * sizeof(WCHAR) ||
            FlagOn(entry->FileAttributes, FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) ||
            !RtlEqualMemory(&entry->FileId, &Backend->Binding.PublicIdentity.FileId, sizeof(FILE_ID_128)))
            status = STATUS_FILE_INVALID;
        else {
            actual.Buffer = entry->FileName;
            actual.Length = (USHORT)entry->FileNameLength;
            actual.MaximumLength = actual.Length;
            /* A short alias can differ from the returned long leaf. Identity
             * is the authority; wildcard/stream selectors were never allowed. */
            Backend->Binding.CanonicalLeafBytes = actual.Length;
            RtlCopyMemory(Backend->Binding.CanonicalLeaf, actual.Buffer, actual.Length);
        }
    }
    ExFreePoolWithTag(entry, STAGE_PUBLIC_TAG);
    return status;
}

NTSTATUS SafeUploadStagePublicOpenBackend(PFLT_INSTANCE Instance, PUNICODE_STRING PublicName,
    PSECURITY_CLIENT_CONTEXT Subject, ACCESS_MASK OriginalDesiredAccess, ULONG OriginalShareAccess,
    ULONG OriginalCreateOptions, BOOLEAN CaseSensitiveOpen, PSAFEUPLOAD_STAGE_PUBLIC_BACKEND *Backend)
{
    PSAFEUPLOAD_STAGE_PUBLIC_BACKEND result = NULL;
    PSAFEUPLOAD_INSTANCE_CONTEXT instanceContext = NULL;
    PFLT_FILE_NAME_INFORMATION name = NULL;
    PACCESS_TOKEN oldToken;
    BOOLEAN copyOnOpen, effectiveOnly, impersonating = FALSE;
    SECURITY_IMPERSONATION_LEVEL level;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io = {0};
    STAGE_PUBLIC_OBJECT_BASIC_INFORMATION basic;
    ULONG returned = 0;
    ULONG index;
    NTSTATUS status;
    PAGED_CODE();
    if (Backend == NULL) return STATUS_INVALID_PARAMETER;
    *Backend = NULL;
    if (Instance == NULL || PublicName == NULL || Subject == NULL || Subject->ClientToken == NULL || PublicName->Buffer == NULL ||
        PublicName->Length == 0 || (PublicName->Length & 1) != 0 || PublicName->Length > SAFEUPLOAD_MAX_PATH_BYTES ||
        PublicName->Length > PublicName->MaximumLength ||
        OriginalShareAccess > (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE) ||
        FlagOn(OriginalCreateOptions, 0xff000000 | FILE_DIRECTORY_FILE | FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_BY_FILE_ID) ||
        IoGetTopLevelIrp() != NULL || !PsIsSystemThread(PsGetCurrentThread()))
        return STATUS_INVALID_PARAMETER;
    for (index = 0; index < PublicName->Length / sizeof(WCHAR); ++index) {
        WCHAR ch = PublicName->Buffer[index];
        if (ch == L':' || ch == L'*' || ch == L'?' || ch == L'"' || ch == L'<' || ch == L'>' || ch == L'|' || ch < 32)
            return STATUS_OBJECT_PATH_INVALID;
    }
    oldToken = PsReferenceImpersonationToken(PsGetCurrentThread(), &copyOnOpen, &effectiveOnly, &level);
    if (oldToken != NULL) {
        PsDereferenceImpersonationToken(oldToken);
        return STATUS_INVALID_DEVICE_STATE; /* never discard another operation's effective subject */
    }
    status = FltGetInstanceContext(Instance, (PFLT_CONTEXT *)&instanceContext);
    if (!NT_SUCCESS(status)) return status;
    if (instanceContext->VolumeKind != SafeUploadVolumeFixed || instanceContext->FileSystemType != FLT_FSTYPE_NTFS)
        status = STATUS_NOT_SUPPORTED;
    FltReleaseContext(instanceContext);
    if (!NT_SUCCESS(status)) return status;
    result = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*result), STAGE_PUBLIC_TAG);
    if (result == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    result->References = 1;
    ExInitializeRundownProtection(&result->Operations);
    KeInitializeEvent(&result->Closed, NotificationEvent, FALSE);
    status = FltObjectReference(Instance);
    if (!NT_SUCCESS(status)) goto Exit;
    result->Instance = Instance;
    result->Binding.OriginalDesiredAccess = OriginalDesiredAccess;
    result->Binding.OriginalShareAccess = OriginalShareAccess;
    status = SeImpersonateClientEx(Subject, NULL);
    if (!NT_SUCCESS(status)) goto Exit;
    impersonating = TRUE;
    InitializeObjectAttributes(&attributes, PublicName,
        OBJ_KERNEL_HANDLE | OBJ_FORCE_ACCESS_CHECK | OBJ_DONT_REPARSE |
        (CaseSensitiveOpen ? 0 : OBJ_CASE_INSENSITIVE), NULL, NULL);
    /* Do not truncate/create and do not grant DELETE_ON_CLOSE before the
     * durable handle intent exists. Original access and sharing stay intact;
     * there is no IO_IGNORE_SHARE_ACCESS_CHECK or service-account fallback. */
    status = FltCreateFileEx2(SafeUploadData.Filter, Instance, &result->PublicHandle, &result->PublicObject,
        OriginalDesiredAccess, &attributes, &io, NULL, 0, OriginalShareAccess, FILE_OPEN,
        (OriginalCreateOptions & ~(FILE_DELETE_ON_CLOSE | FILE_OPEN_BY_FILE_ID)) |
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
        NULL, 0, IO_STOP_ON_SYMLINK, NULL);
    if (status == STATUS_STOPPED_ON_SYMLINK && io.Information != 0) ExFreePool((PVOID)io.Information);
    SeStopImpersonatingClient();
    impersonating = FALSE;
    if (!NT_SUCCESS(status)) goto Exit;
    status = ZwQueryObject(result->PublicHandle, ObjectBasicInformation, &basic, sizeof(basic), &returned);
    if (!NT_SUCCESS(status)) goto Exit;
    if (returned != sizeof(basic)) {
        status = STATUS_INVALID_BUFFER_SIZE;
        goto Exit;
    }
    if (!FlagOn(basic.GrantedAccess, DELETE) || !result->PublicObject->DeleteAccess) {
        status = STATUS_ACCESS_DENIED;
        goto Exit;
    }
    result->Binding.GrantedAccess = basic.GrantedAccess;
    status = StagePublicReadIdentity(Instance, result->PublicObject, FALSE, &result->Binding.PublicIdentity, NULL);
    if (!NT_SUCCESS(status)) goto Exit;
    status = FltGetFileNameInformationUnsafe(result->PublicObject, Instance,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY, &name);
    if (!NT_SUCCESS(status)) goto Exit;
    status = FltParseFileNameInformation(name);
    if (!NT_SUCCESS(status)) goto Exit;
    status = StagePublicBindAnchoredName(result, name);
    if (!NT_SUCCESS(status)) goto Exit;
    if (result->Binding.PublicIdentity.VolumeSerialNumber != result->Binding.ParentIdentity.VolumeSerialNumber) {
        status = STATUS_NOT_SAME_DEVICE;
        goto Exit;
    }
    result->Counted = TRUE;
    InterlockedIncrement(&StagePublicBackendCount);
    *Backend = result;
    result = NULL;
Exit:
    if (impersonating) SeStopImpersonatingClient();
    if (name != NULL) FltReleaseFileNameInformation(name);
    SafeUploadStagePublicDereferenceBackend(result);
    return status;
}
#endif
