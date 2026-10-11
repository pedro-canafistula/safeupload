/* Authenticated, read-only name observation. Local directory opens exist
 * only during this callback; no child open or mutation authority is returned. */
#include "StageNativeRecords.h"
#include "StageNativeWire.h"
#include "Stage.h"

#if SAFEUPLOAD_STAGING_PROTOTYPE
#define NATIVE_OBSERVATION_TAG 'oUpS'
#define NATIVE_OBSERVATION_BYTES (64UL * 1024)
#define NATIVE_OBSERVATION_PAGES 64UL
#define NATIVE_OBSERVATION_INSTANCES SAFEUPLOAD_ADMISSION_COVERAGE_MAX_INSTANCES

typedef struct _NATIVE_OBSERVATION_WORK {
    SAFEUPLOAD_NATIVE_NAME_REPLY Reply;
    SAFEUPLOAD_STAGE_NATIVE_SNAPSHOT RevisionProbe;
    PFLT_INSTANCE Instances[NATIVE_OBSERVATION_INSTANCES];
    PFLT_INSTANCE Instance; /* borrowed from Instances, not another reference */
    HANDLE RootHandle, ParentHandle;
    PFILE_OBJECT RootObject, ParentObject;
    UINT64 Topology, Coverage;
    UCHAR Directory[NATIVE_OBSERVATION_BYTES];
} NATIVE_OBSERVATION_WORK, *PNATIVE_OBSERVATION_WORK;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SafeUploadStageNativeNameControl)
#endif

static BOOLEAN NativeObservationIdentityValid(const SAFEUPLOAD_STAGE_IDENTITY_V19 *Identity)
{
    static const FILE_ID_128 zero = {0};
    return !RtlEqualMemory(&Identity->FileId, &zero, sizeof(zero));
}

static BOOLEAN NativeObservationLeafValid(const SAFEUPLOAD_NATIVE_NAME_REQUEST *Request)
{
    ULONG i, chars = Request->CanonicalLeafBytes / sizeof(WCHAR);
    if (chars == 0 || chars >= SAFEUPLOAD_NATIVE_REPLAY_LEAF_CHARS ||
        (Request->CanonicalLeafBytes & 1) != 0) return FALSE;
    if ((chars == 1 && Request->CanonicalLeaf[0] == L'.') ||
        (chars == 2 && Request->CanonicalLeaf[0] == L'.' && Request->CanonicalLeaf[1] == L'.')) return FALSE;
    for (i = 0; i < chars; ++i) {
        WCHAR c = Request->CanonicalLeaf[i];
        if (c == 0 || c == L'\\' || c == L'/' || c == L':' || c == L'*' || c == L'?') return FALSE;
        if (c >= 0xd800 && c <= 0xdbff) {
            if (++i >= chars || Request->CanonicalLeaf[i] < 0xdc00 || Request->CanonicalLeaf[i] > 0xdfff) return FALSE;
        } else if (c >= 0xdc00 && c <= 0xdfff) return FALSE;
    }
    for (i = chars; i < SAFEUPLOAD_NATIVE_REPLAY_LEAF_CHARS; ++i)
        if (Request->CanonicalLeaf[i] != 0) return FALSE;
    return TRUE;
}

static BOOLEAN NativeObservationStable(PNATIVE_OBSERVATION_WORK Work)
{
    UINT64 topology, coverage;
    return SafeUploadStageAdmissionReadTopology(&topology, &coverage) &&
        topology == Work->Topology && coverage == Work->Coverage &&
        (Work->Instance == NULL || (!SafeUploadStageAttachInstanceRetiring(Work->Instance) &&
            SafeUploadInstanceAdmissionGateSatisfied(Work->Instance)));
}

static VOID NativeObservationCloseDirectories(PNATIVE_OBSERVATION_WORK Work)
{
    if (Work->ParentObject != NULL) { ObDereferenceObject(Work->ParentObject); Work->ParentObject = NULL; }
    if (Work->ParentHandle != NULL) { FltClose(Work->ParentHandle); Work->ParentHandle = NULL; }
    if (Work->RootObject != NULL) { ObDereferenceObject(Work->RootObject); Work->RootObject = NULL; }
    if (Work->RootHandle != NULL) { FltClose(Work->RootHandle); Work->RootHandle = NULL; }
}

static NTSTATUS NativeObservationOpen(PNATIVE_OBSERVATION_WORK Work, HANDLE Root,
    PUNICODE_STRING Name, BOOLEAN ById, PHANDLE Handle, PFILE_OBJECT *Object)
{
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io = {0};
    NTSTATUS status;
    if (!NativeObservationStable(Work)) return STATUS_RETRY;
    InitializeObjectAttributes(&attributes, Name, OBJ_KERNEL_HANDLE | OBJ_DONT_REPARSE, Root, NULL);
    status = FltCreateFileEx2(SafeUploadData.Filter, Work->Instance, Handle, Object,
        FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attributes, &io, NULL, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT |
            FILE_COMPLETE_IF_OPLOCKED | (ById ? FILE_OPEN_BY_FILE_ID : 0),
        NULL, 0, IO_STOP_ON_SYMLINK, NULL);
    if (status == STATUS_STOPPED_ON_SYMLINK && io.Information != 0) ExFreePool((PVOID)io.Information);
    if (status != STATUS_SUCCESS) return NT_SUCCESS(status) ? STATUS_RETRY : status;
    if (*Object == NULL) return STATUS_FILE_INVALID;
    return NativeObservationStable(Work) ? STATUS_SUCCESS : STATUS_RETRY;
}

static NTSTATUS NativeObservationQuery(PNATIVE_OBSERVATION_WORK Work, PFILE_OBJECT Object,
    PVOID Buffer, ULONG Bytes, FILE_INFORMATION_CLASS Kind)
{
    ULONG returned = 0;
    NTSTATUS status;
    if (!NativeObservationStable(Work)) return STATUS_RETRY;
    status = FltQueryInformationFile(Work->Instance, Object, Buffer, Bytes, Kind, &returned);
    if (status != STATUS_SUCCESS) return NT_SUCCESS(status) ? STATUS_RETRY : status;
    if (returned != Bytes) return STATUS_INVALID_BUFFER_SIZE;
    return NativeObservationStable(Work) ? STATUS_SUCCESS : STATUS_RETRY;
}

static NTSTATUS NativeObservationAnchor(PNATIVE_OBSERVATION_WORK Work, PFILE_OBJECT Object,
    const SAFEUPLOAD_STAGE_IDENTITY_V19 *Expected, BOOLEAN CheckCase, BOOLEAN CaseSensitive)
{
    FILE_ATTRIBUTE_TAG_INFORMATION tag;
    FILE_ID_INFORMATION identity;
    FILE_CASE_SENSITIVE_INFORMATION caseInfo;
    NTSTATUS status;
    status = NativeObservationQuery(Work, Object, &tag, sizeof(tag), FileAttributeTagInformation);
    if (!NT_SUCCESS(status)) return status;
    if (!FlagOn(tag.FileAttributes, FILE_ATTRIBUTE_DIRECTORY) ||
        FlagOn(tag.FileAttributes, FILE_ATTRIBUTE_REPARSE_POINT)) return STATUS_REPARSE_POINT_ENCOUNTERED;
    status = NativeObservationQuery(Work, Object, &identity, sizeof(identity), FileIdInformation);
    if (!NT_SUCCESS(status)) return status;
    if (identity.VolumeSerialNumber != Expected->VolumeSerialNumber ||
        !RtlEqualMemory(&identity.FileId, &Expected->FileId, sizeof(FILE_ID_128))) return STATUS_FILE_INVALID;
    if (CheckCase) {
        status = NativeObservationQuery(Work, Object, &caseInfo, sizeof(caseInfo), FileCaseSensitiveInformation);
        if (!NT_SUCCESS(status)) return status;
        if (FlagOn(caseInfo.Flags, ~FILE_CS_FLAG_CASE_SENSITIVE_DIR) ||
            BooleanFlagOn(caseInfo.Flags, FILE_CS_FLAG_CASE_SENSITIVE_DIR) != CaseSensitive) return STATUS_FILE_INVALID;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS NativeObservationOpenAnchors(PNATIVE_OBSERVATION_WORK Work,
    const SAFEUPLOAD_NATIVE_NAME_REQUEST *Request)
{
    PFLT_VOLUME volume = NULL;
    PWCHAR buffer = NULL;
    UNICODE_STRING name = {0}, idName;
    ULONG needed = 0;
    ULONGLONG lowId, highId;
    NTSTATUS status;
    /* NTFS eight-byte selection only when the recorded full ID has a zero
     * high half. The subsequent query still compares all 128 bits. */
    RtlCopyMemory(&lowId, Request->ParentIdentity.FileId.Identifier, sizeof(lowId));
    RtlCopyMemory(&highId, Request->ParentIdentity.FileId.Identifier + sizeof(lowId), sizeof(highId));
    if (highId != 0 || lowId == 0) return STATUS_NOT_SUPPORTED;
    if (!NativeObservationStable(Work)) return STATUS_RETRY;
    status = FltGetVolumeFromInstance(Work->Instance, &volume);
    if (!NT_SUCCESS(status)) return status;
    status = FltGetVolumeName(volume, NULL, &needed);
    if (status != STATUS_BUFFER_TOO_SMALL || needed == 0 || needed > MAXUSHORT - sizeof(WCHAR)) {
        status = STATUS_FILE_INVALID;
        goto Exit;
    }
    buffer = ExAllocatePool2(POOL_FLAG_PAGED, needed + sizeof(WCHAR), NATIVE_OBSERVATION_TAG);
    if (buffer == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    name.Buffer = buffer;
    name.MaximumLength = (USHORT)needed;
    status = FltGetVolumeName(volume, &name, NULL);
    if (!NT_SUCCESS(status)) goto Exit;
    if (name.Length == 0 || (name.Length & 1) != 0 || name.Length > needed) { status = STATUS_FILE_INVALID; goto Exit; }
    buffer[name.Length / sizeof(WCHAR)] = L'\\'; /* directory root, never raw volume */
    name.Length += sizeof(WCHAR);
    name.MaximumLength = name.Length;
    status = NativeObservationOpen(Work, NULL, &name, FALSE, &Work->RootHandle, &Work->RootObject);
    if (!NT_SUCCESS(status)) goto Exit;
    status = NativeObservationAnchor(Work, Work->RootObject, &Request->VolumeRootIdentity, FALSE, FALSE);
    if (!NT_SUCCESS(status)) goto Exit;
    idName.Buffer = (PWCHAR)&lowId;
    idName.Length = idName.MaximumLength = sizeof(lowId);
    status = NativeObservationOpen(Work, Work->RootHandle, &idName, TRUE, &Work->ParentHandle, &Work->ParentObject);
    if (!NT_SUCCESS(status)) goto Exit;
    status = NativeObservationAnchor(Work, Work->ParentObject, &Request->ParentIdentity, TRUE,
        Request->ParentCaseSensitive != 0);
Exit:
    if (buffer != NULL) ExFreePoolWithTag(buffer, NATIVE_OBSERVATION_TAG);
    FltObjectDereference(volume);
    return status;
}

static NTSTATUS NativeObservationScan(PNATIVE_OBSERVATION_WORK Work,
    const SAFEUPLOAD_NATIVE_NAME_REQUEST *Request, PBOOLEAN Present, PFILE_ID_128 Identity)
{
    ULONG page, returned, offset, header = FIELD_OFFSET(FILE_ID_EXTD_DIR_INFORMATION, FileName);
    UNICODE_STRING leaf;
    NTSTATUS status;
    *Present = FALSE;
    RtlZeroMemory(Identity, sizeof(*Identity));
    leaf.Buffer = (PWCHAR)Request->CanonicalLeaf;
    leaf.Length = leaf.MaximumLength = (USHORT)Request->CanonicalLeafBytes;
    for (page = 0; page < NATIVE_OBSERVATION_PAGES; ++page) {
        if (!NativeObservationStable(Work)) return STATUS_RETRY;
        returned = 0;
        RtlZeroMemory(Work->Directory, sizeof(Work->Directory));
        status = FltQueryDirectoryFile(Work->Instance, Work->ParentObject, Work->Directory,
            sizeof(Work->Directory), FileIdExtdDirectoryInformation, FALSE, NULL, page == 0, &returned);
        if (status != STATUS_SUCCESS && status != STATUS_NO_MORE_FILES)
            return NT_SUCCESS(status) ? STATUS_RETRY : status;
        if (!NativeObservationStable(Work)) return STATUS_RETRY;
        if (status == STATUS_NO_MORE_FILES) return returned == 0 ? STATUS_SUCCESS : STATUS_DATA_ERROR;
        if (returned < header || returned > sizeof(Work->Directory)) return STATUS_INVALID_BUFFER_SIZE;
        offset = 0;
        for (;;) {
            PFILE_ID_EXTD_DIR_INFORMATION entry;
            UNICODE_STRING name;
            if (offset > returned - header) return STATUS_DATA_ERROR;
            entry = (PFILE_ID_EXTD_DIR_INFORMATION)(Work->Directory + offset);
            if (entry->FileNameLength == 0 || (entry->FileNameLength & 1) != 0 ||
                entry->FileNameLength > returned - offset - header || entry->FileNameLength > 255 * sizeof(WCHAR))
                return STATUS_DATA_ERROR;
            name.Buffer = entry->FileName;
            name.Length = name.MaximumLength = (USHORT)entry->FileNameLength;
            if (RtlEqualUnicodeString(&name, &leaf, Request->ParentCaseSensitive == 0)) {
                static const FILE_ID_128 zero = {0};
                if (*Present || FlagOn(entry->FileAttributes, FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) ||
                    RtlEqualMemory(&entry->FileId, &zero, sizeof(zero))) return STATUS_FILE_INVALID;
                *Present = TRUE;
                *Identity = entry->FileId;
            }
            if (entry->NextEntryOffset == 0) break;
            if (entry->NextEntryOffset < header + entry->FileNameLength || (entry->NextEntryOffset & 7) != 0 ||
                entry->NextEntryOffset > returned - offset - header) return STATUS_DATA_ERROR;
            offset += entry->NextEntryOffset;
        }
    }
    return STATUS_BUFFER_TOO_SMALL; /* incomplete scan is never absence */
}

_Use_decl_annotations_
NTSTATUS SafeUploadStageNativeNameControl(PVOID PortCookie, PVOID Input, ULONG InputLength,
    PVOID Output, ULONG OutputLength, PULONG Returned)
{
    static const GUID zero = {0};
    SAFEUPLOAD_NATIVE_NAME_REQUEST request;
    PNATIVE_OBSERVATION_WORK work = NULL;
    PEPROCESS process = NULL;
    PVOID cookie = NULL;
    LONG64 epoch = 0;
    ULONG processId, count, index, matches = 0, boot;
    UINT64 revision;
    GUID driver, mount;
    BOOLEAN complete, firstPresent, secondPresent;
    FILE_ID_128 firstId, secondId;
    NTSTATUS status;
    PAGED_CODE();
    *Returned = 0;
    if (InputLength != sizeof(request) || Output == NULL || OutputLength != sizeof(SAFEUPLOAD_NATIVE_NAME_REPLY))
        return STATUS_INVALID_BUFFER_SIZE;
    try {
        ProbeForRead(Input, sizeof(request), __alignof(SAFEUPLOAD_NATIVE_NAME_REQUEST));
        RtlCopyMemory(&request, Input, sizeof(request));
    } except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
    if (request.Control.Version != SAFEUPLOAD_PROTOCOL_VERSION || request.Control.StructSize != sizeof(request) ||
        request.Control.Command != SAFEUPLOAD_CONTROL_NATIVE_NAME_OBSERVATION || request.Control.Reserved != 0 ||
        request.ExtensionVersion != SAFEUPLOAD_NATIVE_REPLAY_VERSION || request.ExpectedConnectionEpoch == 0 ||
        request.ExpectedRevision == 0 || request.ParentCaseSensitive > 1 ||
        RtlEqualMemory(&request.ExpectedDriverInstanceId, &zero, sizeof(zero)) ||
        RtlEqualMemory(&request.MountManagerVolumeId, &zero, sizeof(zero)) ||
        !NativeObservationIdentityValid(&request.VolumeRootIdentity) || !NativeObservationIdentityValid(&request.ParentIdentity) ||
        request.VolumeRootIdentity.VolumeSerialNumber != request.ParentIdentity.VolumeSerialNumber ||
        !NativeObservationLeafValid(&request)) return STATUS_INVALID_PARAMETER;
    if (!SafeUploadConnectionGetAuthenticatedIdentity(PortCookie, &cookie, &epoch, &processId) ||
        !SafeUploadConnectionPinAuthenticatedProcess(cookie, epoch, &process)) return STATUS_ACCESS_DENIED;
    try {
        if (process != PsGetCurrentProcess() || request.ExpectedConnectionEpoch != (UINT64)epoch) {
            status = STATUS_ACCESS_DENIED; leave;
        }
        work = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*work), NATIVE_OBSERVATION_TAG);
        if (work == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; leave; }
        status = SafeUploadStageNativeReadIdentity(&driver, &boot);
        if (!NT_SUCCESS(status)) leave;
        if (boot != request.OsBootSequence || !RtlEqualMemory(&driver, &request.ExpectedDriverInstanceId, sizeof(GUID))) {
            status = STATUS_REVISION_MISMATCH; leave;
        }
        status = SafeUploadStageNativeReadPage(request.ExpectedRevision, 0, &work->RevisionProbe, 1,
            &count, &revision, &complete);
        if (!NT_SUCCESS(status)) leave;
        if (!SafeUploadStageAdmissionReadTopology(&work->Topology, &work->Coverage)) { status = STATUS_RETRY; leave; }
        status = FltEnumerateInstances(NULL, SafeUploadData.Filter, work->Instances, NATIVE_OBSERVATION_INSTANCES, &count);
        if (!NT_SUCCESS(status)) leave;
        if (count > NATIVE_OBSERVATION_INSTANCES) { status = STATUS_BUFFER_TOO_SMALL; leave; }
        for (index = 0; index < count; ++index) {
            if (work->Instances[index] == NULL || !NativeObservationStable(work)) { status = STATUS_RETRY; leave; }
            status = SafeUploadStagePublicReadMountGuid(work->Instances[index], &mount);
            if (!NT_SUCCESS(status)) leave; /* unknown provenance cannot prove unique selection */
            if (RtlEqualMemory(&mount, &request.MountManagerVolumeId, sizeof(GUID))) {
                ++matches;
                work->Instance = work->Instances[index];
            }
        }
        if (matches != 1 || !NativeObservationStable(work)) { status = STATUS_FILE_INVALID; leave; }
        status = NativeObservationOpenAnchors(work, &request);
        if (!NT_SUCCESS(status)) leave;
        status = NativeObservationScan(work, &request, &firstPresent, &firstId);
        if (!NT_SUCCESS(status)) leave;
        status = NativeObservationScan(work, &request, &secondPresent, &secondId);
        if (!NT_SUCCESS(status)) leave;
        if (firstPresent != secondPresent || !RtlEqualMemory(&firstId, &secondId, sizeof(firstId))) { status = STATUS_RETRY; leave; }
        status = NativeObservationAnchor(work, work->ParentObject, &request.ParentIdentity, TRUE, request.ParentCaseSensitive != 0);
        if (!NT_SUCCESS(status)) leave;
        status = NativeObservationAnchor(work, work->RootObject, &request.VolumeRootIdentity, FALSE, FALSE);
        if (!NT_SUCCESS(status)) leave;
        NativeObservationCloseDirectories(work);
        if (!NativeObservationStable(work)) { status = STATUS_RETRY; leave; }
        status = SafeUploadStagePublicReadMountGuid(work->Instance, &mount);
        if (!NT_SUCCESS(status)) leave;
        if (!RtlEqualMemory(&mount, &request.MountManagerVolumeId, sizeof(GUID))) { status = STATUS_FILE_INVALID; leave; }
        status = SafeUploadStageNativeReadPage(request.ExpectedRevision, 0, &work->RevisionProbe, 1, &count, &revision, &complete);
        if (!NT_SUCCESS(status)) leave;
        if (!NativeObservationStable(work) || !SafeUploadConnectionIsAuthenticatedIdentity(cookie, epoch)) {
            status = STATUS_RETRY; leave;
        }
        work->Reply.ExtensionVersion = SAFEUPLOAD_NATIVE_REPLAY_VERSION;
        work->Reply.StructSize = sizeof(work->Reply);
        work->Reply.DriverInstanceId = driver;
        work->Reply.ConnectionEpoch = (UINT64)epoch;
        work->Reply.Revision = revision;
        work->Reply.OsBootSequence = boot;
        work->Reply.CompleteScans = 2;
        work->Reply.MountManagerVolumeId = mount;
        work->Reply.VolumeRootIdentity = request.VolumeRootIdentity;
        work->Reply.ParentIdentity = request.ParentIdentity;
        work->Reply.ParentCaseSensitive = request.ParentCaseSensitive;
        work->Reply.CanonicalLeafBytes = request.CanonicalLeafBytes;
        RtlCopyMemory(work->Reply.CanonicalLeaf, request.CanonicalLeaf, request.CanonicalLeafBytes);
        work->Reply.Present = secondPresent ? 1 : 0;
        if (secondPresent) {
            work->Reply.ChildIdentity.VolumeSerialNumber = request.ParentIdentity.VolumeSerialNumber;
            work->Reply.ChildIdentity.FileId = secondId;
        }
        /* Release all directory/instance references before touching user
         * output. The message callback's authenticated process pin remains
         * until return; a final topology/revision check rejects retirement
         * while dropping these local references. */
        work->Instance = NULL;
        for (index = 0; index < NATIVE_OBSERVATION_INSTANCES; ++index) {
            if (work->Instances[index] != NULL) {
                FltObjectDereference(work->Instances[index]);
                work->Instances[index] = NULL;
            }
        }
        status = SafeUploadStageNativeReadPage(request.ExpectedRevision, 0, &work->RevisionProbe, 1, &count, &revision, &complete);
        if (!NT_SUCCESS(status)) leave;
        if (!NativeObservationStable(work) || !SafeUploadConnectionIsAuthenticatedIdentity(cookie, epoch)) {
            status = STATUS_RETRY; leave;
        }
        try {
#pragma warning(suppress: 6001)
            ProbeForWrite(Output, sizeof(work->Reply), __alignof(SAFEUPLOAD_NATIVE_NAME_REPLY));
            RtlCopyMemory(Output, &work->Reply, sizeof(work->Reply));
            *Returned = sizeof(work->Reply);
            status = STATUS_SUCCESS;
        } except (EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
    } finally {
        if (work != NULL) {
            NativeObservationCloseDirectories(work);
            for (index = 0; index < NATIVE_OBSERVATION_INSTANCES; ++index)
                if (work->Instances[index] != NULL) FltObjectDereference(work->Instances[index]);
            ExFreePoolWithTag(work, NATIVE_OBSERVATION_TAG);
        }
        SafeUploadConnectionReleaseAuthenticatedProcess(cookie, process);
    }
    return status;
}
#endif
