/* Read-only native-record replay on the already authenticated service port.
 * It exports no object addresses, handles, grants or mutation permits. */
#include "StageNativeRecords.h"
#include "StageNativeWire.h"

#if SAFEUPLOAD_STAGING_PROTOTYPE
#define NATIVE_WIRE_TAG 'wUpS'
#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SafeUploadStageNativeReplayControl)
#endif

typedef struct _NATIVE_REPLAY_WORK {
    SAFEUPLOAD_NATIVE_REPLAY_PAGE Page;
    SAFEUPLOAD_STAGE_NATIVE_SNAPSHOT Snapshots[SAFEUPLOAD_NATIVE_REPLAY_PAGE_ROWS];
} NATIVE_REPLAY_WORK, *PNATIVE_REPLAY_WORK;

static VOID NativeWireCopyIdentity(PSAFEUPLOAD_STAGE_IDENTITY_V19 To, const FILE_ID_INFORMATION *From)
{
    To->VolumeSerialNumber = From->VolumeSerialNumber;
    To->FileId = From->FileId;
}

static VOID NativeWireCopyRow(PSAFEUPLOAD_NATIVE_REPLAY_ROW To,
    const SAFEUPLOAD_STAGE_NATIVE_SNAPSHOT *From)
{
    const SAFEUPLOAD_STAGE_NATIVE_BINDING *b = &From->Binding;
    const SAFEUPLOAD_STAGE_PUBLIC_BINDING *p = &b->Public;
    To->DriverInstanceId = b->DriverInstanceId;
    To->MountManagerVolumeId = p->MountManagerVolumeId;
    To->TransferId = b->TransferId;
    To->RequestNonce = b->RequestNonce;
    To->OperationId = b->OperationId;
    To->OriginalConnectionEpoch = b->ConnectionEpoch;
    To->JournalGeneration = From->JournalGeneration;
    To->CallerProcessCreationTime = p->CallerProcessCreationTime;
    NativeWireCopyIdentity(&To->VolumeRootIdentity, &p->VolumeRootIdentity);
    NativeWireCopyIdentity(&To->ParentIdentity, &p->ParentIdentity);
    NativeWireCopyIdentity(&To->PublicIdentity, &p->PublicIdentity);
    To->OsBootSequence = b->OsBootSequence;
    To->CreateOptions = b->CreateOptions;
    To->OriginalDesiredAccess = p->OriginalDesiredAccess;
    To->OriginalShareAccess = p->OriginalShareAccess;
    To->CallerProcessId = p->CallerProcessId;
    To->CallerSessionId = p->CallerSessionId;
    To->CallerSidBytes = p->CallerSidBytes;
    To->ParentCaseSensitive = p->ParentCaseSensitive ? 1 : 0;
    To->CanonicalLeafBytes = p->CanonicalLeafBytes;
    To->Flags = (From->Forwarded ? SAFEUPLOAD_NATIVE_FORWARDED : 0) |
        (From->CreateOutcomeKnown ? SAFEUPLOAD_NATIVE_CREATE_KNOWN : 0) |
        (From->CreateAccepted ? SAFEUPLOAD_NATIVE_CREATE_ACCEPTED : 0) |
        (From->IdentityAndDeleteGrantChecked ? SAFEUPLOAD_NATIVE_IDENTITY_CHECKED : 0) |
        (From->LastHandleCleanedUp ? SAFEUPLOAD_NATIVE_LAST_CLEANUP : 0) |
        (From->CancelledBeforeHandle ? SAFEUPLOAD_NATIVE_CANCEL_BEFORE_HANDLE : 0) |
        (From->CancelledCloseObserved ? SAFEUPLOAD_NATIVE_CANCEL_CLOSE : 0) |
        (From->CleanupCoverageLost ? SAFEUPLOAD_NATIVE_COVERAGE_LOST : 0);
    To->CreateStatus = From->CreateStatus;
    To->IdentityStatus = From->IdentityStatus;
    To->TeardownReason = From->TeardownReason;
    RtlCopyMemory(To->CallerSid, p->CallerSid, p->CallerSidBytes);
    RtlCopyMemory(To->CanonicalLeaf, p->CanonicalLeaf, p->CanonicalLeafBytes);
}

_Use_decl_annotations_
NTSTATUS SafeUploadStageNativeReplayControl(PVOID PortCookie, PVOID Input, ULONG InputLength,
    PVOID Output, ULONG OutputLength, PULONG Returned)
{
    static const GUID zero = {0};
    SAFEUPLOAD_NATIVE_REPLAY_REQUEST request;
    PNATIVE_REPLAY_WORK work = NULL;
    PEPROCESS process = NULL;
    PVOID cookie = NULL;
    LONG64 epoch = 0;
    ULONG processId, count, index, bootSequence;
    UINT64 revision;
    BOOLEAN complete;
    NTSTATUS status;
    PAGED_CODE();
    *Returned = 0;
    if (InputLength != sizeof(request) || Output == NULL || OutputLength != sizeof(work->Page))
        return STATUS_INVALID_BUFFER_SIZE;
    /* Guard user-buffer accesses locally so the safety contract does not
     * depend on the dispatcher's enclosing exception handler. */
    try {
        ProbeForRead(Input, sizeof(request), __alignof(SAFEUPLOAD_NATIVE_REPLAY_REQUEST));
        RtlCopyMemory(&request, Input, sizeof(request));
    } except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    if (request.Control.Version != SAFEUPLOAD_PROTOCOL_VERSION || request.Control.StructSize != sizeof(request) ||
        request.Control.Command != SAFEUPLOAD_CONTROL_NATIVE_RECORD_REPLAY || request.Control.Reserved != 0 ||
        request.ExtensionVersion != SAFEUPLOAD_NATIVE_REPLAY_VERSION || request.Reserved != 0 ||
        request.StartIndex > SAFEUPLOAD_NATIVE_REPLAY_MAX_RECORDS ||
        (request.ExpectedRevision == 0 && (request.StartIndex != 0 || request.ExpectedConnectionEpoch != 0 ||
            !RtlEqualMemory(&request.ExpectedDriverInstanceId, &zero, sizeof(zero)))) ||
        (request.ExpectedRevision != 0 && (request.ExpectedConnectionEpoch == 0 ||
            RtlEqualMemory(&request.ExpectedDriverInstanceId, &zero, sizeof(zero)))))
        return STATUS_INVALID_PARAMETER;
    if (!SafeUploadConnectionGetAuthenticatedIdentity(PortCookie, &cookie, &epoch, &processId) ||
        !SafeUploadConnectionPinAuthenticatedProcess(cookie, epoch, &process)) return STATUS_ACCESS_DENIED;
    try {
        if (process != PsGetCurrentProcess() || (request.ExpectedConnectionEpoch != 0 &&
                request.ExpectedConnectionEpoch != (UINT64)epoch)) {
            status = STATUS_ACCESS_DENIED;
            leave;
        }
        work = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*work), NATIVE_WIRE_TAG);
        if (work == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; leave; }
        status = SafeUploadStageNativeReadIdentity(&work->Page.DriverInstanceId, &bootSequence);
        if (!NT_SUCCESS(status)) leave;
        work->Page.OsBootSequence = bootSequence;
        if (request.ExpectedRevision != 0 && !RtlEqualMemory(&request.ExpectedDriverInstanceId,
                &work->Page.DriverInstanceId, sizeof(GUID))) { status = STATUS_REVISION_MISMATCH; leave; }
        status = SafeUploadStageNativeReadPage(request.ExpectedRevision, request.StartIndex,
            work->Snapshots, SAFEUPLOAD_NATIVE_REPLAY_PAGE_ROWS, &count, &revision, &complete);
        if (!NT_SUCCESS(status)) leave;
        work->Page.ExtensionVersion = SAFEUPLOAD_NATIVE_REPLAY_VERSION;
        work->Page.StructSize = sizeof(work->Page);
        work->Page.ConnectionEpoch = (UINT64)epoch;
        work->Page.Revision = revision;
        work->Page.StartIndex = request.StartIndex;
        work->Page.Count = count;
        work->Page.Complete = complete ? 1 : 0;
        for (index = 0; index < count; ++index) NativeWireCopyRow(&work->Page.Rows[index], &work->Snapshots[index]);
        /* Encoding is outside NativeLock. Reject a change while encoding;
         * no stale page is sent as part of a complete absence proof. */
        status = SafeUploadStageNativeReadPage(revision, 0, work->Snapshots, 1, &count, &revision, &complete);
        if (!NT_SUCCESS(status)) leave;
        if (!SafeUploadConnectionIsAuthenticatedIdentity(cookie, epoch)) { status = STATUS_ACCESS_DENIED; leave; }
        try {
#pragma warning(suppress: 6001)
            ProbeForWrite(Output, sizeof(work->Page), __alignof(SAFEUPLOAD_NATIVE_REPLAY_PAGE));
            RtlCopyMemory(Output, &work->Page, sizeof(work->Page));
            *Returned = sizeof(work->Page);
            status = STATUS_SUCCESS;
        } except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
        }
    } finally {
        if (work != NULL) ExFreePoolWithTag(work, NATIVE_WIRE_TAG);
        SafeUploadConnectionReleaseAuthenticatedProcess(cookie, process);
    }
    return status;
}
#endif
