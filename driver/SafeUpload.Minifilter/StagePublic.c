/* T5 caller-checked public capability. App-facing proxies, journal RPCs,
 * service-only exports and one-use disposition permits are wired separately.
 * This module never sets disposition, writes data, or changes a public name.
 * See T5-DELETES.md sections 4.1/4.2. */
#include "StagePublic.h"
#include "Stage.h"
#include "StageWriterMetadata.h"
#include "StageNativeRecords.h"
#if SAFEUPLOAD_STAGING_PROTOTYPE
#include <bcrypt.h>
#endif

#if SAFEUPLOAD_STAGING_PROTOTYPE
#define STAGE_PUBLIC_TAG 'pUpS'

struct _SAFEUPLOAD_STAGE_PUBLIC_BACKEND {
    volatile LONG References;
    EX_RUNDOWN_REF Operations;
    volatile LONG Closing;
    KEVENT Closed;
    BOOLEAN Counted;
    BOOLEAN TeardownSelected;
    BOOLEAN WriterLease;
    LIST_ENTRY Link;
    PFLT_INSTANCE Instance;
    HANDLE PublicHandle;
    PFILE_OBJECT PublicObject;
    HANDLE RootHandle;
    PFILE_OBJECT RootObject;
    HANDLE ParentHandle;
    PFILE_OBJECT ParentObject;
    SAFEUPLOAD_STAGE_PUBLIC_BINDING Binding;
};

/* Bounds on capture, not promises about the supported product surface. A
 * limit hit is a named refusal; no prefix of an ancestor vector is usable. */
#define STAGE_WRITER_MAX_ANCHORS 128UL
#define STAGE_WRITER_MAX_LEASES 128L
#define STAGE_WRITER_MAX_METADATA_READERS 4L
#define STAGE_WRITER_SECURITY_BUDGET (2UL * 1024 * 1024)
#define STAGE_WRITER_STORED_SECURITY_LIMIT 65536UL
/* Documented all-parts query (includes labels, resource attributes and CAP).
 * This is a query mask, NOT backup intent or a privilege grant. No subset
 * fallback if the kernel/filesystem cannot supply it. Kernel qualification is
 * still required: learn.microsoft.com/windows/win32/secauthz/security-information */
#define STAGE_WRITER_SECURITY_INFORMATION BACKUP_SECURITY_INFORMATION

typedef struct _STAGE_WRITER_ANCHOR {
    HANDLE Handle;
    PFILE_OBJECT Object;
    FILE_ID_INFORMATION Identity;
    FILE_ATTRIBUTE_TAG_INFORMATION Attributes;
    FILE_BASIC_INFORMATION Basic;
    FILE_STANDARD_INFORMATION Standard;
    BOOLEAN CaseSensitive;
    USHORT ComponentOffset; /* Bytes into Snapshot->Name; root includes trailing slash. */
    USHORT ComponentBytes;
    ULONG SecurityBytes;
    PSECURITY_DESCRIPTOR Security;
} STAGE_WRITER_ANCHOR, *PSTAGE_WRITER_ANCHOR;

typedef struct _STAGE_WRITER_SNAPSHOT {
    UNICODE_STRING Name;
    GUID MountId;
    ULONG Count; /* root, all intermediate directories, parent, target (once each) */
    ULONG SecurityBytes;
    STAGE_WRITER_ANCHOR Anchors[STAGE_WRITER_MAX_ANCHORS];
} STAGE_WRITER_SNAPSHOT, *PSTAGE_WRITER_SNAPSHOT;

struct _SAFEUPLOAD_STAGE_WRITER_LEASE {
    SAFEUPLOAD_STAGE_PUBLIC_BACKEND Lifetime; /* common list/rundown, never a DELETE capability */
    SAFEUPLOAD_STAGE_CREATE_INPUT Input;
    SECURITY_CLIENT_CONTEXT Subject;
    BOOLEAN SubjectValid;
    PEPROCESS Process;
    HANDLE ProcessHandle; /* SYNCHRONIZE-only internal lifetime observation, never caller authority */
    PSTAGE_WRITER_SNAPSHOT Snapshot;
    /* Independent representations/provenance. The construction slot remains
     * empty until a native-equivalent constructor is proved. Neither a supplied
     * descriptor nor queried stored bytes may silently fill that slot. */
    PSECURITY_DESCRIPTOR ConstructionSecurity;
    ULONG ConstructionSecurityBytes;
    PSECURITY_DESCRIPTOR ExpectedStoredSecurity;
    ULONG ExpectedStoredSecurityBytes;
    ULONG OriginalInformation;
    ACCESS_MASK NativeGrantedAccess; /* actual retained handle; Binding projects T10 exclusions */
    /* Immutable once MetadataPublished is set under StagePublicListLock.
     * Reader operations protect the paged blob against local close/free. */
    volatile LONG MetadataPreparing;
    BOOLEAN MetadataPublished;
    PVOID MetadataCookie;
    SAFEUPLOAD_WRITER_METADATA_HEADER MetadataHeader;
    PUCHAR Metadata;
    volatile LONG Revalidating; /* at most one additional bounded snapshot per lease */
};
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_STAGE_WRITER_LEASE, Lifetime) == 0);

_IRQL_requires_(PASSIVE_LEVEL)
static VOID StageWriterCloseHandles(_Inout_ PSAFEUPLOAD_STAGE_WRITER_LEASE Lease);
_IRQL_requires_(PASSIVE_LEVEL)
static VOID StageWriterFree(_Inout_ PSAFEUPLOAD_STAGE_WRITER_LEASE Lease);

/* ZwQueryObject's documented public ObjectBasicInformation layout. */
typedef struct _STAGE_PUBLIC_OBJECT_BASIC_INFORMATION {
    ULONG Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG HandleCount;
    ULONG PointerCount;
    ULONG Reserved[10];
} STAGE_PUBLIC_OBJECT_BASIC_INFORMATION;

static volatile LONG StagePublicBackendCount;
static EX_PUSH_LOCK StagePublicListLock;
static LIST_ENTRY StagePublicBackends;
static EX_RUNDOWN_REF StagePublicOpens;
static KEVENT StagePublicDrained;
static BOOLEAN StagePublicOpensDrained;
static BOOLEAN StagePublicAdmissionClosed;
static LONG StagePublicFactories;
/* Protected by StagePublicListLock. A slot precedes every reader reference,
 * operation rundown and page allocation, including native control callers. */
static LONG StageWriterMetadataReaders;
static KEVENT StageWriterMetadataReadersDrained;
static DECLSPEC_ALIGN(8) volatile LONG64 StageWriterRefusals[StageWriterRefusalCount];

static const PCSTR StageWriterReasonNames[StageWriterRefusalCount] = {
    "none", "writer_subject_unrepresentable", "native_create_security_unproved",
    "publication_security_not_equivalent", "writer_creator_grant_unproved",
    "writer_create_semantics_unproved", "writer_lookup_unproved",
    "writer_metadata_unproved", "writer_snapshot_changed", "writer_capture_limit",
    "writer_metadata_binding_mismatch", "writer_metadata_stale", "writer_metadata_resource_limit", "writer_metadata_replay_unbound",
    "seed_coherence_unproved", "seed_completion_unproved", "seed_io_failed"
};

_Use_decl_annotations_
VOID SafeUploadStagePublicRecordWriterRefusal(SAFEUPLOAD_STAGE_WRITER_REFUSAL Reason)
{
    if (Reason > StageWriterNoRefusal && Reason < StageWriterRefusalCount)
        InterlockedIncrement64(&StageWriterRefusals[Reason]);
}

_Use_decl_annotations_
LONG64 SafeUploadStagePublicWriterRefusalCount(SAFEUPLOAD_STAGE_WRITER_REFUSAL Reason)
{
    if (Reason <= StageWriterNoRefusal || Reason >= StageWriterRefusalCount) return 0;
    return InterlockedCompareExchange64(&StageWriterRefusals[Reason], 0, 0);
}

_Use_decl_annotations_
PCSTR SafeUploadStagePublicWriterRefusalName(SAFEUPLOAD_STAGE_WRITER_REFUSAL Reason)
{
    if (Reason < StageWriterNoRefusal || Reason >= StageWriterRefusalCount) return "invalid_writer_refusal";
    return StageWriterReasonNames[Reason];
}

/* Serialize voluntary preflight against factory publication. No I/O/waits
 * under this lock. A veto leaves factory/worker/retry admission usable. */
BOOLEAN SafeUploadStagePublicTryCloseAdmission(VOID)
{
    BOOLEAN allowed;
    FltAcquirePushLockExclusive(&StagePublicListLock);
    allowed = StagePublicFactories == 0 && StageWriterMetadataReaders == 0 &&
        InterlockedCompareExchange(&StagePublicBackendCount, 0, 0) == 0;
    if (allowed) StagePublicAdmissionClosed = TRUE;
    FltReleasePushLock(&StagePublicListLock);
    return allowed;
}

VOID SafeUploadStagePublicReopenAdmission(VOID)
{
    FltAcquirePushLockExclusive(&StagePublicListLock);
    if (!SafeUploadStageMandatoryTeardownActive()) StagePublicAdmissionClosed = FALSE;
    FltReleasePushLock(&StagePublicListLock);
}

static BOOLEAN StagePublicBeginOpen(VOID)
{
    BOOLEAN allowed;
    if (!ExAcquireRundownProtection(&StagePublicOpens)) return FALSE;
    FltAcquirePushLockExclusive(&StagePublicListLock);
    allowed = !StagePublicAdmissionClosed && !SafeUploadStageMandatoryTeardownActive();
    if (allowed) ++StagePublicFactories;
    FltReleasePushLock(&StagePublicListLock);
    if (!allowed) ExReleaseRundownProtection(&StagePublicOpens);
    return allowed;
}

static VOID StagePublicEndOpen(VOID)
{
    FltAcquirePushLockExclusive(&StagePublicListLock);
    NT_ASSERT(StagePublicFactories > 0);
    --StagePublicFactories;
    FltReleasePushLock(&StagePublicListLock);
    ExReleaseRundownProtection(&StagePublicOpens);
}

VOID SafeUploadStagePublicInitialize(VOID)
{
    ULONG index;
    FltInitializePushLock(&StagePublicListLock);
    InitializeListHead(&StagePublicBackends);
    ExInitializeRundownProtection(&StagePublicOpens);
    StagePublicOpensDrained = FALSE;
    StagePublicAdmissionClosed = FALSE;
    StagePublicFactories = 0;
    StageWriterMetadataReaders = 0;
    KeInitializeEvent(&StageWriterMetadataReadersDrained, NotificationEvent, TRUE);
    for (index = 0; index < StageWriterRefusalCount; ++index)
        InterlockedExchange64(&StageWriterRefusals[index], 0);
    KeInitializeEvent(&StagePublicDrained, NotificationEvent, TRUE);
}

_Use_decl_annotations_
VOID SafeUploadStagePublicCloseAllBackends(VOID)
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    /* Close reader admission under the same lock as slot reservation, then
     * drain locally. No page/operation can survive this wait; no service ACK. */
    FltAcquirePushLockExclusive(&StagePublicListLock);
    StagePublicAdmissionClosed = TRUE;
    FltReleasePushLock(&StagePublicListLock);
    (VOID)KeWaitForSingleObject(&StageWriterMetadataReadersDrained, Executive, KernelMode, FALSE, NULL);
    /* The unload thread is the sole closer; a close retry must not start a
     * second EX rundown wait on an already completed rundown object. */
    if (!StagePublicOpensDrained) {
        ExWaitForRundownProtectionRelease(&StagePublicOpens);
        StagePublicOpensDrained = TRUE;
    }
    for (;;) {
        PLIST_ENTRY link;
        PSAFEUPLOAD_STAGE_PUBLIC_BACKEND backend = NULL;
        FltAcquirePushLockExclusive(&StagePublicListLock);
        for (link = StagePublicBackends.Flink; link != &StagePublicBackends; link = link->Flink) {
            PSAFEUPLOAD_STAGE_PUBLIC_BACKEND current = CONTAINING_RECORD(link, SAFEUPLOAD_STAGE_PUBLIC_BACKEND, Link);
            if (current->TeardownSelected) continue;
            current->TeardownSelected = TRUE;
            SafeUploadStagePublicReferenceBackend(current);
            backend = current;
            break;
        }
        FltReleasePushLock(&StagePublicListLock);
        if (backend == NULL) return;
        SafeUploadStagePublicCloseBackend(backend);
        SafeUploadStagePublicDereferenceBackend(backend);
    }
}

_Use_decl_annotations_
VOID SafeUploadStagePublicDrainBackends(VOID)
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    NT_ASSERT(StagePublicOpensDrained);
    (VOID)KeWaitForSingleObject(&StagePublicDrained, Executive, KernelMode, FALSE, NULL);
}


_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StagePublicBindCaller(PSECURITY_CLIENT_CONTEXT Subject,
    PEPROCESS RequestorProcess, PSAFEUPLOAD_STAGE_PUBLIC_BINDING Binding);
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StagePublicCaptureSubject(PFLT_CALLBACK_DATA Data,
    PSECURITY_CLIENT_CONTEXT Subject, BOOLEAN RequireImpersonation);
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StagePublicOpenBackend(_In_ PFLT_INSTANCE Instance,
    _In_ PUNICODE_STRING PublicName, _In_ PSECURITY_CLIENT_CONTEXT Subject,
    _In_ PEPROCESS OriginalRequestorProcess,
    _In_ ACCESS_MASK OriginalDesiredAccess, _In_ ULONG OriginalShareAccess,
    _In_ ULONG OriginalCreateOptions, _In_ BOOLEAN CaseSensitiveOpen,
    _Outptr_result_nullonfailure_ PSAFEUPLOAD_STAGE_PUBLIC_BACKEND *Backend);
#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, StagePublicBindCaller)
#pragma alloc_text(PAGE, StagePublicCaptureSubject)
#pragma alloc_text(PAGE, StagePublicOpenBackend)
#endif

/* RequestorProcess is the original CREATE's referenced process object, not a
 * new PID lookup. The effective SID/session come from the exact copied subject
 * used for the checked NTFS open, including an impersonated/restricted token. */
_Use_decl_annotations_
static NTSTATUS StagePublicBindCaller(PSECURITY_CLIENT_CONTEXT Subject,
    PEPROCESS RequestorProcess, PSAFEUPLOAD_STAGE_PUBLIC_BINDING Binding)
{
    PTOKEN_USER user = NULL;
    PULONG session = NULL;
    ULONG sidBytes;
    NTSTATUS status;
    PAGED_CODE();
    Binding->CallerProcessId = HandleToULong(PsGetProcessId(RequestorProcess));
    Binding->CallerProcessCreationTime = PsGetProcessCreateTimeQuadPart(RequestorProcess);
    if (Binding->CallerProcessId == 0 || Binding->CallerProcessCreationTime <= 0)
        return STATUS_ACCESS_DENIED;
    status = SeQueryInformationToken(Subject->ClientToken, TokenUser, (PVOID *)&user);
    if (!NT_SUCCESS(status)) goto Exit;
    if (user == NULL || user->User.Sid == NULL || !RtlValidSid(user->User.Sid)) {
        status = STATUS_INVALID_SID;
        goto Exit;
    }
    sidBytes = RtlLengthSid(user->User.Sid);
    if (sidBytes == 0 || sidBytes > sizeof(Binding->CallerSid)) {
        status = STATUS_INVALID_SID;
        goto Exit;
    }
    status = RtlCopySid(sizeof(Binding->CallerSid), Binding->CallerSid, user->User.Sid);
    if (!NT_SUCCESS(status)) goto Exit;
    Binding->CallerSidBytes = sidBytes;
    status = SeQueryInformationToken(Subject->ClientToken, TokenSessionId, (PVOID *)&session);
    if (!NT_SUCCESS(status)) goto Exit;
    if (session == NULL) {
        status = STATUS_INVALID_BUFFER_SIZE;
        goto Exit;
    }
    Binding->CallerSessionId = *session;
Exit:
    if (user != NULL) ExFreePool(user);
    if (session != NULL) ExFreePool(session);
    return status;
}

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SafeUploadStagePublicCaptureSubject)
#pragma alloc_text(PAGE, SafeUploadStagePublicCaptureNativeSubject)
#pragma alloc_text(PAGE, SafeUploadStagePublicCaptureCreateSubject)
#pragma alloc_text(PAGE, SafeUploadStagePublicCaptureCreateLookup)
#pragma alloc_text(PAGE, SafeUploadStagePublicCloseCreateLookup)
#pragma alloc_text(PAGE, SafeUploadStagePublicOpenBackend)
#pragma alloc_text(PAGE, SafeUploadStagePublicCloseBackend)
#pragma alloc_text(PAGE, SafeUploadStagePublicDereferenceBackend)
#pragma alloc_text(PAGE, SafeUploadStagePublicReleaseOperation)
#pragma alloc_text(PAGE, SafeUploadStagePublicReadMountGuid)
#pragma alloc_text(PAGE, SafeUploadStagePublicCaptureNativeName)
#endif

_Use_decl_annotations_
NTSTATUS SafeUploadStagePublicReadMountGuid(PFLT_INSTANCE Instance, GUID *VolumeId)
{
    static const GUID zero = {0};
    const UNICODE_STRING prefix = RTL_CONSTANT_STRING(L"\\??\\Volume");
    PSAFEUPLOAD_INSTANCE_CONTEXT context = NULL;
    UNICODE_STRING full, text;
    NTSTATUS status;
    ULONG prefixChars = prefix.Length / sizeof(WCHAR);
    PAGED_CODE();
    RtlZeroMemory(VolumeId, sizeof(*VolumeId));
    status = FltGetInstanceContext(Instance, (PFLT_CONTEXT *)&context);
    if (!NT_SUCCESS(status)) return status;
    if (context->VolumeGuidStatus != STATUS_SUCCESS ||
        (context->VolumeGuidChars != prefixChars + 38 && context->VolumeGuidChars != prefixChars + 39)) {
        status = STATUS_FILE_INVALID;
        goto Exit;
    }
    full.Buffer = context->VolumeGuid;
    full.Length = (USHORT)(context->VolumeGuidChars * sizeof(WCHAR));
    full.MaximumLength = full.Length;
    if (!RtlPrefixUnicodeString(&prefix, &full, TRUE) ||
        (context->VolumeGuidChars == prefixChars + 39 && context->VolumeGuid[prefixChars + 38] != L'\\')) {
        status = STATUS_FILE_INVALID;
        goto Exit;
    }
    text.Buffer = &context->VolumeGuid[prefixChars];
    text.Length = 38 * sizeof(WCHAR);
    text.MaximumLength = text.Length;
    status = RtlGUIDFromString(&text, VolumeId);
    if (NT_SUCCESS(status) && RtlEqualMemory(VolumeId, &zero, sizeof(zero))) status = STATUS_FILE_INVALID;
Exit:
    FltReleaseContext(context);
    if (!NT_SUCCESS(status)) RtlZeroMemory(VolumeId, sizeof(*VolumeId));
    return status;
}

_Use_decl_annotations_
static NTSTATUS StagePublicCaptureSubject(PFLT_CALLBACK_DATA Data,
    PSECURITY_CLIENT_CONTEXT Subject, BOOLEAN RequireImpersonation)
{
    PIO_SECURITY_CONTEXT security;
    PSECURITY_SUBJECT_CONTEXT source;
    SECURITY_QUALITY_OF_SERVICE qos;
    NTSTATUS status;
    PAGED_CODE();
    if (Subject == NULL) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Subject, sizeof(*Subject));
    if (Data == NULL || Data->Iopb == NULL || Data->Iopb->MajorFunction != IRP_MJ_CREATE)
        return STATUS_INVALID_PARAMETER;
    security = Data->Iopb->Parameters.Create.SecurityContext;
    if (security == NULL || security->AccessState == NULL) return STATUS_ACCESS_DENIED;
    source = &security->AccessState->SubjectSecurityContext;
    if (source->ClientToken == NULL && source->PrimaryToken == NULL) return STATUS_ACCESS_DENIED;
    if (RequireImpersonation && source->ClientToken != NULL && source->ImpersonationLevel < SecurityImpersonation)
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
    status = SeCreateClientSecurityFromSubjectContext(source, &qos, FALSE, Subject);
    if (!NT_SUCCESS(status)) RtlZeroMemory(Subject, sizeof(*Subject));
    return status;
}

_Use_decl_annotations_
NTSTATUS SafeUploadStagePublicCaptureSubject(PFLT_CALLBACK_DATA Data, PSECURITY_CLIENT_CONTEXT Subject)
{
    PAGED_CODE();
    return StagePublicCaptureSubject(Data, Subject, TRUE);
}

_Use_decl_annotations_
NTSTATUS SafeUploadStagePublicCaptureNativeSubject(PFLT_CALLBACK_DATA Data, PSECURITY_CLIENT_CONTEXT Subject)
{
    PAGED_CODE();
    return StagePublicCaptureSubject(Data, Subject, FALSE);
}

_Use_decl_annotations_
NTSTATUS SafeUploadStagePublicCaptureCreateSubject(PFLT_CALLBACK_DATA Data, PSECURITY_CLIENT_CONTEXT Subject)
{
    NTSTATUS status;
    PAGED_CODE();
    status = StagePublicCaptureSubject(Data, Subject, TRUE);
    if (status == STATUS_BAD_IMPERSONATION_LEVEL)
        SafeUploadStagePublicRecordWriterRefusal(StageWriterSubjectUnrepresentable);
    return status;
}

_Use_decl_annotations_
NTSTATUS SafeUploadStagePublicCaptureCreateLookup(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, PSAFEUPLOAD_STAGE_CREATE_INPUT Input)
{
    PFLT_FILE_NAME_INFORMATION opened = NULL;
    PFLT_VOLUME volume = NULL;
    PFILE_OBJECT root;
    UNICODE_STRING lookup;
    BOOLEAN directory;
    NTSTATUS status;
    PAGED_CODE();
    if (Data == NULL || Data->Iopb == NULL || Objects == NULL || Objects->Filter == NULL ||
        Input == NULL || Objects->FileObject == NULL ||
        Objects->Volume == NULL || Objects->Instance == NULL ||
        Data->Iopb->MajorFunction != IRP_MJ_CREATE || Input->LookupName.Buffer != NULL ||
        Input->LookupRoot != NULL || Input->LookupRootHandle != NULL) return STATUS_INVALID_PARAMETER;
    root = Objects->FileObject->RelatedFileObject;
    Input->LookupById = BooleanFlagOn(Input->Options, FILE_OPEN_BY_FILE_ID);
    if (root != NULL || Input->LookupById) {
        /* Preserve this exact pair, including a rooted-looking string. The
         * original file object owns these inputs while the callback runs. */
        lookup = Objects->FileObject->FileName;
        if (root != NULL) {
            if (!FlagOn(root->Flags, FO_HANDLE_CREATED) || FlagOn(root->Flags, FO_CLEANUP_COMPLETE))
                return STATUS_INVALID_DEVICE_STATE;
            status = FltGetVolumeFromFileObject(Objects->Filter, root, &volume);
            if (!NT_SUCCESS(status)) return status;
            if (volume != Objects->Volume) { status = STATUS_NOT_SAME_DEVICE; goto Exit; }
            if (!Input->LookupById) {
                status = FltIsDirectory(root, Objects->Instance, &directory);
                if (!NT_SUCCESS(status)) goto Exit;
                if (!directory) { status = STATUS_NOT_A_DIRECTORY; goto Exit; }
            }
            ObReferenceObject(root);
            Input->LookupRoot = root;
            /* Pin an existing original root handle while still on the CREATE
             * callback. Zero desired access is an internal object locator,
             * not a target reopen or an application grant. */
            status = ObOpenObjectByPointer(root, OBJ_KERNEL_HANDLE, NULL, 0,
                *IoFileObjectType, KernelMode, &Input->LookupRootHandle);
            if (!NT_SUCCESS(status)) goto Exit;
            if (FlagOn(root->Flags, FO_CLEANUP_COMPLETE)) {
                status = STATUS_FILE_CLOSED;
                goto Exit;
            }
        }
    } else {
        status = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY, &opened);
        if (!NT_SUCCESS(status)) return status;
        status = FltParseFileNameInformation(opened);
        if (!NT_SUCCESS(status)) goto Exit;
        status = FltGetVolumeFromName(Objects->Filter, &opened->Volume, &volume);
        if (!NT_SUCCESS(status)) goto Exit;
        if (volume != Objects->Volume) { status = STATUS_NOT_SAME_DEVICE; goto Exit; }
        lookup = opened->Name;
    }
    if (lookup.Buffer == NULL || lookup.Length == 0 || lookup.Length > lookup.MaximumLength ||
        lookup.Length > SAFEUPLOAD_MAX_PATH_BYTES ||
        (!Input->LookupById && (lookup.Length & 1) != 0)) {
        status = STATUS_OBJECT_PATH_INVALID;
        goto Exit;
    }
    Input->LookupName.Buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, lookup.Length, STAGE_PUBLIC_TAG);
    if (Input->LookupName.Buffer == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    __try {
        RtlCopyMemory(Input->LookupName.Buffer, lookup.Buffer, lookup.Length);
        Input->LookupName.Length = lookup.Length;
        Input->LookupName.MaximumLength = lookup.Length;
        status = STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
Exit:
    if (volume != NULL) FltObjectDereference(volume);
    if (opened != NULL) FltReleaseFileNameInformation(opened);
    /* Partial captures are owned by the transaction's normal destructor. */
    return status;
}

_Use_decl_annotations_
VOID SafeUploadStagePublicFreeCreateLookup(PSAFEUPLOAD_STAGE_CREATE_INPUT Input)
{
    /* Active rundown drops these pins before unlinking the transaction.
     * The cancel callback can then release the final, empty transaction at
     * DISPATCH_LEVEL, so even the no-op destructor must be nonpageable. */
    NT_ASSERT(Input->LookupRootHandle == NULL); /* closed by PASSIVE active/failure rundown */
    if (Input->LookupRoot != NULL) {
        ObDereferenceObject(Input->LookupRoot);
        Input->LookupRoot = NULL;
    }
    if (Input->LookupName.Buffer != NULL) {
        ExFreePoolWithTag(Input->LookupName.Buffer, STAGE_PUBLIC_TAG);
        RtlZeroMemory(&Input->LookupName, sizeof(Input->LookupName));
    }
}

_Use_decl_annotations_
VOID SafeUploadStagePublicCloseCreateLookup(PSAFEUPLOAD_STAGE_CREATE_INPUT Input)
{
    PAGED_CODE();
    if (Input->LookupRootHandle != NULL) {
        ZwClose(Input->LookupRootHandle);
        Input->LookupRootHandle = NULL;
    }
}

_IRQL_requires_(PASSIVE_LEVEL)
static VOID StagePublicCloseObject(_Inout_ PHANDLE Handle, _Inout_ PFILE_OBJECT *FileObject)
{
    PFILE_OBJECT object = *FileObject;
    HANDLE handle = *Handle;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    *FileObject = NULL;
    *Handle = NULL;
    /* The handle still pins the FILE_OBJECT while its extra reference is
     * dropped. Closing it then permits normal NTFS cleanup/last close. */
    if (object != NULL) ObDereferenceObject(object);
    if (handle != NULL) FltClose(handle);
}

_Use_decl_annotations_
VOID SafeUploadStagePublicReferenceBackend(PSAFEUPLOAD_STAGE_PUBLIC_BACKEND Backend)
{
    NT_ASSERT(Backend != NULL && InterlockedCompareExchange(&Backend->References, 0, 0) > 0);
    InterlockedIncrement(&Backend->References);
}

_Use_decl_annotations_
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
    if (Backend->WriterLease)
        StageWriterCloseHandles(CONTAINING_RECORD(Backend, SAFEUPLOAD_STAGE_WRITER_LEASE, Lifetime));
    /* Close all owned metadata anchors before dependent last-close waits. */
    StagePublicCloseObject(&Backend->ParentHandle, &Backend->ParentObject);
    StagePublicCloseObject(&Backend->RootHandle, &Backend->RootObject);
    KeSetEvent(&Backend->Closed, IO_NO_INCREMENT, FALSE);
}

_Use_decl_annotations_
VOID SafeUploadStagePublicDereferenceBackend(PSAFEUPLOAD_STAGE_PUBLIC_BACKEND Backend)
{
    PAGED_CODE();
    if (Backend == NULL) return;
    FltAcquirePushLockExclusive(&StagePublicListLock);
    if (InterlockedDecrement(&Backend->References) != 0) {
        FltReleasePushLock(&StagePublicListLock);
        return;
    }
    if (Backend->Counted) RemoveEntryList(&Backend->Link);
    FltReleasePushLock(&StagePublicListLock);
    SafeUploadStagePublicCloseBackend(Backend);
    StagePublicCloseObject(&Backend->ParentHandle, &Backend->ParentObject);
    StagePublicCloseObject(&Backend->RootHandle, &Backend->RootObject);
    if (Backend->WriterLease)
        StageWriterFree(CONTAINING_RECORD(Backend, SAFEUPLOAD_STAGE_WRITER_LEASE, Lifetime));
    if (Backend->Instance != NULL) FltObjectDereference(Backend->Instance);
    if (Backend->Counted && InterlockedDecrement(&StagePublicBackendCount) == 0)
        KeSetEvent(&StagePublicDrained, IO_NO_INCREMENT, FALSE);
    ExFreePoolWithTag(Backend, STAGE_PUBLIC_TAG);
}

_Use_decl_annotations_
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
    if (SafeUploadStageMandatoryTeardownActive() ||
        InterlockedCompareExchange(&Backend->Closing, 0, 0) != 0) {
        ExReleaseRundownProtection(&Backend->Operations);
        InterlockedDecrement(&Backend->References);
        return FALSE;
    }
    *Instance = Backend->Instance;
    *FileObject = Backend->PublicObject;
    return TRUE;
}

_Use_decl_annotations_
VOID SafeUploadStagePublicReleaseOperation(PSAFEUPLOAD_STAGE_PUBLIC_BACKEND Backend)
{
    PAGED_CODE();
    ExReleaseRundownProtection(&Backend->Operations);
    SafeUploadStagePublicDereferenceBackend(Backend);
}

_Use_decl_annotations_
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
    PFLT_FILE_NAME_INFORMATION Name, BOOLEAN TargetIdentityKnown)
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
            (TargetIdentityKnown &&
             !RtlEqualMemory(&entry->FileId, &Backend->Binding.PublicIdentity.FileId, sizeof(FILE_ID_128))))
            status = STATUS_FILE_INVALID;
        else {
            actual.Buffer = entry->FileName;
            actual.Length = (USHORT)entry->FileNameLength;
            actual.MaximumLength = actual.Length;
            /* A short alias can differ from the returned long leaf. Identity
             * is the authority; wildcard/stream selectors were never allowed. */
            Backend->Binding.CanonicalLeafBytes = actual.Length;
            RtlCopyMemory(Backend->Binding.CanonicalLeaf, actual.Buffer, actual.Length);
            if (!TargetIdentityKnown) {
                static const FILE_ID_128 zero = {0};
                if (RtlEqualMemory(&entry->FileId, &zero, sizeof(zero))) status = STATUS_FILE_INVALID;
                else {
                    Backend->Binding.PublicIdentity.VolumeSerialNumber = parentIdentity.VolumeSerialNumber;
                    Backend->Binding.PublicIdentity.FileId = entry->FileId;
                }
            }
        }
    }
    ExFreePoolWithTag(entry, STAGE_PUBLIC_TAG);
    return status;
}

_Use_decl_annotations_
NTSTATUS SafeUploadStagePublicCaptureNativeName(PFLT_INSTANCE Instance,
    PFLT_FILE_NAME_INFORMATION Name, PSECURITY_CLIENT_CONTEXT Subject,
    PEPROCESS OriginalRequestorProcess, ACCESS_MASK OriginalDesiredAccess,
    ULONG OriginalShareAccess, ULONG OriginalCreateOptions, PSAFEUPLOAD_STAGE_PUBLIC_BINDING Binding)
{
    PSAFEUPLOAD_STAGE_PUBLIC_BACKEND metadata = NULL;
    PSAFEUPLOAD_INSTANCE_CONTEXT context = NULL;
    PACCESS_TOKEN oldToken;
    BOOLEAN copyOnOpen, effectiveOnly, sensitive;
    SECURITY_IMPERSONATION_LEVEL level;
    FILE_ID_INFORMATION identity;
    ULONG index;
    GUID volumeId;
    NTSTATUS status;
    PAGED_CODE();
    if (Binding == NULL) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Binding, sizeof(*Binding));
    if (Instance == NULL || Name == NULL || Name->Name.Buffer == NULL ||
        Name->Name.Length == 0 || Name->Name.Length > SAFEUPLOAD_MAX_PATH_BYTES ||
        (Name->Name.Length & 1) != 0 || Name->Name.Length > Name->Name.MaximumLength ||
        Subject == NULL || Subject->ClientToken == NULL || OriginalRequestorProcess == NULL ||
        (OriginalCreateOptions >> 24) != FILE_OPEN ||
        FlagOn(OriginalCreateOptions, FILE_DIRECTORY_FILE | FILE_OPEN_BY_FILE_ID | FILE_OPEN_REPARSE_POINT) ||
        !FlagOn(OriginalDesiredAccess, DELETE) ||
        FlagOn(OriginalDesiredAccess, FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
            FILE_DELETE_CHILD | GENERIC_WRITE | GENERIC_ALL | MAXIMUM_ALLOWED) ||
        (FlagOn(OriginalCreateOptions, FILE_DELETE_ON_CLOSE) && FlagOn(OriginalDesiredAccess, FILE_WRITE_ATTRIBUTES)) ||
        FlagOn(OriginalShareAccess, ~(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)) ||
        IoGetTopLevelIrp() != NULL || !PsIsSystemThread(PsGetCurrentThread()) ||
        PsGetCurrentProcess() != PsInitialSystemProcess) return STATUS_INVALID_PARAMETER;
    for (index = 0; index < Name->Name.Length / sizeof(WCHAR); ++index) {
        WCHAR ch = Name->Name.Buffer[index];
        if (ch < 32 || ch == L':' || ch == L'*' || ch == L'?' || ch == L'"' ||
            ch == L'<' || ch == L'>' || ch == L'|') return STATUS_OBJECT_PATH_INVALID;
    }
    oldToken = PsReferenceImpersonationToken(PsGetCurrentThread(), &copyOnOpen, &effectiveOnly, &level);
    if (oldToken != NULL) {
        PsDereferenceImpersonationToken(oldToken);
        return STATUS_INVALID_DEVICE_STATE;
    }
    status = FltGetInstanceContext(Instance, (PFLT_CONTEXT *)&context);
    if (!NT_SUCCESS(status)) return status;
    if (context->VolumeKind != SafeUploadVolumeFixed || context->FileSystemType != FLT_FSTYPE_NTFS ||
        context->DeviceInformationStatus != STATUS_SUCCESS || context->StorageDeviceType != FILE_DEVICE_DISK ||
        FlagOn(context->StorageDeviceCharacteristics, FILE_PORTABLE_DEVICE | FILE_REMOVABLE_MEDIA | FILE_REMOTE_DEVICE))
        status = STATUS_NOT_SUPPORTED;
    FltReleaseContext(context);
    if (!NT_SUCCESS(status)) return status;
    metadata = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*metadata), STAGE_PUBLIC_TAG);
    if (metadata == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    metadata->References = 1;
    ExInitializeRundownProtection(&metadata->Operations);
    KeInitializeEvent(&metadata->Closed, NotificationEvent, FALSE);
    status = FltObjectReference(Instance);
    if (!NT_SUCCESS(status)) goto Exit;
    metadata->Instance = Instance;
    status = SafeUploadStagePublicReadMountGuid(Instance, &metadata->Binding.MountManagerVolumeId);
    if (!NT_SUCCESS(status)) goto Exit;
    metadata->Binding.OriginalDesiredAccess = OriginalDesiredAccess;
    metadata->Binding.OriginalShareAccess = OriginalShareAccess;
    status = StagePublicBindCaller(Subject, OriginalRequestorProcess, &metadata->Binding);
    if (!NT_SUCCESS(status)) goto Exit;
    status = StagePublicBindAnchoredName(metadata, Name, FALSE);
    if (!NT_SUCCESS(status)) goto Exit;
    status = StagePublicReadIdentity(Instance, metadata->RootObject, TRUE, &identity, NULL);
    if (!NT_SUCCESS(status)) goto Exit;
    if (!RtlEqualMemory(&identity, &metadata->Binding.VolumeRootIdentity, sizeof(identity))) {
        status = STATUS_FILE_INVALID; goto Exit;
    }
    status = StagePublicReadIdentity(Instance, metadata->ParentObject, TRUE, &identity, &sensitive);
    if (!NT_SUCCESS(status)) goto Exit;
    if (!RtlEqualMemory(&identity, &metadata->Binding.ParentIdentity, sizeof(identity)) ||
        sensitive != metadata->Binding.ParentCaseSensitive) { status = STATUS_FILE_INVALID; goto Exit; }
    status = SafeUploadStagePublicReadMountGuid(Instance, &volumeId);
    if (!NT_SUCCESS(status)) goto Exit;
    if (!RtlEqualMemory(&volumeId, &metadata->Binding.MountManagerVolumeId, sizeof(volumeId))) {
        status = STATUS_FILE_INVALID; goto Exit;
    }
    /* All directory handles close before the original app CREATE. Their
     * temporary lifetime is not exported as a public-file capability. */
    RtlCopyMemory(Binding, &metadata->Binding, sizeof(*Binding));
Exit:
    SafeUploadStagePublicDereferenceBackend(metadata);
    if (!NT_SUCCESS(status)) RtlZeroMemory(Binding, sizeof(*Binding));
    return status;
}

_Use_decl_annotations_
static NTSTATUS StagePublicOpenBackend(PFLT_INSTANCE Instance, PUNICODE_STRING PublicName,
    PSECURITY_CLIENT_CONTEXT Subject, PEPROCESS OriginalRequestorProcess,
    ACCESS_MASK OriginalDesiredAccess, ULONG OriginalShareAccess,
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
    if (Instance == NULL || PublicName == NULL || Subject == NULL || Subject->ClientToken == NULL ||
        OriginalRequestorProcess == NULL || PublicName->Buffer == NULL ||
        PublicName->Length == 0 || (PublicName->Length & 1) != 0 || PublicName->Length > SAFEUPLOAD_MAX_PATH_BYTES ||
        PublicName->Length > PublicName->MaximumLength ||
        OriginalShareAccess > (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE) ||
        FlagOn(OriginalCreateOptions, 0xff000000 | FILE_DIRECTORY_FILE | FILE_OPEN_BY_FILE_ID) ||
        IoGetTopLevelIrp() != NULL || !PsIsSystemThread(PsGetCurrentThread()) ||
        PsGetCurrentProcess() != PsInitialSystemProcess)
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
    if (instanceContext->VolumeKind != SafeUploadVolumeFixed || instanceContext->FileSystemType != FLT_FSTYPE_NTFS ||
        instanceContext->DeviceInformationStatus != STATUS_SUCCESS || instanceContext->StorageDeviceType != FILE_DEVICE_DISK ||
        FlagOn(instanceContext->StorageDeviceCharacteristics, FILE_PORTABLE_DEVICE | FILE_REMOVABLE_MEDIA | FILE_REMOTE_DEVICE))
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
    status = SafeUploadStagePublicReadMountGuid(Instance, &result->Binding.MountManagerVolumeId);
    if (!NT_SUCCESS(status)) goto Exit;
    result->Binding.OriginalDesiredAccess = OriginalDesiredAccess;
    result->Binding.OriginalShareAccess = OriginalShareAccess;
    status = StagePublicBindCaller(Subject, OriginalRequestorProcess, &result->Binding);
    if (!NT_SUCCESS(status)) goto Exit;
    status = SeImpersonateClientEx(Subject, NULL);
    if (!NT_SUCCESS(status)) goto Exit;
    impersonating = TRUE;
    InitializeObjectAttributes(&attributes, PublicName,
        OBJ_KERNEL_HANDLE | OBJ_FORCE_ACCESS_CHECK | OBJ_DONT_REPARSE |
        (CaseSensitiveOpen ? 0 : OBJ_CASE_INSENSITIVE), NULL, NULL);
    /* Do not truncate/create and do not grant DELETE_ON_CLOSE before the
     * durable handle intent exists. Original access and sharing stay intact;
     * there is no IO_IGNORE_SHARE_ACCESS_CHECK or service-account fallback.
     * Preserve an original backup-intent option (shell opens can use it), but
     * never add that option or enable a backup/restore privilege. Any native
     * privilege check uses only the captured caller's effective token. */
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
    status = StagePublicBindAnchoredName(result, name, TRUE);
    if (!NT_SUCCESS(status)) goto Exit;
    if (result->Binding.PublicIdentity.VolumeSerialNumber != result->Binding.ParentIdentity.VolumeSerialNumber) {
        status = STATUS_NOT_SAME_DEVICE;
        goto Exit;
    }
    FltAcquirePushLockExclusive(&StagePublicListLock);
    result->Counted = TRUE;
    InsertTailList(&StagePublicBackends, &result->Link);
    InterlockedIncrement(&StagePublicBackendCount);
    KeClearEvent(&StagePublicDrained);
    FltReleasePushLock(&StagePublicListLock);
    *Backend = result;
    result = NULL;
Exit:
    if (impersonating) SeStopImpersonatingClient();
    if (name != NULL) FltReleaseFileNameInformation(name);
    SafeUploadStagePublicDereferenceBackend(result);
    return status;
}
_Use_decl_annotations_
NTSTATUS SafeUploadStagePublicOpenBackend(PFLT_INSTANCE Instance, PUNICODE_STRING PublicName,
    PSECURITY_CLIENT_CONTEXT Subject, PEPROCESS OriginalRequestorProcess,
    ACCESS_MASK OriginalDesiredAccess, ULONG OriginalShareAccess,
    ULONG OriginalCreateOptions, BOOLEAN CaseSensitiveOpen, PSAFEUPLOAD_STAGE_PUBLIC_BACKEND *Backend)
{
    PSAFEUPLOAD_STAGE_PUBLIC_BACKEND backend = NULL;
    NTSTATUS status;
    PAGED_CODE();
    if (Backend == NULL) return STATUS_INVALID_PARAMETER;
    *Backend = NULL;
    if (!StagePublicBeginOpen()) return STATUS_FLT_DELETING_OBJECT;
    if (SafeUploadStageMandatoryTeardownActive()) status = STATUS_FLT_DELETING_OBJECT;
    else status = StagePublicOpenBackend(Instance, PublicName, Subject, OriginalRequestorProcess,
        OriginalDesiredAccess, OriginalShareAccess, OriginalCreateOptions, CaseSensitiveOpen, &backend);
    if (NT_SUCCESS(status) && SafeUploadStageMandatoryTeardownActive())
        status = STATUS_FLT_DELETING_OBJECT;
    if (NT_SUCCESS(status)) *Backend = backend;
    else SafeUploadStagePublicDereferenceBackend(backend);
    StagePublicEndOpen();
    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
static VOID StageWriterFreeAnchor(_Inout_ PSTAGE_WRITER_ANCHOR Anchor);
_IRQL_requires_(PASSIVE_LEVEL)
static VOID StageWriterFreeSnapshot(_In_opt_ PSTAGE_WRITER_SNAPSHOT Snapshot);
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageWriterFullId(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT Object,
    _Out_ PFILE_ID_INFORMATION Identity);
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageWriterReadSecurity(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT Object,
    _Outptr_result_nullonfailure_ PSECURITY_DESCRIPTOR *Security, _Out_ PULONG Bytes);
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageWriterOpenAnchor(_In_ PFLT_INSTANCE Instance, _In_opt_ HANDLE Root,
    _In_ PUNICODE_STRING Component, _In_ BOOLEAN Directory, _In_ BOOLEAN CaseSensitive,
    _Inout_ PSTAGE_WRITER_ANCHOR Anchor);
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageWriterCheckLink(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT Parent,
    _In_ PUNICODE_STRING Leaf, _In_ const FILE_ID_INFORMATION *Identity);
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageWriterCaptureSnapshot(_In_ PSAFEUPLOAD_STAGE_WRITER_LEASE Lease,
    _In_ PFILE_OBJECT Source, _Outptr_result_nullonfailure_ PSTAGE_WRITER_SNAPSHOT *Snapshot,
    _Out_ SAFEUPLOAD_STAGE_WRITER_REFUSAL *Reason);
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN StageWriterEqualSnapshots(_In_ const STAGE_WRITER_SNAPSHOT *Left,
    _In_ const STAGE_WRITER_SNAPSHOT *Right);
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageWriterCopyInput(_In_ const SAFEUPLOAD_STAGE_CREATE_INPUT *Input,
    _Inout_ PSAFEUPLOAD_STAGE_CREATE_INPUT Copy);
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageWriterOpenOriginal(_In_ PSAFEUPLOAD_STAGE_WRITER_LEASE Lease,
    _In_ ACCESS_MASK Desired, _Out_ PHANDLE Handle,
    _Outptr_result_nullonfailure_ PFILE_OBJECT *Object);
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageWriterValidateRequest(_In_ const SAFEUPLOAD_STAGE_CREATE_INPUT *Input,
    _In_ PSECURITY_CLIENT_CONTEXT Subject, _Out_ PACCESS_MASK CheckAccess,
    _Out_ SAFEUPLOAD_STAGE_WRITER_REFUSAL *Reason);
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN StageWriterProcessRunning(_In_ HANDLE ProcessHandle);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, StageWriterCloseHandles)
#pragma alloc_text(PAGE, StageWriterFree)
#pragma alloc_text(PAGE, StageWriterFreeAnchor)
#pragma alloc_text(PAGE, StageWriterFreeSnapshot)
#pragma alloc_text(PAGE, StageWriterFullId)
#pragma alloc_text(PAGE, StageWriterReadSecurity)
#pragma alloc_text(PAGE, StageWriterOpenAnchor)
#pragma alloc_text(PAGE, StageWriterCheckLink)
#pragma alloc_text(PAGE, StageWriterCaptureSnapshot)
#pragma alloc_text(PAGE, StageWriterEqualSnapshots)
#pragma alloc_text(PAGE, StageWriterCopyInput)
#pragma alloc_text(PAGE, StageWriterOpenOriginal)
#pragma alloc_text(PAGE, StageWriterValidateRequest)
#pragma alloc_text(PAGE, StageWriterProcessRunning)
#pragma alloc_text(PAGE, SafeUploadStagePublicOpenWriter)
#pragma alloc_text(PAGE, SafeUploadStagePublicReleaseWriter)
#pragma alloc_text(PAGE, SafeUploadStagePublicRevalidateWriter)
#pragma alloc_text(PAGE, SafeUploadStagePublicCheckWriterSecurity)
#endif

_Use_decl_annotations_
static VOID StageWriterFreeAnchor(PSTAGE_WRITER_ANCHOR Anchor)
{
    PAGED_CODE();
    StagePublicCloseObject(&Anchor->Handle, &Anchor->Object);
    if (Anchor->Security != NULL) ExFreePoolWithTag(Anchor->Security, STAGE_PUBLIC_TAG);
    Anchor->Security = NULL;
}

_Use_decl_annotations_
static VOID StageWriterFreeSnapshot(PSTAGE_WRITER_SNAPSHOT Snapshot)
{
    ULONG index;
    PAGED_CODE();
    if (Snapshot == NULL) return;
    for (index = 0; index < Snapshot->Count; ++index) StageWriterFreeAnchor(&Snapshot->Anchors[index]);
    if (Snapshot->Name.Buffer != NULL) ExFreePoolWithTag(Snapshot->Name.Buffer, STAGE_PUBLIC_TAG);
    ExFreePoolWithTag(Snapshot, STAGE_PUBLIC_TAG);
}

_Use_decl_annotations_
static VOID StageWriterCloseHandles(PSAFEUPLOAD_STAGE_WRITER_LEASE Lease)
{
    ULONG index;
    PAGED_CODE();
    /* Operation rundown completed; no reader can still dereference these
     * metadata objects. Keep immutable evidence until the last lease owner. */
    if (Lease->Metadata != NULL) {
        ExFreePoolWithTag(Lease->Metadata, STAGE_PUBLIC_TAG);
        Lease->Metadata = NULL;
    }
    if (Lease->Snapshot != NULL) {
        for (index = 0; index < Lease->Snapshot->Count; ++index) {
            PSTAGE_WRITER_ANCHOR anchor = &Lease->Snapshot->Anchors[index];
            StagePublicCloseObject(&anchor->Handle, &anchor->Object);
        }
    }
    SafeUploadStagePublicCloseCreateLookup(&Lease->Input);
    SafeUploadStagePublicFreeCreateLookup(&Lease->Input);
    if (Lease->ProcessHandle != NULL) {
        ZwClose(Lease->ProcessHandle);
        Lease->ProcessHandle = NULL;
    }
}

_Use_decl_annotations_
static VOID StageWriterFree(PSAFEUPLOAD_STAGE_WRITER_LEASE Lease)
{
    PAGED_CODE();
    StageWriterFreeSnapshot(Lease->Snapshot);
    if (Lease->ConstructionSecurity != NULL)
        ExFreePoolWithTag(Lease->ConstructionSecurity, STAGE_PUBLIC_TAG);
    if (Lease->ExpectedStoredSecurity != NULL)
        ExFreePoolWithTag(Lease->ExpectedStoredSecurity, STAGE_PUBLIC_TAG);
    if (Lease->Input.Security != NULL) ExFreePoolWithTag(Lease->Input.Security, STAGE_PUBLIC_TAG);
    if (Lease->Input.EaBuffer != NULL) ExFreePoolWithTag(Lease->Input.EaBuffer, STAGE_PUBLIC_TAG);
    /* Own reference to the immutable STATIC token, not another token capture
     * or a new SeCreateClientSecurityFromSubjectContext result. */
    if (Lease->SubjectValid) ObDereferenceObject(Lease->Subject.ClientToken);
    if (Lease->Process != NULL) ObDereferenceObject(Lease->Process);
}

_Use_decl_annotations_
static NTSTATUS StageWriterFullId(PFLT_INSTANCE Instance, PFILE_OBJECT Object,
    PFILE_ID_INFORMATION Identity)
{
    static const FILE_ID_128 zero = {0};
    ULONG returned = 0;
    NTSTATUS status;
    PAGED_CODE();
    RtlZeroMemory(Identity, sizeof(*Identity));
    /* FIRST query on the original lease: no READ_ATTRIBUTES prerequisite. */
    status = FltQueryInformationFile(Instance, Object, Identity, sizeof(*Identity),
        FileIdInformation, &returned);
    if (status != STATUS_SUCCESS || returned != sizeof(*Identity) ||
        RtlEqualMemory(&Identity->FileId, &zero, sizeof(zero))) {
        RtlZeroMemory(Identity, sizeof(*Identity));
        return status != STATUS_SUCCESS ? status : STATUS_FILE_INVALID;
    }
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS StageWriterReadSecurity(PFLT_INSTANCE Instance, PFILE_OBJECT Object,
    PSECURITY_DESCRIPTOR *Security, PULONG Bytes)
{
    PSECURITY_DESCRIPTOR buffer = NULL;
    ULONG needed = 0, returned = 0;
    NTSTATUS status;
    PAGED_CODE();
    *Security = NULL;
    *Bytes = 0;
    status = FltQuerySecurityObject(Instance, Object, STAGE_WRITER_SECURITY_INFORMATION,
        NULL, 0, &needed);
    if (status != STATUS_BUFFER_TOO_SMALL) return NT_SUCCESS(status) ? STATUS_INVALID_SECURITY_DESCR : status;
    if (needed < sizeof(SECURITY_DESCRIPTOR_RELATIVE) || needed > STAGE_WRITER_STORED_SECURITY_LIMIT)
        return STATUS_INVALID_BUFFER_SIZE;
    buffer = ExAllocatePool2(POOL_FLAG_PAGED, needed, STAGE_PUBLIC_TAG);
    if (buffer == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    status = FltQuerySecurityObject(Instance, Object, STAGE_WRITER_SECURITY_INFORMATION,
        buffer, needed, &returned);
    if (status == STATUS_SUCCESS && (returned < sizeof(SECURITY_DESCRIPTOR_RELATIVE) || returned > needed ||
        !RtlValidRelativeSecurityDescriptor(buffer, returned,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION)))
        status = STATUS_INVALID_SECURITY_DESCR;
    if (status != STATUS_SUCCESS && NT_SUCCESS(status)) status = STATUS_NOT_SUPPORTED;
    if (status == STATUS_SUCCESS) {
        /* Preserve original binary controls, RM byte, SID/ACL bytes and order.
         * Byte equality may conservatively refuse representation differences;
         * it cannot erase meaningful construction or stored flags. */
        *Security = buffer;
        *Bytes = returned;
    } else {
        ExFreePoolWithTag(buffer, STAGE_PUBLIC_TAG);
    }
    return status;
}

_Use_decl_annotations_
static NTSTATUS StageWriterOpenAnchor(PFLT_INSTANCE Instance, HANDLE Root,
    PUNICODE_STRING Component, BOOLEAN Directory, BOOLEAN CaseSensitive,
    PSTAGE_WRITER_ANCHOR Anchor)
{
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io = {0};
    FILE_CASE_SENSITIVE_INFORMATION caseInfo = {0};
    ULONG returned = 0;
    NTSTATUS status;
    PAGED_CODE();
    InitializeObjectAttributes(&attributes, Component, OBJ_KERNEL_HANDLE | OBJ_DONT_REPARSE |
        (CaseSensitive ? 0 : OBJ_CASE_INSENSITIVE), Root, NULL);
    /* Metadata observer only, never data/delete authority. No privilege
     * adjustment and no share bypass. A missing full-query privilege is a
     * refusal, never permission to fall back to owner/group/DACL only. */
    status = FltCreateFileEx2(SafeUploadData.Filter, Instance, &Anchor->Handle, &Anchor->Object,
        READ_CONTROL | ACCESS_SYSTEM_SECURITY | FILE_READ_ATTRIBUTES |
            (Directory ? FILE_LIST_DIRECTORY : 0),
        &attributes, &io, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN, (Directory ? FILE_DIRECTORY_FILE : FILE_NON_DIRECTORY_FILE) | FILE_OPEN_REPARSE_POINT,
        NULL, 0, IO_STOP_ON_SYMLINK, NULL);
    if (status == STATUS_STOPPED_ON_SYMLINK && io.Information != 0) ExFreePool((PVOID)io.Information);
    if (status != STATUS_SUCCESS) return status;
    if (io.Status != STATUS_SUCCESS || io.Information != FILE_OPENED || Anchor->Object == NULL || Anchor->Handle == NULL)
        return STATUS_FILE_INVALID;
    status = StageWriterFullId(Instance, Anchor->Object, &Anchor->Identity);
    if (status != STATUS_SUCCESS) return status;
    status = FltQueryInformationFile(Instance, Anchor->Object, &Anchor->Attributes,
        sizeof(Anchor->Attributes), FileAttributeTagInformation, &returned);
    if (status != STATUS_SUCCESS) return status;
    if (returned != sizeof(Anchor->Attributes) || Anchor->Attributes.ReparseTag != 0 ||
        FlagOn(Anchor->Attributes.FileAttributes, FILE_ATTRIBUTE_REPARSE_POINT) ||
        BooleanFlagOn(Anchor->Attributes.FileAttributes, FILE_ATTRIBUTE_DIRECTORY) != Directory)
        return STATUS_REPARSE_POINT_ENCOUNTERED;
    status = FltQueryInformationFile(Instance, Anchor->Object, &Anchor->Basic,
        sizeof(Anchor->Basic), FileBasicInformation, &returned);
    if (status != STATUS_SUCCESS) return status;
    if (returned != sizeof(Anchor->Basic)) return STATUS_INVALID_BUFFER_SIZE;
    status = FltQueryInformationFile(Instance, Anchor->Object, &Anchor->Standard,
        sizeof(Anchor->Standard), FileStandardInformation, &returned);
    if (status != STATUS_SUCCESS) return status;
    if (returned != sizeof(Anchor->Standard) || Anchor->Standard.Directory != Directory ||
        Anchor->Standard.DeletePending) return STATUS_FILE_INVALID;
    if (Directory) {
        status = FltQueryInformationFile(Instance, Anchor->Object, &caseInfo,
            sizeof(caseInfo), FileCaseSensitiveInformation, &returned);
        if (status != STATUS_SUCCESS) return status;
        if (returned != sizeof(caseInfo) || FlagOn(caseInfo.Flags, ~FILE_CS_FLAG_CASE_SENSITIVE_DIR))
            return STATUS_NOT_SUPPORTED;
        Anchor->CaseSensitive = BooleanFlagOn(caseInfo.Flags, FILE_CS_FLAG_CASE_SENSITIVE_DIR);
    }
    return StageWriterReadSecurity(Instance, Anchor->Object, &Anchor->Security, &Anchor->SecurityBytes);
}

_Use_decl_annotations_
static NTSTATUS StageWriterCheckLink(PFLT_INSTANCE Instance, PFILE_OBJECT Parent,
    PUNICODE_STRING Leaf, const FILE_ID_INFORMATION *Identity)
{
    PFILE_ID_EXTD_DIR_INFORMATION entry;
    const ULONG prefix = FIELD_OFFSET(FILE_ID_EXTD_DIR_INFORMATION, FileName);
    const ULONG bytes = FIELD_OFFSET(FILE_ID_EXTD_DIR_INFORMATION, FileName) + 255 * sizeof(WCHAR);
    ULONG returned = 0;
    BOOLEAN restart = TRUE, found = FALSE;
    NTSTATUS status;
    PAGED_CODE();
    entry = ExAllocatePool2(POOL_FLAG_PAGED, bytes, STAGE_PUBLIC_TAG);
    if (entry == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    /* Complete scan, no wildcard filter, no short/truncated result treated as
     * absence. The normalized object's exact long component is the selector. */
    for (;;) {
        UNICODE_STRING actual;
        if (SafeUploadStageMandatoryTeardownActive()) { status = STATUS_FLT_DELETING_OBJECT; break; }
        status = FltQueryDirectoryFile(Instance, Parent, entry, bytes,
            FileIdExtdDirectoryInformation, TRUE, NULL, restart, &returned);
        restart = FALSE;
        if (status == STATUS_NO_MORE_FILES) { status = found ? STATUS_SUCCESS : STATUS_FILE_INVALID; break; }
        if (status != STATUS_SUCCESS) break;
        if (returned < prefix || returned > bytes || entry->NextEntryOffset != 0 ||
            entry->FileNameLength == 0 || (entry->FileNameLength & 1) != 0 ||
            entry->FileNameLength > returned - prefix) { status = STATUS_FILE_INVALID; break; }
        actual.Buffer = entry->FileName;
        actual.Length = (USHORT)entry->FileNameLength;
        actual.MaximumLength = actual.Length;
        if (!RtlEqualUnicodeString(&actual, Leaf, FALSE)) continue;
        if (found || !RtlEqualMemory(&entry->FileId, &Identity->FileId, sizeof(FILE_ID_128)) ||
            FlagOn(entry->FileAttributes, FILE_ATTRIBUTE_REPARSE_POINT)) { status = STATUS_FILE_INVALID; break; }
        found = TRUE;
    }
    ExFreePoolWithTag(entry, STAGE_PUBLIC_TAG);
    return status;
}

_Use_decl_annotations_
static NTSTATUS StageWriterCaptureSnapshot(PSAFEUPLOAD_STAGE_WRITER_LEASE Lease, PFILE_OBJECT Source,
    PSTAGE_WRITER_SNAPSHOT *Snapshot, SAFEUPLOAD_STAGE_WRITER_REFUSAL *Reason)
{
    PFLT_FILE_NAME_INFORMATION name = NULL;
    PSTAGE_WRITER_SNAPSHOT result = NULL;
    FILE_ID_INFORMATION sourceIdentity, lookupIdentity;
    STAGE_WRITER_ANCHOR local;
    ULONG cursor, end, chars, index;
    BOOLEAN lookupFound, localOwned = FALSE;
    NTSTATUS status;
    PAGED_CODE();
    RtlZeroMemory(&local, sizeof(local));
    *Snapshot = NULL;
    *Reason = StageWriterMetadataUnproved;
    status = StageWriterFullId(Lease->Lifetime.Instance, Source, &sourceIdentity);
    if (status != STATUS_SUCCESS) goto Exit;
    status = FltGetFileNameInformationUnsafe(Source, Lease->Lifetime.Instance,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY, &name);
    if (status != STATUS_SUCCESS) goto Exit;
    status = FltParseFileNameInformation(name);
    if (status != STATUS_SUCCESS) goto Exit;
    *Reason = StageWriterLookupUnproved;
    if (name->Volume.Length == 0 || name->Stream.Length != 0 || name->FinalComponent.Length == 0 ||
        name->FinalComponent.Length > 255 * sizeof(WCHAR) || (name->Name.Length & 1) != 0 ||
        name->Name.Length > SAFEUPLOAD_MAX_PATH_BYTES ||
        name->Volume.Length + sizeof(WCHAR) >= name->Name.Length ||
        name->Name.Buffer[name->Volume.Length / sizeof(WCHAR)] != L'\\') {
        status = STATUS_OBJECT_PATH_INVALID; goto Exit;
    }
    result = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*result), STAGE_PUBLIC_TAG);
    if (result == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    RtlZeroMemory(result, sizeof(*result));
    result->Name.Buffer = ExAllocatePool2(POOL_FLAG_PAGED, name->Name.Length, STAGE_PUBLIC_TAG);
    if (result->Name.Buffer == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    result->Name.Length = result->Name.MaximumLength = name->Name.Length;
    RtlCopyMemory(result->Name.Buffer, name->Name.Buffer, name->Name.Length);
    status = SafeUploadStagePublicReadMountGuid(Lease->Lifetime.Instance, &result->MountId);
    if (status != STATUS_SUCCESS) goto Exit;
    chars = result->Name.Length / sizeof(WCHAR);
    cursor = 0;
    end = name->Volume.Length / sizeof(WCHAR) + 1;
    while (cursor < chars) {
        PSTAGE_WRITER_ANCHOR anchor, parent = NULL;
        UNICODE_STRING component;
        BOOLEAN directory = end != chars;
        if (result->Count == STAGE_WRITER_MAX_ANCHORS) {
            *Reason = StageWriterCaptureLimit; status = STATUS_QUOTA_EXCEEDED; goto Exit;
        }
        if (result->Count != 0) parent = &result->Anchors[result->Count - 1];
        /* Fill a fully initialized local and publish it into the counted array
         * only when complete; a failed component is released through `local`. */
        anchor = &local;
        RtlZeroMemory(anchor, sizeof(*anchor));
        localOwned = TRUE;
        anchor->ComponentOffset = (USHORT)(cursor * sizeof(WCHAR));
        anchor->ComponentBytes = (USHORT)((end - cursor) * sizeof(WCHAR));
        component.Buffer = &result->Name.Buffer[cursor];
        component.Length = component.MaximumLength = anchor->ComponentBytes;
        if (component.Length == 0) { status = STATUS_OBJECT_PATH_INVALID; goto Exit; }
        *Reason = StageWriterMetadataUnproved;
        status = StageWriterOpenAnchor(Lease->Lifetime.Instance, parent != NULL ? parent->Handle : NULL,
            &component, directory, parent != NULL ? parent->CaseSensitive : FALSE, anchor);
        if (status != STATUS_SUCCESS) goto Exit;
        if (anchor->Identity.VolumeSerialNumber != sourceIdentity.VolumeSerialNumber) {
            status = STATUS_NOT_SAME_DEVICE; goto Exit;
        }
        if (parent != NULL) {
            status = StageWriterCheckLink(Lease->Lifetime.Instance, parent->Object, &component, &anchor->Identity);
            if (status != STATUS_SUCCESS) goto Exit;
        }
        if (anchor->SecurityBytes > STAGE_WRITER_SECURITY_BUDGET - result->SecurityBytes) {
            *Reason = StageWriterCaptureLimit; status = STATUS_QUOTA_EXCEEDED; goto Exit;
        }
        result->SecurityBytes += anchor->SecurityBytes;
        result->Anchors[result->Count] = local;
        ++result->Count;
        localOwned = FALSE;
        RtlZeroMemory(&local, sizeof(local));
        cursor = end;
        if (cursor < chars && result->Name.Buffer[cursor] == L'\\') ++cursor;
        end = cursor;
        while (end < chars && result->Name.Buffer[end] != L'\\') ++end;
    }
    if (result->Count < 2 || !RtlEqualMemory(&sourceIdentity,
        &result->Anchors[result->Count - 1].Identity, sizeof(sourceIdentity))) {
        *Reason = StageWriterSnapshotChanged; status = STATUS_FILE_INVALID; goto Exit;
    }
    if (Lease->Input.LookupById && result->Anchors[result->Count - 1].Standard.NumberOfLinks != 1) {
        *Reason = StageWriterLookupUnproved; status = STATUS_NOT_SUPPORTED; goto Exit;
    }
    /* Bind the original retained relative root to this ancestor chain, rather
     * than substituting a same-ID hard link elsewhere. A raw-volume root that
     * cannot return a full identity is an explicit lookup refusal. */
    lookupFound = Lease->Input.LookupRoot == NULL;
    if (!lookupFound) {
        *Reason = StageWriterLookupUnproved;
        status = StageWriterFullId(Lease->Lifetime.Instance, Lease->Input.LookupRoot, &lookupIdentity);
        if (status != STATUS_SUCCESS) goto Exit;
        for (index = 0; index + 1 < result->Count; ++index)
            if (RtlEqualMemory(&lookupIdentity, &result->Anchors[index].Identity, sizeof(lookupIdentity))) lookupFound = TRUE;
    }
    if (!lookupFound) { *Reason = StageWriterLookupUnproved; status = STATUS_FILE_INVALID; goto Exit; }
    *Snapshot = result;
    result = NULL;
    *Reason = StageWriterNoRefusal;
    status = STATUS_SUCCESS;
Exit:
    if (localOwned) StageWriterFreeAnchor(&local);
    if (name != NULL) FltReleaseFileNameInformation(name);
    StageWriterFreeSnapshot(result);
    return status != STATUS_SUCCESS && NT_SUCCESS(status) ? STATUS_NOT_SUPPORTED : status;
}

_Use_decl_annotations_
static BOOLEAN StageWriterEqualSnapshots(const STAGE_WRITER_SNAPSHOT *Left, const STAGE_WRITER_SNAPSHOT *Right)
{
    ULONG index;
    PAGED_CODE();
    if (Left->Count != Right->Count || !RtlEqualUnicodeString(&Left->Name, &Right->Name, FALSE) ||
        !RtlEqualMemory(&Left->MountId, &Right->MountId, sizeof(GUID))) return FALSE;
    for (index = 0; index < Left->Count; ++index) {
        const STAGE_WRITER_ANCHOR *a = &Left->Anchors[index], *b = &Right->Anchors[index];
        if (!RtlEqualMemory(&a->Identity, &b->Identity, sizeof(a->Identity)) ||
            !RtlEqualMemory(&a->Attributes, &b->Attributes, sizeof(a->Attributes)) ||
            !RtlEqualMemory(&a->Basic, &b->Basic, sizeof(a->Basic)) ||
            !RtlEqualMemory(&a->Standard, &b->Standard, sizeof(a->Standard)) ||
            a->CaseSensitive != b->CaseSensitive || a->ComponentOffset != b->ComponentOffset ||
            a->ComponentBytes != b->ComponentBytes || a->SecurityBytes != b->SecurityBytes ||
            !RtlEqualMemory(a->Security, b->Security, a->SecurityBytes)) return FALSE;
    }
    return TRUE;
}

_Use_decl_annotations_
static NTSTATUS StageWriterCopyInput(const SAFEUPLOAD_STAGE_CREATE_INPUT *Input, PSAFEUPLOAD_STAGE_CREATE_INPUT Copy)
{
    NTSTATUS status;
    PAGED_CODE();
    *Copy = *Input;
    Copy->LookupName.Buffer = NULL;
    Copy->LookupName.MaximumLength = Input->LookupName.Length;
    Copy->LookupRoot = NULL;
    Copy->LookupRootHandle = NULL;
    Copy->EaBuffer = NULL;
    Copy->Security = NULL;
    Copy->LookupName.Buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, Input->LookupName.Length, STAGE_PUBLIC_TAG);
    if (Copy->LookupName.Buffer == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(Copy->LookupName.Buffer, Input->LookupName.Buffer, Input->LookupName.Length);
    if (Input->LookupRoot != NULL) {
        if (Input->LookupRootHandle == NULL || FlagOn(Input->LookupRoot->Flags, FO_CLEANUP_COMPLETE))
            return STATUS_FILE_CLOSED;
        ObReferenceObject(Input->LookupRoot);
        Copy->LookupRoot = Input->LookupRoot;
        status = ObOpenObjectByPointer(Copy->LookupRoot, OBJ_KERNEL_HANDLE, NULL, 0,
            *IoFileObjectType, KernelMode, &Copy->LookupRootHandle);
        if (!NT_SUCCESS(status)) return status;
        if (FlagOn(Copy->LookupRoot->Flags, FO_CLEANUP_COMPLETE)) return STATUS_FILE_CLOSED;
    }
    if (Input->EaLength != 0) {
        Copy->EaBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, Input->EaLength, STAGE_PUBLIC_TAG);
        if (Copy->EaBuffer == NULL) return STATUS_INSUFFICIENT_RESOURCES;
        RtlCopyMemory(Copy->EaBuffer, Input->EaBuffer, Input->EaLength);
    }
    if (Input->SecurityBytes != 0) {
        Copy->Security = ExAllocatePool2(POOL_FLAG_NON_PAGED, Input->SecurityBytes, STAGE_PUBLIC_TAG);
        if (Copy->Security == NULL) return STATUS_INSUFFICIENT_RESOURCES;
        RtlCopyMemory(Copy->Security, Input->Security, Input->SecurityBytes);
    }
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS StageWriterOpenOriginal(PSAFEUPLOAD_STAGE_WRITER_LEASE Lease, ACCESS_MASK Desired,
    PHANDLE Handle, PFILE_OBJECT *Object)
{
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io = {0};
    HANDLE handle = NULL;
    PFILE_OBJECT object = NULL;
    NTSTATUS status;
    PAGED_CODE();
    *Handle = NULL;
    *Object = NULL;
    status = SeImpersonateClientEx(&Lease->Subject, NULL);
    if (status != STATUS_SUCCESS) return NT_SUCCESS(status) ? STATUS_NOT_SUPPORTED : status;
    InitializeObjectAttributes(&attributes, &Lease->Input.LookupName,
        OBJ_KERNEL_HANDLE | OBJ_FORCE_ACCESS_CHECK | OBJ_DONT_REPARSE |
        (FlagOn(Lease->Input.OperationFlags, SL_CASE_SENSITIVE) ? 0 : OBJ_CASE_INSENSITIVE),
        Lease->Input.LookupRootHandle, NULL);
    /* Exact original lookup bytes/root, never Snapshot->Name. No mutation,
     * sharing bypass, token adjustment, creation allocation, EA or SD injection.
     * Unproved option/input transformations are refused before this call. */
    status = FltCreateFileEx2(SafeUploadData.Filter, Lease->Lifetime.Instance, &handle, &object,
        Desired, &attributes, &io, NULL, 0, Lease->Input.ShareAccess, FILE_OPEN,
        (Lease->Input.Options & 0x00ffffff) | FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
        NULL, 0, IO_STOP_ON_SYMLINK, NULL);
    SeStopImpersonatingClient();
    if (status == STATUS_STOPPED_ON_SYMLINK && io.Information != 0) ExFreePool((PVOID)io.Information);
    if (status == STATUS_SUCCESS && (io.Status != STATUS_SUCCESS || io.Information != FILE_OPENED ||
        handle == NULL || object == NULL)) status = STATUS_FILE_INVALID;
    /* Informational CREATE results are not completed leases. Preserve all
     * native failure statuses; never report an unowned pointer as success. */
    if (status != STATUS_SUCCESS && NT_SUCCESS(status)) status = STATUS_NOT_SUPPORTED;
    if (status != STATUS_SUCCESS) {
        StagePublicCloseObject(&handle, &object);
    } else {
        /* Transfer only a validated lease. Failure outputs stay NULL even
         * when the native open or a later consistency check fails. */
        *Handle = handle;
        *Object = object;
    }
    return status;
}

_Use_decl_annotations_
static NTSTATUS StageWriterValidateRequest(const SAFEUPLOAD_STAGE_CREATE_INPUT *Input,
    PSECURITY_CLIENT_CONTEXT Subject, PACCESS_MASK CheckAccess, SAFEUPLOAD_STAGE_WRITER_REFUSAL *Reason)
{
    const ULONG options = FILE_WRITE_THROUGH | FILE_SEQUENTIAL_ONLY | FILE_RANDOM_ACCESS |
        FILE_NO_INTERMEDIATE_BUFFERING | FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT |
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_BY_FILE_ID;
    PTOKEN_PRIVILEGES privileges = NULL;
    ACCESS_MASK original, remaining, desired;
    ULONG index, disposition = Input->Options >> 24;
    NTSTATUS status;
    PAGED_CODE();
    *CheckAccess = 0;
    *Reason = StageWriterSubjectUnrepresentable;
    if (Subject->ClientToken == NULL || Subject->DirectlyAccessClientToken ||
        Subject->SecurityQos.ContextTrackingMode != SECURITY_STATIC_TRACKING ||
        Subject->SecurityQos.ImpersonationLevel < SecurityImpersonation)
        return STATUS_BAD_IMPERSONATION_LEVEL;
    *Reason = StageWriterLookupUnproved;
    if (Input->LookupName.Buffer == NULL || Input->LookupName.Length == 0 ||
        Input->LookupName.Length > Input->LookupName.MaximumLength ||
        Input->LookupName.Length > SAFEUPLOAD_MAX_PATH_BYTES) return STATUS_OBJECT_PATH_INVALID;
    if (Input->LookupById != BooleanFlagOn(Input->Options, FILE_OPEN_BY_FILE_ID)) return STATUS_INVALID_PARAMETER;
    if (Input->LookupById) {
        /* Never parse a binary selector as Unicode or replace its original
         * root with a normalized pathname. Other ID forms stay unproved. */
        if (Input->LookupRoot == NULL || Input->LookupRootHandle == NULL ||
            (Input->LookupName.Length != sizeof(LONGLONG) && Input->LookupName.Length != sizeof(FILE_ID_128)))
            return STATUS_NOT_SUPPORTED;
    } else {
        if ((Input->LookupName.Length & 1) != 0) return STATUS_OBJECT_PATH_INVALID;
        for (index = 0; index < Input->LookupName.Length / sizeof(WCHAR); ++index) {
            WCHAR ch = Input->LookupName.Buffer[index];
            if (ch < 32 || ch == L':' || ch == L'*' || ch == L'?' || ch == L'"' ||
                ch == L'<' || ch == L'>' || ch == L'|') return STATUS_OBJECT_PATH_INVALID;
        }
    }
    *Reason = StageWriterCreateSemanticsUnproved;
    if (Input->RequestorMode != UserMode || Input->PreviouslyGrantedAccess != 0 ||
        FlagOn(Input->OperationFlags, ~SL_CASE_SENSITIVE) ||
        FlagOn(Input->Options & 0x00ffffff, ~options) ||
        FlagOn(Input->ShareAccess, ~(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)) ||
        Input->EaLength != 0 || Input->AllocationSize.QuadPart != 0 ||
        FlagOn(Input->FileAttributes, ~(FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_ARCHIVE)) ||
        disposition > FILE_OVERWRITE_IF || disposition == FILE_CREATE)
        return STATUS_NOT_SUPPORTED;
    original = Input->OriginalDesiredAccess;
    remaining = Input->RemainingDesiredAccess;
    desired = Input->DesiredAccess;
    RtlMapGenericMask(&original, IoGetFileObjectGenericMapping());
    RtlMapGenericMask(&remaining, IoGetFileObjectGenericMapping());
    RtlMapGenericMask(&desired, IoGetFileObjectGenericMapping());
    if (original != desired || remaining != desired) return STATUS_NOT_SUPPORTED;
    if (Input->SuppliedSecurity || Input->Security != NULL || Input->SecurityBytes != 0) {
        *Reason = StageWriterNativeCreateSecurityUnproved;
        return STATUS_NOT_SUPPORTED;
    }
    /* The measured supplemental mask is Restore-disabled. Never disable the
     * original privilege to force this candidate to fit the control evidence. */
    status = SeQueryInformationToken(Subject->ClientToken, TokenPrivileges, (PVOID *)&privileges);
    if (!NT_SUCCESS(status)) return status;
    if (privileges == NULL) return STATUS_INVALID_PARAMETER;
    for (index = 0; index < privileges->PrivilegeCount; ++index) {
        if (RtlEqualMemory(&privileges->Privileges[index].Luid, &SeExports->SeRestorePrivilege, sizeof(LUID)) &&
            FlagOn(privileges->Privileges[index].Attributes, SE_PRIVILEGE_ENABLED)) {
            ExFreePool(privileges);
            return STATUS_NOT_SUPPORTED;
        }
    }
    ExFreePool(privileges);
    *CheckAccess = Input->DesiredAccess;
    if (disposition == FILE_SUPERSEDE) *CheckAccess |= DELETE | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES;
    if (disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF)
        *CheckAccess |= FILE_WRITE_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES;
    *Reason = StageWriterNoRefusal;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static BOOLEAN StageWriterProcessRunning(HANDLE ProcessHandle)
{
    LARGE_INTEGER noWait = {0};
    PAGED_CODE();
    /* A process can choose STATUS_PENDING as its exit code. Observe its
     * dispatcher state instead. This instant check never replaces the later
     * namespace/cancellation/lifetime check at the exposure boundary. */
    return ZwWaitForSingleObject(ProcessHandle, FALSE, &noWait) == STATUS_TIMEOUT;
}

_Use_decl_annotations_
NTSTATUS SafeUploadStagePublicOpenWriter(PFLT_INSTANCE Instance, const SAFEUPLOAD_STAGE_CREATE_INPUT *Input,
    PSECURITY_CLIENT_CONTEXT Subject, PEPROCESS OriginalRequestorProcess,
    PSAFEUPLOAD_STAGE_WRITER_LEASE *Lease, SAFEUPLOAD_STAGE_WRITER_REFUSAL *Reason)
{
    PSAFEUPLOAD_STAGE_WRITER_LEASE result = NULL;
    PSAFEUPLOAD_INSTANCE_CONTEXT context = NULL;
    PSTAGE_WRITER_SNAPSHOT checkSnapshot = NULL;
    HANDLE checkHandle = NULL;
    PFILE_OBJECT checkObject = NULL;
    PACCESS_TOKEN oldToken;
    BOOLEAN copyOnOpen, effectiveOnly;
    SECURITY_IMPERSONATION_LEVEL level;
    ACCESS_MASK checkAccess = 0, mappedAccess;
    STAGE_PUBLIC_OBJECT_BASIC_INFORMATION basic = {0};
    ULONG returned = 0, disposition;
    PSTAGE_WRITER_ANCHOR target, parent;
    NTSTATUS status;
    PAGED_CODE();
    *Lease = NULL;
    *Reason = StageWriterNoRefusal;
    if (Instance == NULL || Input == NULL || Subject == NULL || OriginalRequestorProcess == NULL ||
        IoGetTopLevelIrp() != NULL || !PsIsSystemThread(PsGetCurrentThread()) ||
        PsGetCurrentProcess() != PsInitialSystemProcess) return STATUS_INVALID_PARAMETER;
    /* An initially unimpersonated system worker is required. Never revert a
     * pre-existing token belonging to somebody else's operation. */
    oldToken = PsReferenceImpersonationToken(PsGetCurrentThread(), &copyOnOpen, &effectiveOnly, &level);
    if (oldToken != NULL) {
        PsDereferenceImpersonationToken(oldToken);
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!StagePublicBeginOpen()) return STATUS_FLT_DELETING_OBJECT;
    FltAcquirePushLockExclusive(&StagePublicListLock);
    status = StagePublicFactories + InterlockedCompareExchange(&StagePublicBackendCount, 0, 0) > STAGE_WRITER_MAX_LEASES ?
        STATUS_QUOTA_EXCEEDED : STATUS_SUCCESS;
    FltReleasePushLock(&StagePublicListLock);
    if (!NT_SUCCESS(status)) { *Reason = StageWriterCaptureLimit; goto Exit; }
    status = StageWriterValidateRequest(Input, Subject, &checkAccess, Reason);
    if (!NT_SUCCESS(status)) goto Exit;
    status = FltGetInstanceContext(Instance, (PFLT_CONTEXT *)&context);
    if (!NT_SUCCESS(status)) goto Exit;
    if (context->VolumeKind != SafeUploadVolumeFixed || context->FileSystemType != FLT_FSTYPE_NTFS ||
        context->DeviceInformationStatus != STATUS_SUCCESS || context->StorageDeviceType != FILE_DEVICE_DISK ||
        FlagOn(context->StorageDeviceCharacteristics, FILE_PORTABLE_DEVICE | FILE_REMOVABLE_MEDIA | FILE_REMOTE_DEVICE)) {
        status = STATUS_NOT_SUPPORTED; goto Exit;
    }
    result = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*result), STAGE_PUBLIC_TAG);
    if (result == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    /* The common destructor may run after any following acquisition fails. */
    RtlZeroMemory(result, sizeof(*result));
    result->Lifetime.References = 1;
    result->Lifetime.WriterLease = TRUE;
    ExInitializeRundownProtection(&result->Lifetime.Operations);
    KeInitializeEvent(&result->Lifetime.Closed, NotificationEvent, FALSE);
    status = FltObjectReference(Instance);
    if (!NT_SUCCESS(status)) goto Exit;
    result->Lifetime.Instance = Instance;
    ObReferenceObject(OriginalRequestorProcess);
    result->Process = OriginalRequestorProcess;
    status = ObOpenObjectByPointer(result->Process, OBJ_KERNEL_HANDLE, NULL, SYNCHRONIZE,
        *PsProcessType, KernelMode, &result->ProcessHandle);
    if (!NT_SUCCESS(status)) goto Exit;
    result->Subject = *Subject;
    ObReferenceObject(result->Subject.ClientToken); /* retain the original static copy, never recapture */
    result->SubjectValid = TRUE;
    status = StageWriterCopyInput(Input, &result->Input);
    if (!NT_SUCCESS(status)) { *Reason = StageWriterLookupUnproved; goto Exit; }
    status = StagePublicBindCaller(&result->Subject, result->Process, &result->Lifetime.Binding);
    if (!NT_SUCCESS(status)) goto Exit;
    disposition = Input->Options >> 24;
    *Reason = StageWriterNoRefusal;
    status = StageWriterOpenOriginal(result, checkAccess, &checkHandle, &checkObject);
    if (status != STATUS_SUCCESS) {
        /* An unsuccessful open is NOT an absence proof. In particular, do
         * not authorize creation or recheck a prospective creator's new DACL.
         * Preserve native absence failure for noncreating dispositions. */
        if ((status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND) &&
            disposition != FILE_OPEN && disposition != FILE_OVERWRITE) {
            *Reason = StageWriterCreatorGrantUnproved;
            status = STATUS_NOT_SUPPORTED;
        }
        if (status == STATUS_BAD_IMPERSONATION_LEVEL) *Reason = StageWriterSubjectUnrepresentable;
        goto Exit;
    }
    status = StageWriterCaptureSnapshot(result, checkObject, &checkSnapshot, Reason);
    if (status != STATUS_SUCCESS) goto Exit;
    /* Mandatory ordering: close EVERY supplemental/metadata handle and drop
     * its independent object ref before the original-rights/share FILE_OPEN.
     * Keep only immutable comparison bytes across this race window. */
    {
        ULONG index;
        for (index = 0; index < checkSnapshot->Count; ++index)
            StagePublicCloseObject(&checkSnapshot->Anchors[index].Handle, &checkSnapshot->Anchors[index].Object);
    }
    StagePublicCloseObject(&checkHandle, &checkObject);
    if (SafeUploadStageMandatoryTeardownActive()) { status = STATUS_FLT_DELETING_OBJECT; goto Exit; }
    status = StageWriterOpenOriginal(result, Input->DesiredAccess,
        &result->Lifetime.PublicHandle, &result->Lifetime.PublicObject);
    if (status != STATUS_SUCCESS) { *Reason = StageWriterSnapshotChanged; goto Exit; }
    status = StageWriterCaptureSnapshot(result, result->Lifetime.PublicObject, &result->Snapshot, Reason);
    if (status != STATUS_SUCCESS) goto Exit;
    if (!StageWriterEqualSnapshots(checkSnapshot, result->Snapshot)) {
        *Reason = StageWriterSnapshotChanged; status = STATUS_FILE_INVALID; goto Exit;
    }
    *Reason = StageWriterCreateSemanticsUnproved;
    status = ZwQueryObject(result->Lifetime.PublicHandle, ObjectBasicInformation, &basic, sizeof(basic), &returned);
    if (status != STATUS_SUCCESS) goto Exit;
    if (returned != sizeof(basic)) { status = STATUS_INVALID_BUFFER_SIZE; goto Exit; }
    mappedAccess = Input->DesiredAccess;
    RtlMapGenericMask(&mappedAccess, IoGetFileObjectGenericMapping());
    if ((!FlagOn(mappedAccess, MAXIMUM_ALLOWED) && basic.GrantedAccess != mappedAccess) ||
        !FlagOn(basic.GrantedAccess, FILE_WRITE_DATA | FILE_APPEND_DATA)) {
        status = STATUS_NOT_SUPPORTED; goto Exit;
    }
    /* The retained NTFS lease's grant is never widened or overwritten. Only
     * the projected future staged-data grant excludes T10 security mutators. */
    result->Lifetime.Binding.OriginalDesiredAccess = Input->OriginalDesiredAccess;
    result->NativeGrantedAccess = basic.GrantedAccess;
    result->Lifetime.Binding.OriginalShareAccess = Input->ShareAccess;
    result->Lifetime.Binding.GrantedAccess = basic.GrantedAccess & ~(WRITE_DAC | WRITE_OWNER | ACCESS_SYSTEM_SECURITY);
    target = &result->Snapshot->Anchors[result->Snapshot->Count - 1];
    parent = &result->Snapshot->Anchors[result->Snapshot->Count - 2];
    result->Lifetime.Binding.MountManagerVolumeId = result->Snapshot->MountId;
    result->Lifetime.Binding.VolumeRootIdentity = result->Snapshot->Anchors[0].Identity;
    result->Lifetime.Binding.ParentIdentity = parent->Identity;
    result->Lifetime.Binding.ParentCaseSensitive = parent->CaseSensitive;
    result->Lifetime.Binding.PublicIdentity = target->Identity;
    result->Lifetime.Binding.CanonicalLeafBytes = target->ComponentBytes;
    RtlCopyMemory(result->Lifetime.Binding.CanonicalLeaf,
        (PUCHAR)result->Snapshot->Name.Buffer + target->ComponentOffset, target->ComponentBytes);
    result->ExpectedStoredSecurity = ExAllocatePool2(POOL_FLAG_PAGED, target->SecurityBytes, STAGE_PUBLIC_TAG);
    if (result->ExpectedStoredSecurity == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    RtlCopyMemory(result->ExpectedStoredSecurity, target->Security, target->SecurityBytes);
    result->ExpectedStoredSecurityBytes = target->SecurityBytes;
    /* Not FILE_OPENED merely because both probes use FILE_OPEN. This remains
     * a candidate app result until the CREATE semantics gate is qualified. */
    result->OriginalInformation = disposition == FILE_SUPERSEDE ? FILE_SUPERSEDED :
        ((disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF) ? FILE_OVERWRITTEN : FILE_OPENED);
    if (SafeUploadStageMandatoryTeardownActive() || !StageWriterProcessRunning(result->ProcessHandle)) {
        status = STATUS_CANCELLED; goto Exit;
    }
    FltAcquirePushLockExclusive(&StagePublicListLock);
    result->Lifetime.Counted = TRUE;
    InsertTailList(&StagePublicBackends, &result->Lifetime.Link);
    InterlockedIncrement(&StagePublicBackendCount);
    KeClearEvent(&StagePublicDrained);
    FltReleasePushLock(&StagePublicListLock);
    *Lease = result; /* one caller reference; list is a lookup, not another owner */
    result = NULL;
    *Reason = StageWriterNoRefusal;
    status = STATUS_SUCCESS;
Exit:
    StagePublicCloseObject(&checkHandle, &checkObject);
    StageWriterFreeSnapshot(checkSnapshot);
    if (context != NULL) FltReleaseContext(context);
    if (result != NULL) SafeUploadStagePublicDereferenceBackend(&result->Lifetime);
    if (status != STATUS_SUCCESS && NT_SUCCESS(status)) status = STATUS_NOT_SUPPORTED;
    if (status != STATUS_SUCCESS) SafeUploadStagePublicRecordWriterRefusal(*Reason);
    StagePublicEndOpen();
    return status;
}

_Use_decl_annotations_
VOID SafeUploadStagePublicReleaseWriter(PSAFEUPLOAD_STAGE_WRITER_LEASE Lease)
{
    PAGED_CODE();
    if (Lease != NULL) SafeUploadStagePublicDereferenceBackend(&Lease->Lifetime);
}

_Use_decl_annotations_
VOID SafeUploadStagePublicGetWriterBinding(PSAFEUPLOAD_STAGE_WRITER_LEASE Lease,
    PSAFEUPLOAD_STAGE_PUBLIC_BINDING Binding)
{
    *Binding = Lease->Lifetime.Binding; /* immutable, caller holds a lease reference */
}

_Use_decl_annotations_
NTSTATUS SafeUploadStagePublicRevalidateWriter(PSAFEUPLOAD_STAGE_WRITER_LEASE Lease,
    SAFEUPLOAD_STAGE_WRITER_REFUSAL *Reason)
{
    PFLT_INSTANCE instance = NULL;
    PFILE_OBJECT object = NULL;
    PSTAGE_WRITER_SNAPSHOT current = NULL;
    PACCESS_TOKEN oldToken;
    BOOLEAN copyOnOpen, effectiveOnly;
    SECURITY_IMPERSONATION_LEVEL level;
    NTSTATUS status;
    PAGED_CODE();
    *Reason = StageWriterNoRefusal;
    if (IoGetTopLevelIrp() != NULL || !PsIsSystemThread(PsGetCurrentThread()) ||
        PsGetCurrentProcess() != PsInitialSystemProcess) return STATUS_INVALID_DEVICE_STATE;
    oldToken = PsReferenceImpersonationToken(PsGetCurrentThread(), &copyOnOpen, &effectiveOnly, &level);
    if (oldToken != NULL) {
        PsDereferenceImpersonationToken(oldToken);
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!SafeUploadStagePublicAcquireOperation(&Lease->Lifetime, &instance, &object))
        return STATUS_FLT_DELETING_OBJECT;
    if (InterlockedCompareExchange(&Lease->Revalidating, 1, 0) != 0) {
        SafeUploadStagePublicReleaseOperation(&Lease->Lifetime);
        return STATUS_DEVICE_BUSY;
    }
    /* Never reopen the target with writer rights or zero access. This directly
     * queries the retained lease and rewalks only metadata anchors/selected links. */
    status = StageWriterCaptureSnapshot(Lease, object, &current, Reason);
    if (status == STATUS_SUCCESS && (!StageWriterEqualSnapshots(Lease->Snapshot, current) ||
        !StageWriterProcessRunning(Lease->ProcessHandle))) {
        *Reason = StageWriterSnapshotChanged;
        status = STATUS_FILE_INVALID;
    }
    if (status == STATUS_SUCCESS && SafeUploadStageMandatoryTeardownActive()) status = STATUS_FLT_DELETING_OBJECT;
    StageWriterFreeSnapshot(current);
    InterlockedExchange(&Lease->Revalidating, 0);
    SafeUploadStagePublicReleaseOperation(&Lease->Lifetime);
    if (status != STATUS_SUCCESS) SafeUploadStagePublicRecordWriterRefusal(*Reason);
    return status;
}

_Use_decl_annotations_
NTSTATUS SafeUploadStagePublicCheckWriterSecurity(PSAFEUPLOAD_STAGE_WRITER_LEASE Lease,
    SAFEUPLOAD_STAGE_WRITER_REFUSAL *Reason)
{
    PAGED_CODE();
    /* No native-equivalent construction producer exists. Keeping these slots
     * separate prevents a future transport from claiming queried stored bits
     * are construction authority. In particular 0x8C04 -> 0x8804 is NOT fixed
     * by masking SE_DACL_AUTO_INHERITED, protection, or a privileged post-set. */
    *Reason = StageWriterNativeCreateSecurityUnproved;
    if (Lease->ExpectedStoredSecurity != NULL &&
        Lease->ExpectedStoredSecurityBytes >= sizeof(SECURITY_DESCRIPTOR_RELATIVE) &&
        FlagOn(((SECURITY_DESCRIPTOR_RELATIVE *)Lease->ExpectedStoredSecurity)->Control, SE_DACL_AUTO_INHERITED))
        *Reason = StageWriterPublicationSecurityNotEquivalent;
    SafeUploadStagePublicRecordWriterRefusal(*Reason);
    return STATUS_NOT_SUPPORTED;
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageWriterHashAncestors(_In_ PSAFEUPLOAD_STAGE_WRITER_LEASE Lease,
    _Out_writes_bytes_(32) PUCHAR Digest);
#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, StageWriterHashAncestors)
#pragma alloc_text(PAGE, SafeUploadStageWriterMetadataPrepare)
#pragma alloc_text(PAGE, SafeUploadStageWriterMetadataControl)
#endif

/* Hash fields individually: no structure padding, addresses or handle values. */
_Use_decl_annotations_
static NTSTATUS StageWriterHashAncestors(PSAFEUPLOAD_STAGE_WRITER_LEASE Lease, PUCHAR Digest)
{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    NTSTATUS status;
    ULONG index, value;
    PSTAGE_WRITER_SNAPSHOT snapshot = Lease->Snapshot;
    PAGED_CODE();
    RtlZeroMemory(Digest, 32);
    status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) goto Exit;
    status = BCryptCreateHash(algorithm, &hash, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(status)) goto Exit;
#define HASH_BYTES(p, n) do { status = BCryptHashData(hash, (PUCHAR)(p), (ULONG)(n), 0); if (!NT_SUCCESS(status)) goto Exit; } while (0)
#define HASH_FIELD(f) HASH_BYTES(&(f), sizeof(f))
    HASH_FIELD(snapshot->MountId);
    HASH_FIELD(snapshot->Count);
    HASH_FIELD(snapshot->Name.Length);
    HASH_BYTES(snapshot->Name.Buffer, snapshot->Name.Length);
    HASH_FIELD(Lease->Input.LookupName.Length);
    HASH_BYTES(Lease->Input.LookupName.Buffer, Lease->Input.LookupName.Length);
    for (index = 0; index < snapshot->Count; ++index) {
        PSTAGE_WRITER_ANCHOR a = &snapshot->Anchors[index];
        HASH_FIELD(a->Identity.VolumeSerialNumber); HASH_FIELD(a->Identity.FileId);
        HASH_FIELD(a->Attributes.FileAttributes); HASH_FIELD(a->Attributes.ReparseTag);
        HASH_FIELD(a->Basic.CreationTime); HASH_FIELD(a->Basic.LastAccessTime);
        HASH_FIELD(a->Basic.LastWriteTime); HASH_FIELD(a->Basic.ChangeTime); HASH_FIELD(a->Basic.FileAttributes);
        HASH_FIELD(a->Standard.AllocationSize); HASH_FIELD(a->Standard.EndOfFile); HASH_FIELD(a->Standard.NumberOfLinks);
        value = a->Standard.DeletePending ? 1UL : 0UL; HASH_FIELD(value);
        value = a->Standard.Directory ? 1UL : 0UL; HASH_FIELD(value);
        value = a->CaseSensitive ? 1UL : 0UL; HASH_FIELD(value);
        HASH_FIELD(a->ComponentOffset); HASH_FIELD(a->ComponentBytes); HASH_FIELD(a->SecurityBytes);
        HASH_BYTES(a->Security, a->SecurityBytes);
    }
    status = BCryptFinishHash(hash, Digest, 32, 0);
#undef HASH_FIELD
#undef HASH_BYTES
Exit:
    if (hash != NULL) (VOID)BCryptDestroyHash(hash);
    if (algorithm != NULL) (VOID)BCryptCloseAlgorithmProvider(algorithm, 0);
    return status;
}

_Use_decl_annotations_
NTSTATUS SafeUploadStageWriterMetadataPrepare(PSAFEUPLOAD_STAGE_WRITER_LEASE Lease,
    const SAFEUPLOAD_STAGE_ALLOCATE_V23 *Binding, const GUID *DriverInstanceId, UINT64 RequestId,
    PVOID *Cookie, PUINT64 Revision, SAFEUPLOAD_STAGE_WRITER_REFUSAL *Reason)
{
    static const GUID zero = {0};
    const SAFEUPLOAD_STAGE_PUBLIC_BINDING *b = &Lease->Lifetime.Binding;
    SAFEUPLOAD_WRITER_METADATA_HEADER header = {0};
    PSAFEUPLOAD_WRITER_METADATA_FACTS facts = NULL;
    PFLT_INSTANCE instance = NULL;
    PFILE_OBJECT object = NULL;
    PACCESS_TOKEN primary = NULL;
    PTOKEN_USER user = NULL;
    PULONG session = NULL;
    GUID driver;
    ULONG boot, bytes;
    PVOID cookie = NULL, checkedCookie = NULL;
    UINT64 epoch = 0, revision = 0, checkedEpoch = 0, checkedRevision = 0;
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    BOOLEAN publishing = FALSE;
    PAGED_CODE();
    *Cookie = NULL; *Revision = 0; *Reason = StageWriterMetadataBindingMismatch;
    if (RequestId == 0 || Binding->Version != SAFEUPLOAD_STAGE_BOUND_ALLOCATION_VERSION ||
        Binding->StructSize != sizeof(*Binding) || RtlEqualMemory(&Binding->AllocationReservationId, &zero, sizeof(zero)) ||
        Binding->Disposition != (Lease->Input.Options >> 24) || Binding->ReferenceKind > 2 ||
        ((Binding->ReferenceKind == 0) != RtlEqualMemory(&Binding->ParentTransferId, &zero, sizeof(zero))) ||
        !RtlEqualMemory(&Binding->MountManagerVolumeId, &b->MountManagerVolumeId, sizeof(GUID)) ||
        !RtlEqualMemory(&Binding->VolumeRootId, &b->VolumeRootIdentity.FileId, sizeof(FILE_ID_128)) ||
        Binding->ParentIdentity.VolumeSerialNumber != b->ParentIdentity.VolumeSerialNumber ||
        !RtlEqualMemory(&Binding->ParentIdentity.FileId, &b->ParentIdentity.FileId, sizeof(FILE_ID_128)) ||
        !RtlEqualMemory(&Binding->PublicTargetId, &b->PublicIdentity.FileId, sizeof(FILE_ID_128)) ||
        Binding->ParentCaseSensitive != (b->ParentCaseSensitive ? 1 : 0) ||
        Binding->CanonicalLeafBytes != b->CanonicalLeafBytes) goto Refused;
    status = SafeUploadStageNativeReadIdentity(&driver, &boot);
    if (!NT_SUCCESS(status) || !RtlEqualMemory(&driver, DriverInstanceId, sizeof(GUID))) {
        status = STATUS_REVISION_MISMATCH; goto Refused;
    }
    *Reason = StageWriterMetadataStale;
    if (!SafeUploadStagePublicAcquireOperation(&Lease->Lifetime, &instance, &object)) {
        status = STATUS_FLT_DELETING_OBJECT; goto Refused;
    }
    if (InterlockedCompareExchange(&Lease->MetadataPreparing, 1, 0) != 0) {
        status = STATUS_DEVICE_BUSY; goto Exit;
    }
    publishing = TRUE;
    if (Lease->MetadataPublished || !StageWriterProcessRunning(Lease->ProcessHandle) ||
        !SafeUploadStageProtocolMetadataIdentity(NULL, &cookie, &epoch, &revision)) {
        status = STATUS_INVALID_DEVICE_STATE; goto Exit;
    }
    *Reason = StageWriterMetadataResourceLimit;
    if (Lease->ConstructionSecurityBytes > SAFEUPLOAD_STAGE_CREATE_SECURITY_LIMIT ||
        Lease->ExpectedStoredSecurityBytes > SAFEUPLOAD_STAGE_CREATE_SECURITY_LIMIT ||
        Lease->Snapshot == NULL || Lease->Snapshot->Count < 2 || Lease->Snapshot->Count > STAGE_WRITER_MAX_ANCHORS) {
        status = STATUS_QUOTA_EXCEEDED; goto Exit;
    }
    bytes = (ULONG)sizeof(*facts) + Lease->ConstructionSecurityBytes + Lease->ExpectedStoredSecurityBytes;
    facts = ExAllocatePool2(POOL_FLAG_PAGED, bytes, STAGE_PUBLIC_TAG);
    if (facts == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    *Reason = StageWriterMetadataUnproved;
    facts->Format = 1; facts->HeaderBytes = sizeof(*facts); facts->Binding = *Binding;
    RtlCopyMemory(facts->CanonicalLeaf, b->CanonicalLeaf, b->CanonicalLeafBytes);
    facts->ProcessId = b->CallerProcessId; facts->ProcessCreationTime = b->CallerProcessCreationTime;
    /* Recipient candidate is process-primary; effective subject stays separate.
     * Neither field is affirmative export authority. */
    primary = PsReferencePrimaryToken(Lease->Process);
    status = SeQueryInformationToken(primary, TokenUser, (PVOID *)&user);
    if (!NT_SUCCESS(status)) goto Exit;
    if (user == NULL || !RtlValidSid(user->User.Sid) || RtlLengthSid(user->User.Sid) > sizeof(facts->ProcessSid)) {
        status = STATUS_INVALID_SID; goto Exit;
    }
    facts->ProcessSidBytes = RtlLengthSid(user->User.Sid);
    status = RtlCopySid(sizeof(facts->ProcessSid), facts->ProcessSid, user->User.Sid);
    if (!NT_SUCCESS(status)) goto Exit;
    status = SeQueryInformationToken(primary, TokenSessionId, (PVOID *)&session);
    if (!NT_SUCCESS(status)) goto Exit;
    if (session == NULL) { status = STATUS_INVALID_BUFFER_SIZE; goto Exit; }
    facts->SessionId = *session;
    facts->SubjectSidBytes = b->CallerSidBytes;
    RtlCopyMemory(facts->SubjectSid, b->CallerSid, b->CallerSidBytes);
    facts->DesiredAccess = Lease->Input.DesiredAccess;
    facts->OriginalDesiredAccess = Lease->Input.OriginalDesiredAccess;
    facts->RemainingDesiredAccess = Lease->Input.RemainingDesiredAccess;
    facts->PreviouslyGrantedAccess = Lease->Input.PreviouslyGrantedAccess;
    facts->NativeGrantedAccess = Lease->NativeGrantedAccess; facts->StagedGrantedAccess = b->GrantedAccess;
    facts->Options = Lease->Input.Options; facts->Attributes = Lease->Input.FileAttributes;
    facts->ShareAccess = Lease->Input.ShareAccess; facts->OperationFlags = Lease->Input.OperationFlags;
    facts->RequestorMode = Lease->Input.RequestorMode; facts->OriginalInformation = Lease->OriginalInformation;
    facts->AllocationSize = Lease->Input.AllocationSize.QuadPart;
    facts->AncestorCount = Lease->Snapshot->Count;
    status = StageWriterHashAncestors(Lease, facts->AncestorDigest);
    if (!NT_SUCCESS(status)) goto Exit;
    facts->SecurityInformation = STAGE_WRITER_SECURITY_INFORMATION;
    facts->ConstructionBytes = Lease->ConstructionSecurityBytes;
    facts->StoredBytes = Lease->ExpectedStoredSecurityBytes;
    facts->SeedOrigin = Binding->Disposition == FILE_OPEN || Binding->Disposition == FILE_OPEN_IF ?
        (Binding->ReferenceKind == SAFEUPLOAD_STAGE_ALLOC_REFERENCE_FOLLOWUP ? 2UL : 1UL) : 0UL;
    facts->ReadStatus = STATUS_NOT_SUPPORTED; facts->ExportStatus = STATUS_NOT_SUPPORTED;
    status = ExUuidCreate(&facts->EffectiveSubjectId);
    if (!NT_SUCCESS(status)) goto Exit;
    if (facts->ConstructionBytes != 0)
        RtlCopyMemory((PUCHAR)facts + sizeof(*facts), Lease->ConstructionSecurity, facts->ConstructionBytes);
    if (facts->StoredBytes != 0)
        RtlCopyMemory((PUCHAR)facts + sizeof(*facts) + facts->ConstructionBytes,
            Lease->ExpectedStoredSecurity, facts->StoredBytes);
    header.ExtensionVersion = SAFEUPLOAD_WRITER_METADATA_VERSION; header.StructSize = sizeof(SAFEUPLOAD_WRITER_METADATA_PAGE);
    header.Phase = SAFEUPLOAD_WRITER_METADATA_DISCOVER; header.Result = SAFEUPLOAD_WRITER_METADATA_CAPTURED;
    header.DriverInstanceId = driver; header.ReservationId = Binding->AllocationReservationId;
    header.RequestId = RequestId; header.ConnectionEpoch = epoch; header.AuthorityRevision = revision;
    status = ExUuidCreate(&header.SnapshotId);
    if (!NT_SUCCESS(status)) goto Exit;
    header.TotalBytes = bytes;
    header.Flags = SAFEUPLOAD_WRITER_METADATA_ANCESTORS | SAFEUPLOAD_WRITER_METADATA_IDENTITY |
        (facts->ConstructionBytes != 0 ? SAFEUPLOAD_WRITER_METADATA_CONSTRUCTION : 0) |
        (facts->StoredBytes != 0 ? SAFEUPLOAD_WRITER_METADATA_STORED : 0);
    /* No assignment-proven flag/revision: increment 2 has no constructor. */
    status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) goto Exit;
    status = BCryptCreateHash(algorithm, &hash, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(status)) goto Exit;
    status = BCryptHashData(hash, (PUCHAR)facts, bytes, 0);
    if (!NT_SUCCESS(status)) goto Exit;
    status = BCryptFinishHash(hash, header.Digest, sizeof(header.Digest), 0);
    if (!NT_SUCCESS(status)) goto Exit;
    *Reason = StageWriterMetadataStale;
    if (!SafeUploadStageProtocolMetadataIdentity(cookie, &checkedCookie, &checkedEpoch, &checkedRevision) ||
        checkedEpoch != epoch || checkedRevision != revision || !StageWriterProcessRunning(Lease->ProcessHandle)) {
        status = STATUS_PORT_DISCONNECTED; goto Exit;
    }
    FltAcquirePushLockExclusive(&StagePublicListLock);
    if (StagePublicAdmissionClosed || SafeUploadStageMandatoryTeardownActive() || Lease->Lifetime.Closing) {
        status = STATUS_FLT_DELETING_OBJECT;
    } else {
        PLIST_ENTRY link;
        status = STATUS_SUCCESS;
        for (link = StagePublicBackends.Flink; link != &StagePublicBackends; link = link->Flink) {
            PSAFEUPLOAD_STAGE_PUBLIC_BACKEND backend = CONTAINING_RECORD(link, SAFEUPLOAD_STAGE_PUBLIC_BACKEND, Link);
            if (backend->WriterLease) {
                PSAFEUPLOAD_STAGE_WRITER_LEASE other = (PSAFEUPLOAD_STAGE_WRITER_LEASE)backend;
                if (other->MetadataPublished && RtlEqualMemory(&other->MetadataHeader.ReservationId,
                    &Binding->AllocationReservationId, sizeof(GUID))) { status = STATUS_OBJECT_NAME_COLLISION; break; }
            }
        }
        if (status == STATUS_SUCCESS) {
            Lease->Metadata = (PUCHAR)facts; facts = NULL;
            Lease->MetadataCookie = cookie; Lease->MetadataHeader = header;
            Lease->MetadataPublished = TRUE;
            *Cookie = cookie; *Revision = revision; *Reason = StageWriterNoRefusal;
        }
    }
    FltReleasePushLock(&StagePublicListLock);
Exit:
    if (hash != NULL) (VOID)BCryptDestroyHash(hash);
    if (algorithm != NULL) (VOID)BCryptCloseAlgorithmProvider(algorithm, 0);
    if (user != NULL) ExFreePool(user);
    if (session != NULL) ExFreePool(session);
    if (primary != NULL) PsDereferencePrimaryToken(primary);
    if (facts != NULL) ExFreePoolWithTag(facts, STAGE_PUBLIC_TAG);
    if (publishing) InterlockedExchange(&Lease->MetadataPreparing, 0);
    SafeUploadStagePublicReleaseOperation(&Lease->Lifetime);
Refused:
    if (status != STATUS_SUCCESS) SafeUploadStagePublicRecordWriterRefusal(*Reason);
    return status;
}

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SafeUploadStagePublicWriterMetadataCurrent)
#pragma alloc_text(PAGE, SafeUploadStagePublicSeedWriter)
#endif

_Use_decl_annotations_
NTSTATUS SafeUploadStagePublicWriterMetadataCurrent(PSAFEUPLOAD_STAGE_WRITER_LEASE Lease,
    SAFEUPLOAD_STAGE_WRITER_REFUSAL *Reason)
{
    PFLT_INSTANCE instance = NULL;
    PFILE_OBJECT object = NULL;
    PVOID cookie = NULL;
    UINT64 epoch = 0, revision = 0;
    NTSTATUS status = STATUS_DEVICE_NOT_READY;
    PAGED_CODE();
    *Reason = StageWriterMetadataStale;
    if (!SafeUploadStagePublicAcquireOperation(&Lease->Lifetime, &instance, &object))
        return STATUS_FLT_DELETING_OBJECT;
    if (Lease->MetadataPublished && Lease->Metadata != NULL &&
        SafeUploadStageProtocolMetadataIdentity(Lease->MetadataCookie, &cookie, &epoch, &revision) &&
        epoch == Lease->MetadataHeader.ConnectionEpoch && revision == Lease->MetadataHeader.AuthorityRevision &&
        StageWriterProcessRunning(Lease->ProcessHandle)) {
        *Reason = StageWriterMetadataUnproved;
        if (Lease->MetadataHeader.Flags == (SAFEUPLOAD_WRITER_METADATA_CONSTRUCTION |
            SAFEUPLOAD_WRITER_METADATA_STORED | SAFEUPLOAD_WRITER_METADATA_ANCESTORS |
            SAFEUPLOAD_WRITER_METADATA_IDENTITY | SAFEUPLOAD_WRITER_METADATA_ASSIGNED)) {
            status = STATUS_SUCCESS;
            *Reason = StageWriterNoRefusal;
        }
    }
    SafeUploadStagePublicReleaseOperation(&Lease->Lifetime);
    if (status != STATUS_SUCCESS) SafeUploadStagePublicRecordWriterRefusal(*Reason);
    return status;
}

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SafeUploadStagePublicWriterReplayIdentity)
#endif
_Use_decl_annotations_
NTSTATUS SafeUploadStagePublicWriterReplayIdentity(PSAFEUPLOAD_STAGE_WRITER_LEASE Lease,
    const SAFEUPLOAD_REQUEST *Request, PVOID *Cookie, PUINT64 Revision)
{
    PFLT_INSTANCE instance = NULL;
    PFILE_OBJECT object = NULL;
    PSAFEUPLOAD_WRITER_METADATA_FACTS facts;
    SAFEUPLOAD_STAGE_WRITER_REFUSAL reason;
    NTSTATUS status;
    PAGED_CODE();
    *Cookie = NULL; *Revision = 0;
    status = SafeUploadStagePublicWriterMetadataCurrent(Lease, &reason);
    if (status != STATUS_SUCCESS) return status;
    if (!SafeUploadStagePublicAcquireOperation(&Lease->Lifetime, &instance, &object))
        return STATUS_FLT_DELETING_OBJECT;
    facts = (PSAFEUPLOAD_WRITER_METADATA_FACTS)Lease->Metadata;
    status = STATUS_INVALID_PARAMETER;
    if (facts != NULL && Request->RequestId == Lease->MetadataHeader.RequestId &&
        Request->RequestorProcessId == Lease->Lifetime.Binding.CallerProcessId &&
        Request->ImageNameLength == sizeof(facts->Binding) &&
        RtlEqualMemory(Request->ImageName, &facts->Binding, sizeof(facts->Binding)) &&
        Request->PathLength == Lease->Snapshot->Name.Length &&
        RtlEqualMemory(Request->Path, Lease->Snapshot->Name.Buffer, Request->PathLength)) {
        *Cookie = Lease->MetadataCookie;
        *Revision = Lease->MetadataHeader.AuthorityRevision;
        status = STATUS_SUCCESS;
    }
    SafeUploadStagePublicReleaseOperation(&Lease->Lifetime);
    if (status != STATUS_SUCCESS) SafeUploadStagePublicRecordWriterRefusal(StageWriterMetadataReplayUnbound);
    return status;
}

/* No mechanism currently owns a whole-copy interval on the original public
 * FILE_OBJECT or a private predecessor. Do not replace this refusal with ID,
 * EOF/digest comparisons, per-chunk range locks or a caller-supplied boolean. */
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageWriterSeedInterval(_In_ ULONG Origin, _Out_ PLARGE_INTEGER Length);
#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, StageWriterSeedInterval)
#endif
_Use_decl_annotations_
static NTSTATUS StageWriterSeedInterval(ULONG Origin, PLARGE_INTEGER Length)
{
    PAGED_CODE();
    Length->QuadPart = 0;
    return Origin == 0 ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
}

_Use_decl_annotations_
NTSTATUS SafeUploadStagePublicSeedWriter(PSAFEUPLOAD_STAGE_WRITER_LEASE Lease,
    PFLT_INSTANCE BackingInstance, PFILE_OBJECT BackingObject, ULONG BackingSectorSize,
    const SAFEUPLOAD_STAGE_IDENTITY_V19 *Identity, UINT64 Generation, PFLT_CALLBACK_DATA Data,
    PSAFEUPLOAD_STAGE_SEED_COMPLETION Completion, SAFEUPLOAD_STAGE_WRITER_REFUSAL *Reason)
{
    PFLT_INSTANCE instance = NULL;
    PFILE_OBJECT source = NULL;
    PFLT_VOLUME volume = NULL;
    PVOID input = NULL, output = NULL;
    SAFEUPLOAD_STAGE_SEED_COMPLETION receipt = {0};
    FILE_ID_INFORMATION actual;
    FILE_STANDARD_INFORMATION standard;
    FILE_END_OF_FILE_INFORMATION eof;
    FLT_VOLUME_PROPERTIES properties;
    LARGE_INTEGER length = {0}, offset = {0};
    ULONG returned = 0, sector, wanted, aligned, read, written;
    PSAFEUPLOAD_WRITER_METADATA_FACTS facts;
    NTSTATUS status;
    PAGED_CODE();
    RtlZeroMemory(Completion, sizeof(*Completion));
    *Reason = StageWriterSeedCompletionUnproved;
    if (Generation == 0 || BackingSectorSize < 512 || BackingSectorSize > 65536 ||
        (BackingSectorSize & (BackingSectorSize - 1)) != 0) return STATUS_INVALID_PARAMETER;
    status = SafeUploadStagePublicWriterMetadataCurrent(Lease, Reason);
    if (status != STATUS_SUCCESS) return status;
    status = SafeUploadStagePublicRevalidateWriter(Lease, Reason);
    if (status != STATUS_SUCCESS) return status;
    if (!SafeUploadStagePublicAcquireOperation(&Lease->Lifetime, &instance, &source))
        return STATUS_FLT_DELETING_OBJECT;
    facts = (PSAFEUPLOAD_WRITER_METADATA_FACTS)Lease->Metadata;
    if (facts == NULL) { status = STATUS_INVALID_DEVICE_STATE; goto Exit; }
    *Reason = StageWriterSeedCoherenceUnproved;
    status = StageWriterSeedInterval(facts->SeedOrigin, &length);
    if (status != STATUS_SUCCESS) goto Exit; /* Before any source read or app binding. */
    *Reason = StageWriterSeedIoFailed;
    if (length.QuadPart < 0 || length.QuadPart > 16 * 1024 * 1024) {
        status = STATUS_FILE_TOO_LARGE; goto Exit;
    }
    status = StageWriterFullId(BackingInstance, BackingObject, &actual);
    if (status != STATUS_SUCCESS) goto Exit;
    if (actual.VolumeSerialNumber != Identity->VolumeSerialNumber ||
        !RtlEqualMemory(&actual.FileId, &Identity->FileId, sizeof(FILE_ID_128))) {
        status = STATUS_FILE_INVALID; goto Exit;
    }
    status = FltQueryInformationFile(BackingInstance, BackingObject, &standard,
        sizeof(standard), FileStandardInformation, &returned);
    if (status != STATUS_SUCCESS) goto Exit;
    if (returned != sizeof(standard) || standard.Directory || standard.DeletePending ||
        standard.EndOfFile.QuadPart != 0) { status = STATUS_FILE_INVALID; goto Exit; }
    /* Two bounded aligned buffers satisfy each stack independently, including
     * different physical alignment requirements. Never use paging I/O to read
     * through a lock or change the source's synchronous current position. */
    status = FltGetVolumeFromInstance(instance, &volume);
    if (status != STATUS_SUCCESS) goto Exit;
    status = FltGetVolumeProperties(volume, &properties, sizeof(properties), &returned);
    if (status != STATUS_BUFFER_OVERFLOW && status != STATUS_SUCCESS) goto Exit;
    sector = properties.SectorSize;
    if (sector < 512 || sector > 65536 || (sector & (sector - 1)) != 0) {
        status = STATUS_NOT_SUPPORTED; goto Exit;
    }
    sector = max(sector, BackingSectorSize);
    if (length.QuadPart != 0) {
        input = FltAllocatePoolAlignedWithTag(instance, NonPagedPoolNx, 65536, STAGE_PUBLIC_TAG);
        output = FltAllocatePoolAlignedWithTag(BackingInstance, NonPagedPoolNx, 65536, STAGE_PUBLIC_TAG);
        if (input == NULL || output == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    }
    while (offset.QuadPart < length.QuadPart) {
        if (SafeUploadStageMandatoryTeardownActive() || FltIsIoCanceled(Data)) {
            status = STATUS_CANCELLED; goto Exit;
        }
        wanted = (ULONG)min(65536LL, length.QuadPart - offset.QuadPart);
        aligned = (wanted + sector - 1) & ~(sector - 1);
        read = 0;
        status = FltReadFile(instance, source, &offset, aligned, input,
            FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
            &read, NULL, NULL);
        if (status != STATUS_SUCCESS) goto Exit;
        if (read != wanted) { status = STATUS_DATA_ERROR; goto Exit; }
        RtlZeroMemory(output, aligned); /* No stale final-sector padding. */
        RtlCopyMemory(output, input, wanted);
        written = 0;
        status = FltWriteFile(BackingInstance, BackingObject, &offset, aligned, output,
            FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
            &written, NULL, NULL);
        if (status != STATUS_SUCCESS) goto Exit;
        if (written != aligned) { status = STATUS_DATA_ERROR; goto Exit; }
        offset.QuadPart += wanted; /* Bounded by the checked 16-MiB product limit. */
    }
    eof.EndOfFile = length;
    status = FltSetInformationFile(BackingInstance, BackingObject, &eof, sizeof(eof), FileEndOfFileInformation);
    if (status != STATUS_SUCCESS) goto Exit;
    status = FltFlushBuffers(BackingInstance, BackingObject);
    if (status != STATUS_SUCCESS) goto Exit;
    status = FltQueryInformationFile(BackingInstance, BackingObject, &standard,
        sizeof(standard), FileStandardInformation, &returned);
    if (status != STATUS_SUCCESS) goto Exit;
    if (returned != sizeof(standard) || standard.EndOfFile.QuadPart != length.QuadPart || standard.DeletePending) {
        status = STATUS_FILE_INVALID; goto Exit;
    }
    status = SafeUploadStagePublicRevalidateWriter(Lease, Reason);
    if (status != STATUS_SUCCESS) goto Exit;
    status = SafeUploadStagePublicWriterMetadataCurrent(Lease, Reason);
    if (status != STATUS_SUCCESS) goto Exit;
    if (SafeUploadStageMandatoryTeardownActive() || FltIsIoCanceled(Data)) {
        status = STATUS_CANCELLED; goto Exit;
    }
    status = ExUuidCreate(&receipt.ReceiptId);
    if (!NT_SUCCESS(status)) goto Exit;
    receipt.DriverInstanceId = Lease->MetadataHeader.DriverInstanceId;
    receipt.TransferId = Lease->MetadataHeader.ReservationId;
    receipt.SnapshotId = Lease->MetadataHeader.SnapshotId;
    receipt.ParentTransferId = facts->Binding.ParentTransferId;
    receipt.StageIdentity = *Identity; receipt.Generation = Generation;
    receipt.RequestId = Lease->MetadataHeader.RequestId;
    receipt.ConnectionEpoch = Lease->MetadataHeader.ConnectionEpoch;
    receipt.AuthorityRevision = Lease->MetadataHeader.AuthorityRevision;
    RtlCopyMemory(receipt.MetadataDigest, Lease->MetadataHeader.Digest, sizeof(receipt.MetadataDigest));
    receipt.Length = length.QuadPart; receipt.Origin = facts->SeedOrigin;
    receipt.Complete = TRUE;
    *Completion = receipt;
    *Reason = StageWriterNoRefusal;
    status = STATUS_SUCCESS;
Exit:
    if (input != NULL) FltFreePoolAlignedWithTag(instance, input, STAGE_PUBLIC_TAG);
    if (output != NULL) FltFreePoolAlignedWithTag(BackingInstance, output, STAGE_PUBLIC_TAG);
    if (volume != NULL) FltObjectDereference(volume);
    SafeUploadStagePublicReleaseOperation(&Lease->Lifetime);
    if (status != STATUS_SUCCESS) SafeUploadStagePublicRecordWriterRefusal(*Reason);
    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS StageWriterMetadataBeginRead(VOID);
_IRQL_requires_(PASSIVE_LEVEL)
static VOID StageWriterMetadataEndRead(VOID);
#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, StageWriterMetadataBeginRead)
#pragma alloc_text(PAGE, StageWriterMetadataEndRead)
#endif

_Use_decl_annotations_
static NTSTATUS StageWriterMetadataBeginRead(VOID)
{
    NTSTATUS status;
    PAGED_CODE();
    FltAcquirePushLockExclusive(&StagePublicListLock);
    if (StagePublicAdmissionClosed || SafeUploadStageMandatoryTeardownActive())
        status = STATUS_FLT_DELETING_OBJECT;
    else if (StageWriterMetadataReaders >= STAGE_WRITER_MAX_METADATA_READERS)
        status = STATUS_INSUFFICIENT_RESOURCES;
    else {
        if (StageWriterMetadataReaders++ == 0) KeClearEvent(&StageWriterMetadataReadersDrained);
        status = STATUS_SUCCESS;
    }
    FltReleasePushLock(&StagePublicListLock);
    return status;
}

_Use_decl_annotations_
static VOID StageWriterMetadataEndRead(VOID)
{
    PAGED_CODE();
    FltAcquirePushLockExclusive(&StagePublicListLock);
    NT_ASSERT(StageWriterMetadataReaders > 0);
    if (--StageWriterMetadataReaders == 0)
        KeSetEvent(&StageWriterMetadataReadersDrained, IO_NO_INCREMENT, FALSE);
    FltReleasePushLock(&StagePublicListLock);
}

_Use_decl_annotations_
NTSTATUS SafeUploadStageWriterMetadataControl(PVOID PortCookie, PVOID Input, ULONG InputLength,
    PVOID Output, ULONG OutputLength, PULONG Returned)
{
    static const GUID zero = {0};
    static const UCHAR zeroDigest[32] = {0};
    SAFEUPLOAD_WRITER_METADATA_REQUEST request;
    PSAFEUPLOAD_WRITER_METADATA_PAGE page = NULL;
    PSAFEUPLOAD_STAGE_WRITER_LEASE lease = NULL;
    PFLT_INSTANCE instance = NULL;
    PFILE_OBJECT object = NULL;
    PVOID cookie = NULL, afterCookie = NULL;
    UINT64 epoch = 0, revision = 0, afterEpoch = 0, afterRevision = 0;
    PLIST_ENTRY link;
    NTSTATUS status;
    BOOLEAN operation = FALSE, reader = FALSE;
    PAGED_CODE();
    *Returned = 0;
    if (InputLength != sizeof(request) || Output == NULL || OutputLength != sizeof(*page))
        return STATUS_INVALID_BUFFER_SIZE;
    try {
        ProbeForRead(Input, sizeof(request), __alignof(SAFEUPLOAD_WRITER_METADATA_REQUEST));
        RtlCopyMemory(&request, Input, sizeof(request));
    } except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
    if (request.Control.Version != SAFEUPLOAD_PROTOCOL_VERSION || request.Control.StructSize != sizeof(request) ||
        request.Control.Command != SAFEUPLOAD_CONTROL_WRITER_METADATA || request.Control.Reserved != 0 ||
        request.ExtensionVersion != SAFEUPLOAD_WRITER_METADATA_VERSION || request.Reserved != 0 ||
        request.Phase < SAFEUPLOAD_WRITER_METADATA_DISCOVER || request.Phase > SAFEUPLOAD_WRITER_METADATA_CONFIRM ||
        request.RequestId == 0 || RtlEqualMemory(&request.DriverInstanceId, &zero, sizeof(zero)) ||
        RtlEqualMemory(&request.ReservationId, &zero, sizeof(zero)) ||
        (request.Phase == SAFEUPLOAD_WRITER_METADATA_DISCOVER && (request.Offset != 0 || request.ConnectionEpoch != 0 ||
            request.AuthorityRevision != 0 || !RtlEqualMemory(&request.SnapshotId, &zero, sizeof(zero)) ||
            !RtlEqualMemory(request.Digest, zeroDigest, sizeof(zeroDigest)))) ||
        (request.Phase != SAFEUPLOAD_WRITER_METADATA_DISCOVER && (request.ConnectionEpoch == 0 ||
            request.AuthorityRevision == 0 || RtlEqualMemory(&request.SnapshotId, &zero, sizeof(zero)))))
        return STATUS_INVALID_PARAMETER;
    if (!SafeUploadStageProtocolMetadataIdentity(PortCookie, &cookie, &epoch, &revision)) return STATUS_ACCESS_DENIED;
    status = StageWriterMetadataBeginRead();
    if (status != STATUS_SUCCESS) goto Exit;
    reader = TRUE;
    FltAcquirePushLockShared(&StagePublicListLock);
    for (link = StagePublicBackends.Flink; link != &StagePublicBackends; link = link->Flink) {
        PSAFEUPLOAD_STAGE_PUBLIC_BACKEND backend = CONTAINING_RECORD(link, SAFEUPLOAD_STAGE_PUBLIC_BACKEND, Link);
        if (backend->WriterLease && !backend->Closing) {
            PSAFEUPLOAD_STAGE_WRITER_LEASE candidate = (PSAFEUPLOAD_STAGE_WRITER_LEASE)backend;
            if (candidate->MetadataPublished && candidate->MetadataCookie == cookie &&
                candidate->MetadataHeader.RequestId == request.RequestId &&
                RtlEqualMemory(&candidate->MetadataHeader.ReservationId, &request.ReservationId, sizeof(GUID)) &&
                RtlEqualMemory(&candidate->MetadataHeader.DriverInstanceId, &request.DriverInstanceId, sizeof(GUID))) {
                SafeUploadStagePublicReferenceBackend(backend); lease = candidate; break;
            }
        }
    }
    FltReleasePushLock(&StagePublicListLock);
    status = STATUS_NOT_FOUND;
    if (lease == NULL) goto Exit;
    operation = SafeUploadStagePublicAcquireOperation(&lease->Lifetime, &instance, &object);
    status = STATUS_FLT_DELETING_OBJECT;
    if (!operation) goto Exit;
    status = STATUS_REVISION_MISMATCH;
    if (lease->Metadata == NULL || lease->MetadataHeader.ConnectionEpoch != epoch ||
        lease->MetadataHeader.AuthorityRevision != revision || !StageWriterProcessRunning(lease->ProcessHandle)) goto Exit;
    if (request.Phase != SAFEUPLOAD_WRITER_METADATA_DISCOVER &&
        (request.ConnectionEpoch != epoch || request.AuthorityRevision != revision ||
        !RtlEqualMemory(&request.SnapshotId, &lease->MetadataHeader.SnapshotId, sizeof(GUID)) ||
        !RtlEqualMemory(request.Digest, lease->MetadataHeader.Digest, sizeof(request.Digest)))) goto Exit;
    status = STATUS_INVALID_PARAMETER;
    if ((request.Phase == SAFEUPLOAD_WRITER_METADATA_READ &&
            (request.Offset >= lease->MetadataHeader.TotalBytes || request.Offset % SAFEUPLOAD_WRITER_METADATA_PAGE_BYTES != 0)) ||
        (request.Phase == SAFEUPLOAD_WRITER_METADATA_CONFIRM && request.Offset != lease->MetadataHeader.TotalBytes)) goto Exit;
    page = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*page), STAGE_PUBLIC_TAG);
    status = STATUS_INSUFFICIENT_RESOURCES;
    if (page == NULL) goto Exit;
    /* The whole page is copied to the caller: never let a short or non-read
     * page carry pool bytes, whatever the allocator's default fill. */
    RtlZeroMemory(page, sizeof(*page));
    page->Header = lease->MetadataHeader; page->Header.Phase = request.Phase; page->Header.Offset = request.Offset;
    if (request.Phase == SAFEUPLOAD_WRITER_METADATA_READ) {
        page->Header.Count = min(SAFEUPLOAD_WRITER_METADATA_PAGE_BYTES, page->Header.TotalBytes - request.Offset);
        RtlCopyMemory(page->Bytes, lease->Metadata + request.Offset, page->Header.Count);
    }
    status = STATUS_ACCESS_DENIED;
    if (!SafeUploadStageProtocolMetadataIdentity(cookie, &afterCookie, &afterEpoch, &afterRevision) ||
        afterEpoch != epoch || afterRevision != revision || lease->Lifetime.Closing) goto Exit;
    try {
        /* ProbeForWrite's annotation reads the probed buffer; same reviewed C6001
         * suppression as the other user-output controls (StageNativeObservation.c). */
#pragma warning(suppress: 6001)
        ProbeForWrite(Output, sizeof(*page), __alignof(SAFEUPLOAD_WRITER_METADATA_PAGE));
        RtlCopyMemory(Output, page, sizeof(*page));
        *Returned = sizeof(*page); status = STATUS_SUCCESS;
    } except (EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
Exit:
    if (page != NULL) ExFreePoolWithTag(page, STAGE_PUBLIC_TAG);
    if (operation) SafeUploadStagePublicReleaseOperation(&lease->Lifetime);
    if (lease != NULL) SafeUploadStagePublicReleaseWriter(lease);
    if (status != STATUS_SUCCESS) SafeUploadStagePublicRecordWriterRefusal(
        status == STATUS_INSUFFICIENT_RESOURCES ? StageWriterMetadataResourceLimit : StageWriterMetadataStale);
    if (reader) StageWriterMetadataEndRead();
    return status;
}
#endif
