/* Provisional transport and bounded metadata contracts. No modern admission.
 * See StageResourceMetadata.h for the lock/lifetime table and unresolved
 * installed-root authority at MetadataRegisterRoot. */
#include "Filter.h"
#include "StageNativeRecords.h"
#include "StageResourceMetadata.h"

typedef struct _SU_METADATA_GROUP {
    EX_RUNDOWN_REF Rundown;
    PEPROCESS Process;
    PACCESS_TOKEN Token;
    PFLT_PORT ResourcePort;
    PVOID MainCookie;
    GUID DriverInstance;
    SU_RESOURCE_NEGOTIATE_REQUEST Probe;
    BOOLEAN Revoked;
    BOOLEAN Paired;
    LONG MetadataControls;
    UINT64 RequestIds[SU_METADATA_CONTROLS + 2]; /* metadata, revoke, bootstrap */
} SU_METADATA_GROUP;

typedef struct _SU_METADATA_CONTROL_BUFFER {
    SU_RESOURCE_CONTROL_HEADER Header;
    union {
        SU_RESOURCE_NEGOTIATE_REQUEST Negotiate;
        SU_RESOURCE_ROOT_REQUEST Root;
        SU_RESOURCE_CHILD_REQUEST Child;
        SU_RESOURCE_REVOKE_PAYLOAD Revoke;
    } Request;
    SU_RESOURCE_CONTROL_HEADER ReplyHeader;
    union {
        SU_RESOURCE_NEGOTIATE_REPLY Negotiate;
        SU_RESOURCE_ROOT_REPLY Root;
        SU_RESOURCE_CHILD_REPLY Child;
        SU_RESOURCE_REVOKE_PAYLOAD Revoke;
    } Reply;
} SU_METADATA_CONTROL_BUFFER;

static KSPIN_LOCK MetadataLock;
static SU_METADATA_GROUP *MetadataGroup;
static BOOLEAN MetadataClosing;
static BOOLEAN MetadataReaping;
static BOOLEAN MetadataBootstrap;
static UINT64 MetadataRetiredSerial;
static KEVENT MetadataReaped;
static KEVENT MetadataWork;
static HANDLE MetadataThread;
static BOOLEAN MetadataWorkerStopping;
static SU_METADATA_GROUP *MetadataRetiringGroup;

/* Identity words preserve their unsigned native order; never compare a path
 * or a digest as object authority. */
static BOOLEAN MetadataZero(_In_reads_bytes_(Bytes) const VOID *Value, _In_ SIZE_T Bytes)
{
    const UCHAR *p = Value;
    SIZE_T i;
    for (i = 0; i < Bytes; ++i) if (p[i] != 0) return FALSE;
    return TRUE;
}

_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN MetadataOriginalToken(_In_opt_ PACCESS_TOKEN Expected)
{
    BOOLEAN copyOnOpen, effectiveOnly;
    SECURITY_IMPERSONATION_LEVEL level;
    PACCESS_TOKEN impersonation, primary;
    BOOLEAN same;

    /* A duplicated port in the same process while impersonating a different
     * subject is not the registered original subject. */
    impersonation = PsReferenceImpersonationToken(PsGetCurrentThread(),
        &copyOnOpen, &effectiveOnly, &level);
    if (impersonation != NULL) {
        PsDereferenceImpersonationToken(impersonation);
        return FALSE;
    }
    primary = PsReferencePrimaryToken(PsGetCurrentProcess());
    same = Expected == NULL || primary == Expected;
    PsDereferencePrimaryToken(primary);
    return same && SafeUploadCurrentProcessHasAgentServiceSid();
}

/* Pointer publication and rundown acquisition are atomic with respect to the
 * reaper. A revoked group is never returned for a new control or pair. */
_IRQL_requires_(PASSIVE_LEVEL)
static SU_METADATA_GROUP *MetadataPin(_In_opt_ PVOID Cookie)
{
    SU_METADATA_GROUP *group = NULL;
    KIRQL irql;
    KeAcquireSpinLock(&MetadataLock, &irql);
    if (!MetadataClosing && MetadataGroup != NULL && !MetadataGroup->Revoked &&
        MetadataGroup->MainCookie == Cookie &&
        ExAcquireRundownProtection(&MetadataGroup->Rundown)) group = MetadataGroup;
    KeReleaseSpinLock(&MetadataLock, irql);
    return group;
}

_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN MetadataAuthenticate(_In_ SU_METADATA_GROUP *Group)
{
    PEPROCESS process = NULL;
    BOOLEAN valid;
    if (PsGetCurrentProcess() != Group->Process || !MetadataOriginalToken(Group->Token) ||
        !SafeUploadConnectionIsOriginalToken(Group->MainCookie, Group->Token)) return FALSE;
    valid = SafeUploadConnectionPinAuthenticatedProcess(Group->MainCookie,
        (LONG64)(ULONG_PTR)Group->MainCookie, &process);
    if (valid) {
        valid = process == Group->Process;
        SafeUploadConnectionReleaseAuthenticatedProcess(Group->MainCookie, process);
    }
    return valid;
}

_IRQL_requires_(PASSIVE_LEVEL)
static VOID MetadataReap(_In_ PVOID Parameter)
{
    SU_METADATA_GROUP *group = Parameter;
    KIRQL irql;

    /* No map/policy/namespace/communication guard is held. Resource controls
     * cannot await the main policy callback. No outbound resource send exists
     * in this increment. Source removal and the communication callback owner
     * protect these code pointers through final destruction. */
    ExWaitForRundownProtectionRelease(&group->Rundown);
    if (group->ResourcePort != NULL)
        FltCloseClientPort(SafeUploadData.Filter, &group->ResourcePort);
    PsDereferencePrimaryToken(group->Token);
    ObDereferenceObject(group->Process);
    ExFreePoolWithTag(group, SU_METADATA_TAG);
    KeAcquireSpinLock(&MetadataLock, &irql);
    MetadataReaping = FALSE;
    KeSetEvent(&MetadataReaped, IO_NO_INCREMENT, FALSE);
    KeReleaseSpinLock(&MetadataLock, irql);
}

_IRQL_requires_(PASSIVE_LEVEL)
static VOID MetadataWorker(_In_opt_ PVOID Parameter)
{
    SU_METADATA_GROUP *group;
    BOOLEAN stop;
    KIRQL irql;
    UNREFERENCED_PARAMETER(Parameter);
    for (;;) {
        (VOID)KeWaitForSingleObject(&MetadataWork, Executive, KernelMode, FALSE, NULL);
        KeAcquireSpinLock(&MetadataLock, &irql);
        group = MetadataRetiringGroup;
        MetadataRetiringGroup = NULL;
        stop = MetadataWorkerStopping;
        KeReleaseSpinLock(&MetadataLock, irql);
        if (group != NULL) MetadataReap(group);
        if (stop) break;
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

_Use_decl_annotations_
VOID SafeUploadMetadataInitialize(VOID)
{
    OBJECT_ATTRIBUTES attributes;
    NTSTATUS status;
    KeInitializeSpinLock(&MetadataLock);
    KeInitializeEvent(&MetadataReaped, NotificationEvent, TRUE);
    KeInitializeEvent(&MetadataWork, SynchronizationEvent, FALSE);
    MetadataGroup = NULL;
    MetadataClosing = FALSE;
    MetadataReaping = FALSE;
    MetadataBootstrap = FALSE;
    MetadataRetiredSerial = 0;
    MetadataRetiringGroup = NULL;
    MetadataWorkerStopping = FALSE;
    MetadataThread = NULL;
    InitializeObjectAttributes(&attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = PsCreateSystemThread(&MetadataThread, THREAD_ALL_ACCESS, &attributes,
        NULL, NULL, MetadataWorker, NULL);
    if (!NT_SUCCESS(status)) {
        /* A dormant optional transport failure cannot break shipped v1.
         * No group is admitted if its local PASSIVE owner is unavailable. */
        MetadataClosing = TRUE;
        MetadataThread = NULL;
    }
}

_Use_decl_annotations_
VOID SafeUploadMetadataRevoke(PVOID MainCookie)
{
    SU_METADATA_GROUP *group = NULL;
    KIRQL irql;
    KeAcquireSpinLock(&MetadataLock, &irql);
    if (MetadataGroup != NULL &&
        (MainCookie == NULL || MainCookie == MetadataGroup->MainCookie)) {
        group = MetadataGroup;
        group->Revoked = TRUE; /* authority disappears before either port close */
        MetadataRetiredSerial = (UINT64)(ULONG_PTR)group->MainCookie;
        MetadataGroup = NULL;
        MetadataRetiringGroup = group;
        MetadataReaping = TRUE;
        KeClearEvent(&MetadataReaped);
    }
    KeReleaseSpinLock(&MetadataLock, irql);
    if (group != NULL) KeSetEvent(&MetadataWork, IO_NO_INCREMENT, FALSE);
}

_Use_decl_annotations_
BOOLEAN SafeUploadMetadataGroupDraining(VOID)
{
    BOOLEAN draining;
    KIRQL irql;
    KeAcquireSpinLock(&MetadataLock, &irql);
    /* Communication owns its permanent main admission gate. Failure of this
     * optional substrate must not reject a legacy main-port connection. */
    draining = MetadataReaping || MetadataGroup != NULL;
    KeReleaseSpinLock(&MetadataLock, irql);
    return draining;
}

_Use_decl_annotations_
VOID SafeUploadMetadataDestroy(VOID)
{
    KIRQL irql;
    KeAcquireSpinLock(&MetadataLock, &irql);
    MetadataClosing = TRUE;
    KeReleaseSpinLock(&MetadataLock, irql);
    SafeUploadMetadataRevoke(NULL);
    (VOID)KeWaitForSingleObject(&MetadataReaped, Executive, KernelMode, FALSE, NULL);
    /* DriverEntry/unload is the sole destroy owner. A signal from a work
     * routine is not a code-image barrier; join the system thread itself. */
    if (MetadataThread != NULL) {
        KeAcquireSpinLock(&MetadataLock, &irql);
        MetadataWorkerStopping = TRUE;
        KeReleaseSpinLock(&MetadataLock, irql);
        KeSetEvent(&MetadataWork, IO_NO_INCREMENT, FALSE);
        (VOID)ZwWaitForSingleObject(MetadataThread, FALSE, NULL);
        ZwClose(MetadataThread);
        MetadataThread = NULL;
    }
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS MetadataProbe(_In_ PVOID Cookie,
    _In_ const SU_RESOURCE_NEGOTIATE_REQUEST *Request, _Out_ GUID *Instance)
{
    SU_METADATA_GROUP *candidate, *group;
    PEPROCESS process = NULL;
    ULONG bootSequence;
    NTSTATUS status;
    BOOLEAN original;
    KIRQL irql;

    group = MetadataPin(Cookie);
    if (group != NULL) {
        status = MetadataAuthenticate(group) && RtlEqualMemory(&group->Probe, Request, sizeof(*Request)) ?
            STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
        if (NT_SUCCESS(status)) *Instance = group->DriverInstance;
        ExReleaseRundownProtection(&group->Rundown);
        return status;
    }
    if (!MetadataOriginalToken(NULL) ||
        !SafeUploadConnectionPinAuthenticatedProcess(Cookie, (LONG64)(ULONG_PTR)Cookie, &process))
        return STATUS_ACCESS_DENIED;
    if (process != PsGetCurrentProcess()) {
        SafeUploadConnectionReleaseAuthenticatedProcess(Cookie, process);
        return STATUS_ACCESS_DENIED;
    }
    candidate = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*candidate), SU_METADATA_TAG);
    if (candidate == NULL) {
        SafeUploadConnectionReleaseAuthenticatedProcess(Cookie, process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    status = SafeUploadStageNativeReadIdentity(&candidate->DriverInstance, &bootSequence);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(candidate, SU_METADATA_TAG);
        SafeUploadConnectionReleaseAuthenticatedProcess(Cookie, process);
        return status;
    }
    ExInitializeRundownProtection(&candidate->Rundown);
    candidate->Process = process;
    ObReferenceObject(process);
    candidate->Token = PsReferencePrimaryToken(process);
    candidate->MainCookie = Cookie;
    candidate->Probe = *Request;
    original = SafeUploadConnectionIsOriginalToken(Cookie, candidate->Token);
    status = STATUS_DEVICE_BUSY;
    KeAcquireSpinLock(&MetadataLock, &irql);
    if (!MetadataClosing && !MetadataReaping && MetadataGroup == NULL &&
        (UINT64)(ULONG_PTR)Cookie > MetadataRetiredSerial && original) {
        MetadataGroup = candidate;
        *Instance = candidate->DriverInstance;
        status = STATUS_SUCCESS;
    }
    KeReleaseSpinLock(&MetadataLock, irql);
    if (!NT_SUCCESS(status)) {
        PsDereferencePrimaryToken(candidate->Token);
        ObDereferenceObject(candidate->Process);
        ExFreePoolWithTag(candidate, SU_METADATA_TAG);
    }
    /* Keep the existing main send-lifetime pin through publication. A main
     * disconnect revokes again after publishing its closed connection state. */
    SafeUploadConnectionReleaseAuthenticatedProcess(Cookie, process);
    if (NT_SUCCESS(status) && !SafeUploadConnectionIsAuthenticatedIdentity(Cookie, (LONG64)(ULONG_PTR)Cookie)) {
        SafeUploadMetadataRevoke(Cookie);
        status = STATUS_ACCESS_DENIED;
    }
    return status;
}

_Use_decl_annotations_
NTSTATUS SafeUploadMetadataPair(PFLT_PORT ClientPort, PVOID Context, ULONG Bytes, PVOID *Cookie)
{
    SU_RESOURCE_PAIR_CONTEXT pair;
    SU_METADATA_GROUP *group;
    KIRQL irql;
    NTSTATUS status = STATUS_ACCESS_DENIED;
    *Cookie = NULL;
    if (Context == NULL || Bytes != sizeof(pair)) return STATUS_INVALID_BUFFER_SIZE;
    __try {
        ProbeForRead(Context, sizeof(pair), __alignof(SU_RESOURCE_PAIR_CONTEXT));
        RtlCopyMemory(&pair, Context, sizeof(pair));
    } __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
    if (pair.ConnectionCookie == 0 || pair.ConnectionCookie > MAXLONGLONG ||
        (UINT64)(ULONG_PTR)pair.ConnectionCookie != pair.ConnectionCookie) return STATUS_ACCESS_DENIED;
    group = MetadataPin((PVOID)(ULONG_PTR)pair.ConnectionCookie);
    if (group == NULL) return STATUS_ACCESS_DENIED;
    if (MetadataAuthenticate(group) && RtlEqualMemory(&pair.DriverInstance, &group->DriverInstance, sizeof(GUID))) {
        KeAcquireSpinLock(&MetadataLock, &irql);
        if (!group->Revoked && !group->Paired) {
            group->ResourcePort = ClientPort;
            group->Paired = TRUE;
            *Cookie = group->MainCookie; /* numeric serial, never an address */
            status = STATUS_SUCCESS;
        }
        KeReleaseSpinLock(&MetadataLock, irql);
    }
    ExReleaseRundownProtection(&group->Rundown);
    return status;
}

_Use_decl_annotations_
VOID SafeUploadMetadataDisconnect(PVOID Cookie)
{
    /* A delayed disconnect carries the retired serial, not a group address. */
    if (Cookie != NULL) SafeUploadMetadataRevoke(Cookie);
}

_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN MetadataNegotiateShape(_In_ const SU_RESOURCE_NEGOTIATE_REQUEST *Request)
{
    return !MetadataZero(&Request->AgentInstance, sizeof(GUID)) &&
        Request->RequiredCapabilities == 0xff && Request->OfferedCapabilities == 0xff &&
        Request->GrowthWaitTicks == 0 && /* owner duration is still unselected */
        Request->AllocationLimit == 8 && Request->SidLimit == 4 &&
        Request->GrowthWorkers == 8 && Request->GrowthQueue == 32 &&
        Request->LifecycleWorkers == 2 && Request->LifecycleQueue == 32 &&
        MetadataZero(Request->Reserved, sizeof(Request->Reserved)) &&
        ((Request->Phase == 1 && MetadataZero(&Request->ReadinessEpoch, sizeof(GUID))) ||
         (Request->Phase == 2 && !MetadataZero(&Request->ReadinessEpoch, sizeof(GUID))));
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS MetadataRegisterRoot(_In_ const SU_RESOURCE_ROOT_REQUEST *Request,
    _Out_ SU_RESOURCE_ROOT_REPLY *Reply)
{
    PFILE_OBJECT object = NULL;
    NTSTATUS status;
    Reply->Result = 2;
    if (Request->RootRole < 1 || Request->RootRole > 4 || Request->Flags != 0 ||
        Request->Handle == 0 || (UINT64)(ULONG_PTR)Request->Handle != Request->Handle ||
        Request->SecurityContractVersion != 1 ||
        !MetadataZero(Request->Reserved, sizeof(Request->Reserved)) ||
        MetadataZero(&Request->Identity, sizeof(Request->Identity)) ||
        ((Request->RootRole == 1 || Request->RootRole == 3) != (Request->ParentRootId == 0)))
        return STATUS_INVALID_PARAMETER;
    /* UserMode checks the *original* handle grant. KernelMode/SYSTEM reopen
     * would manufacture authority. The reference is released before return. */
    status = ObReferenceObjectByHandle((HANDLE)(ULONG_PTR)Request->Handle,
        READ_CONTROL | SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY,
        *IoFileObjectType, UserMode, (PVOID *)&object, NULL);
    if (!NT_SUCCESS(status)) return status;
    ObDereferenceObject(object);
    /* STOP: 8.1 names installed-root ancestry but supplies no kernel trusted
     * enrollment source for StageRoot/JournalHot. A SYSTEM owner, expected ID,
     * protected DACL or caller-supplied path cannot supply that missing source.
     * No map entry/RootId is created. Do not replace this refusal with success
     * until that source and root-chain/exclusion capture have been specified.
     * This is an incomplete substrate, not successful registration. */
    return STATUS_NOT_SUPPORTED;
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS MetadataChildShape(_In_ const SU_RESOURCE_CHILD_REQUEST *Request)
{
    ULONG i;
    UINT64 maximum;
    ACCESS_MASK allowed = READ_CONTROL | SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_READ_DATA;
    BOOLEAN output;
    if (Request->RootId == 0 || MetadataZero(&Request->TransactionId, sizeof(GUID)) ||
        Request->Role < SuLedgerCurrent || Request->Role > SuCompactionIntentNew ||
        Request->LeafBytes == 0 || Request->LeafBytes > 510 || (Request->LeafBytes & 1) != 0 ||
        !MetadataZero(Request->Reserved, sizeof(Request->Reserved)) ||
        (Request->CreateDisposition != FILE_OPEN && Request->CreateDisposition != FILE_CREATE) ||
        (MetadataZero(&Request->ExpectedIdentity, sizeof(Request->ExpectedIdentity)) !=
         (Request->CreateDisposition == FILE_CREATE))) return STATUS_INVALID_PARAMETER;
    for (i = 0; i < Request->LeafBytes / sizeof(WCHAR); ++i) {
        WCHAR c = Request->Leaf[i];
        if (c == 0 || c == L'\\' || c == L'/' || c == L':' || c == L'*' || c == L'?')
            return STATUS_INVALID_PARAMETER;
    }
    if ((Request->LeafBytes == 2 && Request->Leaf[0] == L'.') ||
        (Request->LeafBytes == 4 && Request->Leaf[0] == L'.' && Request->Leaf[1] == L'.') ||
        !MetadataZero((const UCHAR *)Request->Leaf + Request->LeafBytes,
            sizeof(Request->Leaf) - Request->LeafBytes)) return STATUS_INVALID_PARAMETER;
    output = Request->Role == SuLedgerNew || Request->Role == SuCompanionNew ||
        Request->Role == SuManifestNew || Request->Role == SuSegment ||
        Request->Role == SuInventoryNew || Request->Role == SuMarkerNew ||
        Request->Role == SuEpochNew || Request->Role == SuHistoryCandidate ||
        Request->Role == SuAppendIntentNew || Request->Role == SuCompactionIntentNew;
    if (output) allowed |= FILE_WRITE_DATA;
    if (Request->Role != SuMarkerCurrent && Request->Role != SuLegacySecurity &&
        Request->Role != SuLegacyNegative && Request->Role != SuSegment) allowed |= DELETE;
    /* LegacyNegative has no serialized noncommitment-proof input in this
     * exchange. Its role alone cannot grant delete. */
    if ((Request->AccessMask & ~allowed) != 0 || Request->AccessMask == 0 ||
        (Request->CreateDisposition == FILE_CREATE && !output)) return STATUS_ACCESS_DENIED;
    switch (Request->Role) {
    case SuCompanionCurrent: case SuCompanionNew: maximum = 192; break;
    case SuManifestCurrent: case SuManifestNew: case SuHistoryCandidate: maximum = 128 * 1024; break;
    case SuSegment: maximum = 4 * 1024 * 1024; break;
    case SuInventoryCurrent: case SuInventoryNew: maximum = 128; break;
    case SuMarkerCurrent: case SuMarkerNew: maximum = 128; break;
    case SuEpochCurrent: case SuEpochNew: maximum = 4096; break;
    case SuLegacyNegative: maximum = 1192; break;
    case SuLegacySecurity:
        /* Its actual legacy codec bound must be imported before admitting
         * this role. An invented unlimited security-file role is forbidden. */
        return STATUS_NOT_SUPPORTED;
    default: maximum = 64 * 1024; break;
    }
    if (Request->MaximumLogicalBytes > maximum) return STATUS_INVALID_PARAMETER;
    return STATUS_SUCCESS;
}

/* Per-invocation scratch and a nonqueued metadata class. This routine has no
 * policy/epoch/namespace/service call and no wait for a credit or cleanup. */
_Use_decl_annotations_
NTSTATUS SafeUploadMetadataControl(PVOID Cookie, BOOLEAN ResourceChannel, PVOID Input,
    ULONG InputBytes, PVOID Output, ULONG OutputBytes, PULONG Returned)
{
    SU_METADATA_CONTROL_BUFFER *buffer;
    SU_RESOURCE_CONTROL_HEADER header;
    SU_METADATA_GROUP *group = NULL;
    ULONG payload, replyBytes, slot = SU_METADATA_CONTROLS + 2, i, first, last;
    BOOLEAN revoke = FALSE, bootstrap = FALSE;
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    KIRQL irql;

    *Returned = 0;
    if (Cookie == NULL || Input == NULL || Output == NULL || InputBytes < sizeof(header))
        return STATUS_INVALID_BUFFER_SIZE;
    __try {
        ProbeForRead(Input, sizeof(header), __alignof(SU_RESOURCE_CONTROL_HEADER));
        RtlCopyMemory(&header, Input, sizeof(header));
    } __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
    if (header.Version != SAFEUPLOAD_PROTOCOL_VERSION || header.StructSize != InputBytes ||
        header.Command != SAFEUPLOAD_CONTROL_RESOURCE || header.Reserved != 0 ||
        header.ResourceVersion != SAFEUPLOAD_RESOURCE_VERSION || header.ControlRequestId == 0 ||
        header.Flags != 0 || header.PayloadBytes != InputBytes - sizeof(header)) return STATUS_INVALID_PARAMETER;
    if (ResourceChannel != (header.Opcode != SU_RESOURCE_NEGOTIATE)) return STATUS_INVALID_DEVICE_REQUEST;
    if (header.Opcode >= SU_RESOURCE_FENCE) {
        group = MetadataPin(Cookie);
        if (group == NULL) return STATUS_ACCESS_DENIED;
        status = MetadataAuthenticate(group) && header.ConnectionCookie == (UINT64)(ULONG_PTR)Cookie &&
            RtlEqualMemory(&header.DriverInstance, &group->DriverInstance, sizeof(GUID)) ?
            STATUS_NOT_SUPPORTED : STATUS_ACCESS_DENIED;
        ExReleaseRundownProtection(&group->Rundown);
        return status;
    }
    switch (header.Opcode) {
    case SU_RESOURCE_NEGOTIATE: payload = sizeof(SU_RESOURCE_NEGOTIATE_REQUEST);
        replyBytes = sizeof(SU_RESOURCE_NEGOTIATE_REPLY); break;
    case SU_RESOURCE_REVOKE: payload = sizeof(SU_RESOURCE_REVOKE_PAYLOAD);
        replyBytes = sizeof(SU_RESOURCE_REVOKE_PAYLOAD); break;
    case SU_RESOURCE_REGISTER_ROOT: payload = sizeof(SU_RESOURCE_ROOT_REQUEST);
        replyBytes = sizeof(SU_RESOURCE_ROOT_REPLY); break;
    case SU_RESOURCE_REGISTER_CHILD: payload = sizeof(SU_RESOURCE_CHILD_REQUEST);
        replyBytes = sizeof(SU_RESOURCE_CHILD_REPLY); break;
    default: return STATUS_NOT_SUPPORTED;
    }
    if (header.PayloadBytes != payload || OutputBytes != sizeof(header) + replyBytes)
        return STATUS_INVALID_BUFFER_SIZE;
    if (header.Opcode == SU_RESOURCE_NEGOTIATE) {
        KeAcquireSpinLock(&MetadataLock, &irql);
        if (!MetadataClosing && !MetadataBootstrap) {
            MetadataBootstrap = TRUE;
            bootstrap = TRUE;
        }
        KeReleaseSpinLock(&MetadataLock, irql);
        if (!bootstrap) return STATUS_DEVICE_BUSY;
        if (!MetadataOriginalToken(NULL)) { status = STATUS_ACCESS_DENIED; goto Exit; }
    }
    if (header.Opcode != SU_RESOURCE_NEGOTIATE || header.ConnectionCookie != 0) {
        group = MetadataPin(Cookie);
        if (group == NULL) { status = STATUS_ACCESS_DENIED; goto Exit; }
        if (header.ConnectionCookie != (UINT64)(ULONG_PTR)Cookie ||
            !RtlEqualMemory(&header.DriverInstance, &group->DriverInstance, sizeof(GUID))) {
            status = STATUS_ACCESS_DENIED;
            goto Exit;
        }
        KeAcquireSpinLock(&MetadataLock, &irql);
        if (!group->Revoked && (!ResourceChannel || group->Paired)) {
            last = RTL_NUMBER_OF(group->RequestIds);
            for (i = 0; i < last; ++i) {
                if (group->RequestIds[i] == header.ControlRequestId) break;
            }
            if (i == last) {
                first = 0;
                last = SU_METADATA_CONTROLS;
                if (header.Opcode == SU_RESOURCE_REVOKE) { first = last; ++last; }
                if (header.Opcode == SU_RESOURCE_NEGOTIATE) { first = SU_METADATA_CONTROLS + 1; last = first + 1; }
                for (i = first; i < last; ++i) {
                    if (group->RequestIds[i] == 0) {
                        slot = i;
                        group->RequestIds[i] = header.ControlRequestId;
                        ++group->MetadataControls;
                        break;
                    }
                }
            }
        }
        KeReleaseSpinLock(&MetadataLock, irql);
        if (slot == SU_METADATA_CONTROLS + 2) { status = STATUS_DEVICE_BUSY; goto Exit; }
        if (!MetadataAuthenticate(group)) { status = STATUS_ACCESS_DENIED; goto Exit; }
    } else if (!MetadataZero(&header.DriverInstance, sizeof(GUID))) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }
    buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*buffer), SU_METADATA_TAG);
    if (buffer == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    __try {
        ProbeForRead(Input, InputBytes, __alignof(SU_RESOURCE_CONTROL_HEADER));
        ProbeForWrite(Output, OutputBytes, __alignof(SU_RESOURCE_CONTROL_HEADER));
        RtlCopyMemory(buffer, Input, InputBytes);
        if (!RtlEqualMemory(&buffer->Header, &header, sizeof(header))) {
            status = STATUS_INVALID_PARAMETER;
            __leave;
        }
        buffer->ReplyHeader = header;
        buffer->ReplyHeader.PayloadBytes = replyBytes;
        buffer->ReplyHeader.StructSize = (ULONG)sizeof(header) + replyBytes;
        switch (header.Opcode) {
        case SU_RESOURCE_NEGOTIATE:
            if (!MetadataNegotiateShape(&buffer->Request.Negotiate)) { status = STATUS_INVALID_PARAMETER; break; }
            if (buffer->Request.Negotiate.Phase == 1) {
                if (header.ConnectionCookie != 0) { status = STATUS_INVALID_PARAMETER; break; }
                status = MetadataProbe(Cookie, &buffer->Request.Negotiate, &buffer->ReplyHeader.DriverInstance);
                if (!NT_SUCCESS(status)) break;
                buffer->ReplyHeader.ConnectionCookie = (UINT64)(ULONG_PTR)Cookie;
            } else {
                if (group == NULL || !RtlEqualMemory(&group->Probe, &buffer->Request.Negotiate,
                    FIELD_OFFSET(SU_RESOURCE_NEGOTIATE_REQUEST, ReadinessEpoch))) {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }
                status = STATUS_SUCCESS;
            }
            /* Deliberate final result for BOTH phases, with every grant field
             * zero from ExAllocatePool2. BootDomain is unresolved and is zero;
             * no OS-boot claim is synthesized from driver ID or wall clock. */
            buffer->Reply.Negotiate.Result = 2;
            buffer->Reply.Negotiate.AgentInstance = buffer->Request.Negotiate.AgentInstance;
            buffer->Reply.Negotiate.ReadinessEpoch = buffer->Request.Negotiate.ReadinessEpoch;
            break;
        case SU_RESOURCE_REVOKE:
            if (buffer->Request.Revoke.Reserved != 0 || buffer->Request.Revoke.ReasonOrResult < 1 ||
                buffer->Request.Revoke.ReasonOrResult > 3) { status = STATUS_INVALID_PARAMETER; break; }
            buffer->Reply.Revoke.ReasonOrResult = 1;
            revoke = TRUE;
            status = STATUS_SUCCESS;
            break;
        case SU_RESOURCE_REGISTER_ROOT:
            status = MetadataRegisterRoot(&buffer->Request.Root, &buffer->Reply.Root);
            /* A root refusal has a typed reply and zero authority. Native
             * access/shape failures also refuse, never a successful map entry. */
            if (!NT_SUCCESS(status)) status = STATUS_SUCCESS;
            break;
        case SU_RESOURCE_REGISTER_CHILD:
            buffer->Reply.Child.Result = 2;
            status = MetadataChildShape(&buffer->Request.Child);
            /* No RootId can be authoritative until installed roots can be
             * enrolled. Never return a successful child registration stub. */
            status = STATUS_SUCCESS; /* Result=refused, ChildIntentId=0 */
            break;
        default: status = STATUS_NOT_SUPPORTED; break;
        }
        if (NT_SUCCESS(status)) {
            RtlCopyMemory(Output, &buffer->ReplyHeader, sizeof(header));
            RtlCopyMemory((PUCHAR)Output + sizeof(header), &buffer->Reply, replyBytes);
            *Returned = (ULONG)sizeof(header) + replyBytes;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
    ExFreePoolWithTag(buffer, SU_METADATA_TAG);
Exit:
    if (group != NULL) {
        if (slot != SU_METADATA_CONTROLS + 2) {
            KeAcquireSpinLock(&MetadataLock, &irql);
            group->RequestIds[slot] = 0;
            --group->MetadataControls;
            KeReleaseSpinLock(&MetadataLock, irql);
        }
        if (revoke) SafeUploadMetadataRevoke(Cookie);
        ExReleaseRundownProtection(&group->Rundown);
    }
    if (bootstrap) {
        KeAcquireSpinLock(&MetadataLock, &irql);
        MetadataBootstrap = FALSE;
        KeReleaseSpinLock(&MetadataLock, irql);
    }
    return status;
}

_Use_decl_annotations_
NTSTATUS SafeUploadMetadataPlanOutput(UINT64 Incarnation, UINT64 LogicalLength,
    UINT64 MaximumLogicalBytes, UINT32 IoAlignment, UINT32 AllocationUnit, SU_METADATA_OUTPUT_PLAN *Plan)
{
    UINT64 padded, peak;
    RtlZeroMemory(Plan, sizeof(*Plan));
    if (Incarnation == 0 || Incarnation > MAXLONGLONG || LogicalLength > MaximumLogicalBytes ||
        MaximumLogicalBytes > SU_METADATA_MAX_BUFFER || IoAlignment == 0 || AllocationUnit == 0 ||
        (IoAlignment & (IoAlignment - 1)) != 0 || (AllocationUnit & (AllocationUnit - 1)) != 0 ||
        IoAlignment > 65536 || AllocationUnit > 65536) return STATUS_INVALID_PARAMETER;
    if (LogicalLength > MAXLONGLONG - (UINT64)(IoAlignment - 1)) return STATUS_INTEGER_OVERFLOW;
    padded = (LogicalLength + IoAlignment - 1) & ~((UINT64)IoAlignment - 1);
    if (padded > MAXLONGLONG - (UINT64)(AllocationUnit - 1)) return STATUS_INTEGER_OVERFLOW;
    peak = (padded + AllocationUnit - 1) & ~((UINT64)AllocationUnit - 1);
    Plan->Incarnation = Incarnation;
    Plan->LogicalLength = LogicalLength;
    Plan->PaddedWriteExtent = padded;
    Plan->PeakAllocation = peak;
    Plan->IoAlignment = IoAlignment;
    Plan->AllocationUnit = AllocationUnit;
    return STATUS_SUCCESS;
}
