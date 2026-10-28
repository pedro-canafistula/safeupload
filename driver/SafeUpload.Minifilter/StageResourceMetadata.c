/* Dormant registration/routing substrate. No modern admission or native child
 * data operation. See StageResourceMetadata.h for security and ownership. */
#include "Filter.h"
#include "StageNativeRecords.h"
#include "StageResourceMetadata.h"

#define SU_METADATA_NODES 7UL
#define SU_METADATA_SD_BYTES 65536UL
#define SU_METADATA_CONTEXT_SIGNATURE 0x334d5553UL

typedef struct _SU_METADATA_NODE {
    HANDLE Handle;
    PFILE_OBJECT Object;
    SAFEUPLOAD_STAGE_IDENTITY_V19 Identity;
    PSECURITY_DESCRIPTOR Security;
    ULONG SecurityBytes;
} SU_METADATA_NODE;

struct _SU_METADATA_GROUP;
typedef struct DECLSPEC_ALIGN(16) _SU_METADATA_COMPLETION {
    ULONG Signature;
    struct _SU_METADATA_GROUP *Group;
    PFILE_OBJECT Object;
    UINT64 Incarnation;
    ULONG RootIndex;
    UCHAR Operation;
    BOOLEAN InUse;
} SU_METADATA_COMPLETION;

typedef struct _SU_METADATA_ROOT {
    UINT64 Id;
    PFILE_OBJECT Original; /* owned until PASSIVE revoke; Key is nonowning */
    PFILE_OBJECT Key;
    BOOLEAN Cleaned;
    SU_METADATA_COMPLETION Cleanup;
} SU_METADATA_ROOT;

typedef struct _SU_METADATA_TRANSACTION {
    GUID Id;
    ULONG Children;
    BOOLEAN Pending;
} SU_METADATA_TRANSACTION;

typedef struct _SU_METADATA_CHILD {
    SU_METADATA_STATE State;
    UINT64 Id;
    SU_RESOURCE_CHILD_REQUEST Request;
    WCHAR FoldedLeaf[256]; /* computed at PASSIVE, compared under M */
} SU_METADATA_CHILD;

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
    BOOLEAN RootBusy, AnchorsClosed, ForceForgetKeys;
    UINT64 NextRootId, NextChildId;
    ULONG PostOwners;
    PFLT_VOLUME Volume;
    PFLT_INSTANCE Instance;
    SU_METADATA_NODE Nodes[SU_METADATA_NODES];
    SU_METADATA_ROOT Roots[SU_METADATA_ROOTS];
    SU_METADATA_TRANSACTION Transactions[SU_METADATA_TRANSACTIONS];
    SU_METADATA_CHILD Children[SU_METADATA_CHILDREN];
    UINT64 RequestIds[SU_METADATA_CONTROLS + 2]; /* metadata, revoke, bootstrap */
} SU_METADATA_GROUP;
C_ASSERT(__alignof(SU_METADATA_COMPLETION) >= 16);
C_ASSERT((FIELD_OFFSET(SU_METADATA_ROOT, Cleanup) & 15) == 0);
C_ASSERT((FIELD_OFFSET(SU_METADATA_GROUP, Roots) & 15) == 0);
C_ASSERT(MEMORY_ALLOCATION_ALIGNMENT >= 16);

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

static volatile LONG MetadataInitialized;
static KSPIN_LOCK MetadataLock;
static SU_METADATA_GROUP *MetadataGroup;
static SU_METADATA_GROUP *MetadataRoutingGroup;
static BOOLEAN MetadataClosing;
static BOOLEAN MetadataReaping;
static BOOLEAN MetadataBootstrap;
static UINT64 MetadataRetiredSerial;
static KEVENT MetadataReaped;
static KEVENT MetadataWork;
static HANDLE MetadataThread;
static BOOLEAN MetadataWorkerStopping;
static SU_METADATA_GROUP *MetadataRetiringGroup;

_IRQL_requires_(PASSIVE_LEVEL)
static VOID MetadataFreeNode(_Inout_ SU_METADATA_NODE *Node);
static VOID MetadataRemoveChildLocked(_Inout_ SU_METADATA_GROUP *Group, _In_ ULONG ChildIndex);

typedef struct _SU_METADATA_REFUSAL_RECORD {
    UINT64 Sequence, Cookie, RootId, ChildId;
    UINT32 Role;
    NTSTATUS Status;
    UCHAR Operation;
} SU_METADATA_REFUSAL_RECORD;
static SU_METADATA_REFUSAL_RECORD MetadataRefusals[32];
static UINT64 MetadataRefusalSequence;

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
static VOID MetadataReap(_In_ SU_METADATA_GROUP *Group)
{
    SU_METADATA_NODE nodes[SU_METADATA_NODES];
    PFILE_OBJECT originals[SU_METADATA_ROOTS];
    PFLT_PORT port = NULL;
    BOOLEAN release = FALSE, ready = TRUE;
    ULONG i;
    KIRQL irql;
    RtlZeroMemory(nodes, sizeof(nodes));
    RtlZeroMemory(originals, sizeof(originals));
    KeAcquireSpinLock(&MetadataLock, &irql);
    if (Group->RootBusy) { KeReleaseSpinLock(&MetadataLock, irql); return; }
    if (!Group->AnchorsClosed) {
        Group->AnchorsClosed = TRUE;
        release = TRUE;
        RtlCopyMemory(nodes, Group->Nodes, sizeof(nodes));
        RtlZeroMemory(Group->Nodes, sizeof(Group->Nodes));
        for (i = 0; i < SU_METADATA_ROOTS; ++i) {
            originals[i] = Group->Roots[i].Original;
            Group->Roots[i].Original = NULL;
        }
        port = Group->ResourcePort;
        Group->ResourcePort = NULL;
    }
    KeReleaseSpinLock(&MetadataLock, irql);
    if (release) {
        if (port != NULL) FltCloseClientPort(SafeUploadData.Filter, &port);
        i = SU_METADATA_NODES;
        while (i != 0) MetadataFreeNode(&nodes[--i]);
        /* Drop the owned references while the nonowning root keys still
         * route a resulting CLOSE. No filesystem or object release under M. */
        for (i = 0; i < SU_METADATA_ROOTS; ++i)
            if (originals[i] != NULL) ObDereferenceObject(originals[i]);
    }
    KeAcquireSpinLock(&MetadataLock, &irql);
    for (i = 0; i < SU_METADATA_ROOTS; ++i) {
        if (Group->ForceForgetKeys) Group->Roots[i].Key = NULL;
        if (Group->Roots[i].Key != NULL) ready = FALSE;
    }
    if (Group->PostOwners != 0) ready = FALSE;
    if (ready) {
        NT_ASSERT(MetadataRoutingGroup == Group);
        MetadataRoutingGroup = NULL;
        MetadataRetiringGroup = NULL;
    }
    KeReleaseSpinLock(&MetadataLock, irql);
    if (!ready) return; /* CLOSE/post/local teardown will wake this owner */
    ExWaitForRundownProtectionRelease(&Group->Rundown);
    if (Group->Instance != NULL) FltObjectDereference(Group->Instance);
    if (Group->Volume != NULL) FltObjectDereference(Group->Volume);
    PsDereferencePrimaryToken(Group->Token);
    ObDereferenceObject(Group->Process);
    ExFreePoolWithTag(Group, SU_METADATA_TAG);
    KeAcquireSpinLock(&MetadataLock, &irql);
    MetadataReaping = FALSE;
    KeSetEvent(&MetadataReaped, IO_NO_INCREMENT, FALSE);
    KeReleaseSpinLock(&MetadataLock, irql);
}

_IRQL_requires_(PASSIVE_LEVEL)
static KSTART_ROUTINE MetadataWorker;
_Use_decl_annotations_
static VOID MetadataWorker(PVOID Parameter)
{
    SU_METADATA_GROUP *group;
    BOOLEAN stop;
    KIRQL irql;
    UNREFERENCED_PARAMETER(Parameter);
    for (;;) {
        (VOID)KeWaitForSingleObject(&MetadataWork, Executive, KernelMode, FALSE, NULL);
        KeAcquireSpinLock(&MetadataLock, &irql);
        group = MetadataRetiringGroup;
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
    RtlZeroMemory(MetadataRefusals, sizeof(MetadataRefusals));
    MetadataRefusalSequence = 0;
    MetadataGroup = NULL;
    MetadataRoutingGroup = NULL;
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
    InterlockedExchange(&MetadataInitialized, 1);
}

_Use_decl_annotations_
VOID SafeUploadMetadataRevoke(PVOID MainCookie)
{
    SU_METADATA_GROUP *group = NULL;
    ULONG i;
    KIRQL irql;
    KeAcquireSpinLock(&MetadataLock, &irql);
    if (MetadataGroup != NULL &&
        (MainCookie == NULL || MainCookie == MetadataGroup->MainCookie)) {
        group = MetadataGroup;
        group->Revoked = TRUE; /* authority disappears before either port close */
        for (i = 0; i < SU_METADATA_CHILDREN; ++i)
            if (group->Children[i].State == SuMetadataPendingOpen) MetadataRemoveChildLocked(group, i);
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
    if (MetadataRoutingGroup != NULL) MetadataRoutingGroup->ForceForgetKeys = TRUE;
    KeReleaseSpinLock(&MetadataLock, irql);
    SafeUploadMetadataRevoke(NULL);
    KeSetEvent(&MetadataWork, IO_NO_INCREMENT, FALSE);
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
    KeAcquireSpinLock(&MetadataLock, &irql);
    original = !MetadataClosing && !MetadataReaping && MetadataGroup == NULL &&
        (UINT64)(ULONG_PTR)Cookie > MetadataRetiredSerial;
    KeReleaseSpinLock(&MetadataLock, irql);
    if (!original) return STATUS_DEVICE_BUSY; /* before allocating another group */
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
        MetadataRoutingGroup = candidate;
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

/* Fixed signed graph: volume -> ProgramData -> SafeUpload; staging and
 * staging-journal are siblings. No caller-controlled locator is consumed. */
static const PCWSTR MetadataNodeNames[SU_METADATA_NODES] = {
    L"", L"ProgramData", L"SafeUpload", L"staging", L".space-reservations",
    L"staging-journal", L"completed"
};
static const ULONG MetadataNodeParents[SU_METADATA_NODES] = {0, 0, 1, 2, 3, 2, 5};
static const ULONG MetadataRoleNodes[SU_METADATA_ROOTS] = {3, 4, 5, 6};
static const struct {
    UCHAR Revision, Count;
    SID_IDENTIFIER_AUTHORITY Authority;
    ULONG Parts[6];
} MetadataTrustedInstaller = {
    SID_REVISION, 6, SECURITY_NT_AUTHORITY,
    {80, 956008885UL, 3418522649UL, 1831038044UL, 1853292631UL, 2271478464UL}
};

typedef struct _SU_METADATA_CAPTURE {
    SU_METADATA_NODE Nodes[SU_METADATA_NODES];
    PFLT_VOLUME Volume;
    PFLT_INSTANCE Instance;
    WCHAR DeviceBuffer[512], SystemBuffer[512];
    UCHAR Scratch[SU_METADATA_SD_BYTES];
} SU_METADATA_CAPTURE;

_IRQL_requires_(PASSIVE_LEVEL)
static VOID MetadataFreeNode(_Inout_ SU_METADATA_NODE *Node)
{
    if (Node->Handle != NULL) FltClose(Node->Handle);
    if (Node->Object != NULL) ObDereferenceObject(Node->Object);
    if (Node->Security != NULL) ExFreePoolWithTag(Node->Security, SU_METADATA_TAG);
    RtlZeroMemory(Node, sizeof(*Node));
}

_IRQL_requires_(PASSIVE_LEVEL)
static VOID MetadataFreeCapture(_Inout_ SU_METADATA_CAPTURE *Capture)
{
    ULONG i = SU_METADATA_NODES;
    while (i != 0) MetadataFreeNode(&Capture->Nodes[--i]);
    if (Capture->Instance != NULL) FltObjectDereference(Capture->Instance);
    if (Capture->Volume != NULL) FltObjectDereference(Capture->Volume);
    ExFreePoolWithTag(Capture, SU_METADATA_TAG);
}

_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN MetadataTrustedSid(_In_ PSID Sid, _In_ BOOLEAN WindowsAncestor)
{
    return RtlEqualSid(Sid, SeExports->SeLocalSystemSid) ||
        RtlEqualSid(Sid, SeExports->SeAliasAdminsSid) ||
        (WindowsAncestor && RtlEqualSid(Sid, (PSID)&MetadataTrustedInstaller));
}

/* The caller already validated the bounded self-relative descriptor. */
_IRQL_requires_(PASSIVE_LEVEL)
_Success_(return != FALSE)
static BOOLEAN MetadataSecurityParts(_In_ PSECURITY_DESCRIPTOR Security,
    _Outptr_ PSID *Owner, _Outptr_ PACL *Dacl, _Out_ PBOOLEAN Protected)
{
    BOOLEAN defaulted, present;
    PISECURITY_DESCRIPTOR_RELATIVE relative = Security;
    *Owner = NULL;
    *Dacl = NULL;
    *Protected = FALSE;
    if (!NT_SUCCESS(RtlGetOwnerSecurityDescriptor(Security, Owner, &defaulted)) ||
        *Owner == NULL || !RtlValidSid(*Owner) ||
        !NT_SUCCESS(RtlGetDaclSecurityDescriptor(Security, &present, Dacl, &defaulted)) ||
        !present || *Dacl == NULL) return FALSE;
    *Protected = BooleanFlagOn(relative->Control, SE_DACL_PROTECTED);
    return relative->Revision == SECURITY_DESCRIPTOR_REVISION &&
        FlagOn(relative->Control, SE_SELF_RELATIVE);
}

/* No deny-cancellation inference: an unsafe allow refuses even if another ACE
 * might deny it. Generic masks are expanded before either predicate. */
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN MetadataSecurityPredicate(_In_ const SU_METADATA_NODE *Node,
    _In_ BOOLEAN WindowsAncestor, _In_ BOOLEAN InstallationParent,
    _In_opt_ const SU_METADATA_NODE *Child)
{
    PSID owner, childOwner = NULL;
    PACL dacl, childDacl;
    BOOLEAN protectedDacl, childProtected = FALSE;
    ULONG i;
    const ACCESS_MASK mutations = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
        FILE_WRITE_ATTRIBUTES | DELETE | FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER;
    const ACCESS_MASK destructive = DELETE | FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER |
        FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES;
    GENERIC_MAPPING mapping = {FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
    if (!MetadataSecurityParts(Node->Security, &owner, &dacl, &protectedDacl) ||
        !MetadataTrustedSid(owner, WindowsAncestor && !InstallationParent) ||
        (!WindowsAncestor && !protectedDacl)) return FALSE;
    if (Child != NULL && !MetadataSecurityParts(Child->Security, &childOwner, &childDacl, &childProtected))
        return FALSE;
    for (i = 0; i < dacl->AceCount; ++i) {
        PVOID ace = NULL;
        PACCESS_ALLOWED_ACE allow;
        PACE_HEADER header;
        PSID sid;
        ACCESS_MASK mask;
        BOOLEAN trusted;
        if (!NT_SUCCESS(RtlGetAce(dacl, i, &ace)) || ace == NULL) return FALSE;
        header = ace;
        if ((header->AceType != ACCESS_ALLOWED_ACE_TYPE && header->AceType != ACCESS_DENIED_ACE_TYPE) ||
            (header->AceFlags & ~(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE |
                INHERIT_ONLY_ACE | INHERITED_ACE)) != 0 ||
            header->AceSize < FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + 8) return FALSE;
        allow = ace;
        sid = (PSID)&allow->SidStart;
        if (((PISID)sid)->SubAuthorityCount > SID_MAX_SUB_AUTHORITIES ||
            FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + 8UL +
                4UL * ((PISID)sid)->SubAuthorityCount != header->AceSize || !RtlValidSid(sid))
            return FALSE;
        mask = allow->Mask;
        RtlMapGenericMask(&mask, &mapping);
        if ((mask & ~FILE_ALL_ACCESS) != 0) return FALSE;
        if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
        trusted = MetadataTrustedSid(sid, WindowsAncestor && !InstallationParent);
        if (!WindowsAncestor) {
            if (!trusted && (mask & mutations) != 0) return FALSE;
        } else {
            if (!trusted && !FlagOn(header->AceFlags, INHERIT_ONLY_ACE) && (mask & destructive) != 0)
                return FALSE;
            if (!trusted && Child != NULL && !childProtected &&
                FlagOn(header->AceFlags, CONTAINER_INHERIT_ACE) && (mask & destructive) != 0) {
                /* CREATOR_OWNER substitutes the already trusted next owner;
                 * it is not accepted as an effective ACE on this ancestor. */
                if (!RtlEqualSid(sid, SeExports->SeCreatorOwnerSid) || childOwner == NULL ||
                    !MetadataTrustedSid(childOwner, TRUE)) return FALSE;
            }
        }
    }
    return TRUE;
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS MetadataQueryDirectory(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT Object,
    _Out_ SAFEUPLOAD_STAGE_IDENTITY_V19 *Identity)
{
    FILE_ID_INFORMATION id;
    FILE_STANDARD_INFORMATION standard;
    FILE_ATTRIBUTE_TAG_INFORMATION tag;
    ULONG bytes = 0;
    NTSTATUS status;
    status = FltQueryInformationFile(Instance, Object, &standard, sizeof(standard), FileStandardInformation, &bytes);
    if (!NT_SUCCESS(status)) return status;
    if (bytes != sizeof(standard) || !standard.Directory || standard.DeletePending) return STATUS_NOT_A_DIRECTORY;
    status = FltQueryInformationFile(Instance, Object, &tag, sizeof(tag), FileAttributeTagInformation, &bytes);
    if (!NT_SUCCESS(status)) return status;
    if (bytes != sizeof(tag) || FlagOn(tag.FileAttributes, FILE_ATTRIBUTE_REPARSE_POINT) || tag.ReparseTag != 0)
        return STATUS_REPARSE_POINT_ENCOUNTERED;
    status = FltQueryInformationFile(Instance, Object, &id, sizeof(id), FileIdInformation, &bytes);
    if (!NT_SUCCESS(status)) return status;
    if (bytes != sizeof(id)) return STATUS_INFO_LENGTH_MISMATCH;
    Identity->VolumeSerialNumber = id.VolumeSerialNumber;
    Identity->FileId = id.FileId;
    return MetadataZero(Identity, sizeof(*Identity)) ? STATUS_INVALID_PARAMETER : STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS MetadataCaptureSecurity(_In_ PFLT_INSTANCE Instance, _Inout_ SU_METADATA_NODE *Node)
{
    ULONG needed = 0;
    NTSTATUS status;
    SECURITY_INFORMATION information = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    status = FltQuerySecurityObject(Instance, Node->Object, information, NULL, 0, &needed);
    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW)
        return NT_SUCCESS(status) ? STATUS_INVALID_SECURITY_DESCR : status;
    if (needed < sizeof(SECURITY_DESCRIPTOR_RELATIVE) || needed > SU_METADATA_SD_BYTES)
        return STATUS_INVALID_SECURITY_DESCR;
    Node->Security = ExAllocatePool2(POOL_FLAG_PAGED, needed, SU_METADATA_TAG);
    if (Node->Security == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    Node->SecurityBytes = needed;
    status = FltQuerySecurityObject(Instance, Node->Object, information, Node->Security, needed, &needed);
    if (!NT_SUCCESS(status)) return status;
    if (!RtlValidRelativeSecurityDescriptor(Node->Security, Node->SecurityBytes, information))
        return STATUS_INVALID_SECURITY_DESCR;
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS MetadataReadLink(_In_ PCWSTR Name, _Inout_ PUNICODE_STRING Target)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attributes;
    HANDLE handle;
    NTSTATUS status;
    RtlInitUnicodeString(&name, Name);
    InitializeObjectAttributes(&attributes, &name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = ZwOpenSymbolicLinkObject(&handle, SYMBOLIC_LINK_QUERY, &attributes);
    if (!NT_SUCCESS(status)) return status;
    status = ZwQuerySymbolicLinkObject(handle, Target, NULL);
    ZwClose(handle);
    if (NT_SUCCESS(status) && (Target->Length == 0 || (Target->Length & 1) != 0)) status = STATUS_INVALID_PARAMETER;
    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS MetadataCheckProgramData(_Inout_ SU_METADATA_CAPTURE *Capture)
{
    UNICODE_STRING keyName, valueName, value, literal, expanded;
    OBJECT_ATTRIBUTES attributes;
    HANDLE key;
    ULONG returned;
    PKEY_VALUE_PARTIAL_INFORMATION data = (PKEY_VALUE_PARTIAL_INFORMATION)Capture->Scratch;
    NTSTATUS status;
    RtlInitUnicodeString(&keyName, L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList");
    RtlInitUnicodeString(&valueName, L"ProgramData");
    InitializeObjectAttributes(&attributes, &keyName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = ZwOpenKey(&key, KEY_QUERY_VALUE, &attributes);
    if (!NT_SUCCESS(status)) return status;
    status = ZwQueryValueKey(key, &valueName, KeyValuePartialInformation, data, sizeof(Capture->Scratch), &returned);
    ZwClose(key);
    if (!NT_SUCCESS(status)) return status;
    if (returned < (ULONG)FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) ||
        (data->Type != REG_SZ && data->Type != REG_EXPAND_SZ) || data->DataLength < 2 ||
        data->DataLength > 512 * sizeof(WCHAR) || (data->DataLength & 1) != 0 ||
        data->DataLength > returned - (ULONG)FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data)) return STATUS_INVALID_PARAMETER;
    value.Buffer = (PWCHAR)data->Data;
    value.MaximumLength = (USHORT)data->DataLength;
    value.Length = (USHORT)(value.MaximumLength - (USHORT)sizeof(WCHAR));
    if (value.Buffer[value.Length / sizeof(WCHAR)] != 0) return STATUS_INVALID_PARAMETER;
    RtlInitUnicodeString(&literal, L"C:\\ProgramData");
    RtlInitUnicodeString(&expanded, L"%SystemDrive%\\ProgramData");
    return RtlEqualUnicodeString(&value, &literal, TRUE) || RtlEqualUnicodeString(&value, &expanded, TRUE) ?
        STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS MetadataCaptureInstallation(_Inout_ SU_METADATA_CAPTURE *Capture)
{
    UNICODE_STRING device, system, name, actualVolume;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io;
    PSAFEUPLOAD_INSTANCE_CONTEXT context = NULL;
    FLT_FILESYSTEM_TYPE type;
    ULONG i;
    NTSTATUS status;
    const ACCESS_MASK access = READ_CONTROL | SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY;
    device.Buffer = Capture->DeviceBuffer;
    device.Length = 0;
    device.MaximumLength = sizeof(Capture->DeviceBuffer) - sizeof(WCHAR);
    system.Buffer = Capture->SystemBuffer;
    system.Length = 0;
    system.MaximumLength = sizeof(Capture->SystemBuffer);
    status = MetadataReadLink(L"\\GLOBAL??\\C:", &device);
    if (!NT_SUCCESS(status)) return status;
    status = MetadataReadLink(L"\\SystemRoot", &system);
    if (!NT_SUCCESS(status)) return status;
    if (!RtlPrefixUnicodeString(&device, &system, TRUE) || system.Length <= device.Length ||
        system.Buffer[device.Length / sizeof(WCHAR)] != L'\\') return STATUS_NOT_SUPPORTED;
    status = MetadataCheckProgramData(Capture);
    if (!NT_SUCCESS(status)) return status;
    status = FltGetVolumeFromName(SafeUploadData.Filter, &device, &Capture->Volume);
    if (!NT_SUCCESS(status)) return status;
    actualVolume.Buffer = (PWCHAR)Capture->Scratch;
    actualVolume.Length = 0;
    actualVolume.MaximumLength = 1024;
    status = FltGetVolumeName(Capture->Volume, &actualVolume, NULL);
    if (!NT_SUCCESS(status)) return status;
    if (!RtlEqualUnicodeString(&actualVolume, &device, TRUE)) return STATUS_NOT_SUPPORTED;
    status = FltGetVolumeInstanceFromName(SafeUploadData.Filter, Capture->Volume, NULL, &Capture->Instance);
    if (!NT_SUCCESS(status)) return status;
    status = FltGetInstanceContext(Capture->Instance, (PFLT_CONTEXT *)&context);
    if (!NT_SUCCESS(status)) return status;
    status = context->VolumeKind == SafeUploadVolumeFixed ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
    FltReleaseContext(context);
    if (!NT_SUCCESS(status)) return status;
    status = FltGetFileSystemType(Capture->Instance, &type);
    if (!NT_SUCCESS(status)) return status;
    if (type != FLT_FSTYPE_NTFS) return STATUS_NOT_SUPPORTED;
    device.Buffer[device.Length / sizeof(WCHAR)] = L'\\';
    device.Length = (USHORT)(device.Length + (USHORT)sizeof(WCHAR));
    device.MaximumLength = sizeof(Capture->DeviceBuffer);
    for (i = 0; i < SU_METADATA_NODES; ++i) {
        SU_METADATA_NODE *node = &Capture->Nodes[i];
        if (i == 0) name = device;
        else RtlInitUnicodeString(&name, MetadataNodeNames[i]);
        InitializeObjectAttributes(&attributes, &name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
            i == 0 ? NULL : Capture->Nodes[MetadataNodeParents[i]].Handle, NULL);
        RtlZeroMemory(&io, sizeof(io));
        status = FltCreateFileEx2(SafeUploadData.Filter, Capture->Instance, &node->Handle, &node->Object,
            access, &attributes, &io, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN, FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT |
            FILE_COMPLETE_IF_OPLOCKED, NULL, 0, IO_STOP_ON_SYMLINK, NULL);
        if (status == STATUS_STOPPED_ON_SYMLINK && io.Information != 0) ExFreePool((PVOID)io.Information);
        if (status != STATUS_SUCCESS) return NT_SUCCESS(status) ? STATUS_NOT_SUPPORTED : status;
        if (io.Information != FILE_OPENED) return STATUS_INVALID_PARAMETER;
        status = MetadataQueryDirectory(Capture->Instance, node->Object, &node->Identity);
        if (!NT_SUCCESS(status)) return status;
        if (i != 0 && node->Identity.VolumeSerialNumber != Capture->Nodes[0].Identity.VolumeSerialNumber)
            return STATUS_NOT_SAME_DEVICE;
        status = MetadataCaptureSecurity(Capture->Instance, node);
        if (!NT_SUCCESS(status)) return status;
    }
    if (!MetadataSecurityPredicate(&Capture->Nodes[0], TRUE, FALSE, &Capture->Nodes[1]) ||
        !MetadataSecurityPredicate(&Capture->Nodes[1], TRUE, FALSE, &Capture->Nodes[2]) ||
        !MetadataSecurityPredicate(&Capture->Nodes[2], TRUE, TRUE, &Capture->Nodes[3]) ||
        !MetadataSecurityPredicate(&Capture->Nodes[2], TRUE, TRUE, &Capture->Nodes[5])) return STATUS_ACCESS_DENIED;
    for (i = 3; i < SU_METADATA_NODES; ++i)
        if (!MetadataSecurityPredicate(&Capture->Nodes[i], FALSE, FALSE, NULL)) return STATUS_ACCESS_DENIED;
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS MetadataRegisterRoot(_In_ SU_METADATA_GROUP *Group,
    _In_ const SU_RESOURCE_ROOT_REQUEST *Request, _Out_ SU_RESOURCE_ROOT_REPLY *Reply)
{
    SU_METADATA_CAPTURE *capture = NULL;
    SU_METADATA_NODE *node;
    PFILE_OBJECT original = NULL;
    PFLT_VOLUME volume = NULL;
    SAFEUPLOAD_STAGE_IDENTITY_V19 identity;
    ULONG index, bytes = 0;
    BOOLEAN captureNeeded, publish = FALSE, revoke = FALSE;
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    KIRQL irql;
    Reply->Result = 2;
    if (Request->RootRole < 1 || Request->RootRole > 4 || Request->Flags != 0 || Request->Handle == 0 ||
        (UINT64)(ULONG_PTR)Request->Handle != Request->Handle || Request->SecurityContractVersion != 1 ||
        !MetadataZero(Request->Reserved, sizeof(Request->Reserved)) ||
        MetadataZero(&Request->Identity, sizeof(Request->Identity)) ||
        ((Request->RootRole == 1 || Request->RootRole == 3) != (Request->ParentRootId == 0))) return status;
    index = Request->RootRole - 1;
    KeAcquireSpinLock(&MetadataLock, &irql);
    if (Group->Revoked || !Group->Paired) status = STATUS_ACCESS_DENIED;
    else if (Group->RootBusy) status = STATUS_DEVICE_BUSY;
    else if ((index == 1 && (Group->Roots[0].Id == 0 || Group->Roots[0].Id != Request->ParentRootId ||
                         Group->Roots[0].Key == NULL || Group->Roots[0].Cleaned)) ||
             (index == 3 && (Group->Roots[2].Id == 0 || Group->Roots[2].Id != Request->ParentRootId ||
                         Group->Roots[2].Key == NULL || Group->Roots[2].Cleaned)))
        status = STATUS_INVALID_PARAMETER;
    else { Group->RootBusy = TRUE; status = STATUS_SUCCESS; }
    captureNeeded = Group->Instance == NULL;
    KeReleaseSpinLock(&MetadataLock, irql);
    if (!NT_SUCCESS(status)) return status;
    status = ObReferenceObjectByHandle((HANDLE)(ULONG_PTR)Request->Handle,
        READ_CONTROL | SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY,
        *IoFileObjectType, UserMode, (PVOID *)&original, NULL);
    if (!NT_SUCCESS(status)) goto Exit;
    if (!FlagOn(original->Flags, FO_HANDLE_CREATED) || FlagOn(original->Flags, FO_CLEANUP_COMPLETE)) {
        status = STATUS_INVALID_HANDLE;
        goto Exit;
    }
    capture = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*capture), SU_METADATA_TAG);
    if (capture == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    if (captureNeeded) {
        status = MetadataCaptureInstallation(capture);
        if (!NT_SUCCESS(status)) goto Exit;
    }
    node = captureNeeded ? &capture->Nodes[MetadataRoleNodes[index]] : &Group->Nodes[MetadataRoleNodes[index]];
    status = FltGetVolumeFromFileObject(SafeUploadData.Filter, original, &volume);
    if (!NT_SUCCESS(status)) goto Exit;
    if (volume != (captureNeeded ? capture->Volume : Group->Volume)) {
        status = STATUS_NOT_SAME_DEVICE;
        revoke = TRUE;
        goto Exit;
    }
    status = MetadataQueryDirectory(captureNeeded ? capture->Instance : Group->Instance, original, &identity);
    if (!NT_SUCCESS(status)) goto Exit;
    if (!RtlEqualMemory(&identity, &Request->Identity, sizeof(identity)) ||
        !RtlEqualMemory(&identity, &node->Identity, sizeof(identity))) {
        status = STATUS_INVALID_PARAMETER;
        revoke = TRUE;
        goto Exit;
    }
    status = FltQuerySecurityObject(captureNeeded ? capture->Instance : Group->Instance, original,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, capture->Scratch, node->SecurityBytes, &bytes);
    if (!NT_SUCCESS(status)) goto Exit;
    if (!RtlEqualMemory(capture->Scratch, node->Security, node->SecurityBytes)) {
        status = STATUS_INVALID_SECURITY_DESCR;
        revoke = TRUE;
        goto Exit;
    }
    /* Recheck original subject after the bounded native capture, outside the
     * map lock. The final publication latch checks live revocation again. */
    if (!MetadataAuthenticate(Group) || FlagOn(original->Flags, FO_CLEANUP_COMPLETE)) {
        status = STATUS_ACCESS_DENIED;
        goto Exit;
    }
    KeAcquireSpinLock(&MetadataLock, &irql);
    if (Group->Revoked) status = STATUS_ACCESS_DENIED;
    else if (Group->Roots[index].Id != 0) {
        if (Group->Roots[index].Key != original || Group->Roots[index].Cleaned) status = STATUS_INVALID_PARAMETER;
        else { Reply->RootId = Group->Roots[index].Id; publish = TRUE; }
    } else if (Group->NextRootId == (UINT64)MAXLONGLONG) status = STATUS_TOO_MANY_CONTEXT_IDS;
    else {
        if (captureNeeded) {
            RtlCopyMemory(Group->Nodes, capture->Nodes, sizeof(Group->Nodes));
            RtlZeroMemory(capture->Nodes, sizeof(capture->Nodes));
            Group->Instance = capture->Instance; capture->Instance = NULL;
            Group->Volume = capture->Volume; capture->Volume = NULL;
        }
        Group->Roots[index].Id = ++Group->NextRootId;
        Group->Roots[index].Original = original;
        Group->Roots[index].Key = original;
        original = NULL;
        Reply->RootId = Group->Roots[index].Id;
        publish = TRUE;
    }
    if (publish) {
        Reply->Result = 1;
        Reply->Identity = identity;
        status = STATUS_SUCCESS;
    }
    KeReleaseSpinLock(&MetadataLock, irql);
Exit:
    if (volume != NULL) FltObjectDereference(volume);
    if (original != NULL) ObDereferenceObject(original);
    if (capture != NULL) MetadataFreeCapture(capture);
    KeAcquireSpinLock(&MetadataLock, &irql);
    Group->RootBusy = FALSE;
    KeReleaseSpinLock(&MetadataLock, irql);
    if (revoke) SafeUploadMetadataRevoke(Group->MainCookie);
    KeSetEvent(&MetadataWork, IO_NO_INCREMENT, FALSE);
    return status;
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
    if (!MetadataZero(&Request->ReplaceTargetIdentity, sizeof(Request->ReplaceTargetIdentity)) &&
        (!output || Request->Role == SuSegment || Request->Role == SuHistoryCandidate ||
         (Request->AccessMask & (DELETE | FILE_WRITE_DATA)) != (DELETE | FILE_WRITE_DATA)))
        return STATUS_INVALID_PARAMETER;
    switch (Request->Role) {
    case SuCompanionCurrent: case SuCompanionNew: maximum = 192; break;
    case SuManifestCurrent: case SuManifestNew: case SuHistoryCandidate: maximum = 128 * 1024; break;
    case SuSegment: maximum = 4 * 1024 * 1024; break;
    case SuInventoryCurrent: maximum = 4 * 1024 * 1024; break; /* legacy bounded inventory reader */
    case SuInventoryNew: maximum = 128; break;
    case SuMarkerCurrent: case SuMarkerNew: maximum = 128; break;
    case SuEpochCurrent: case SuEpochNew: maximum = 4096; break;
    case SuLegacyNegative: maximum = 1192; break;
    case SuLegacySecurity:
        /* Existing StagedAllocationSecuritySnapshot.MaximumBytes:
         * 112 + 2*131228 + WriterMetadataV27 envelope(136+1024+2*131228).
         * Read/query only; no schema parser or write capability. */
        maximum = 526184;
        break;
    default: maximum = 64 * 1024; break;
    }
    if (Request->MaximumLogicalBytes > maximum) return STATUS_INVALID_PARAMETER;
    return STATUS_SUCCESS;
}

static BOOLEAN MetadataRoleRoot(_In_ ULONG Role, _In_ ULONG RootRole)
{
    switch (Role) {
    case SuLedgerCurrent: case SuLedgerNew: return RootRole == 2;
    case SuCompanionCurrent: case SuCompanionNew: return RootRole == 1;
    case SuManifestCurrent: case SuManifestNew: case SuLegacySecurity:
    case SuEpochCurrent: case SuEpochNew: case SuHistoryCandidate: return RootRole == 3;
    case SuMarkerCurrent: case SuMarkerNew: return RootRole == 2;
    case SuLegacyNegative: return RootRole == 1 || RootRole == 2;
    default: return RootRole == 4;
    }
}

static BOOLEAN MetadataHex(_In_reads_(Chars) const WCHAR *Text, _In_ ULONG Chars)
{
    ULONG i;
    for (i = 0; i < Chars; ++i)
        if (!((Text[i] >= L'0' && Text[i] <= L'9') || (Text[i] >= L'a' && Text[i] <= L'f') ||
            (Text[i] >= L'A' && Text[i] <= L'F'))) return FALSE;
    return Chars != 0;
}

_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN MetadataLeafRole(_In_ const SU_RESOURCE_CHILD_REQUEST *Request)
{
    PCWSTR fixed = NULL, suffix = NULL;
    UNICODE_STRING leaf, expected;
    ULONG chars = Request->LeafBytes / (ULONG)sizeof(WCHAR), baseChars = chars;
    BOOLEAN output = Request->Role == SuLedgerNew || Request->Role == SuCompanionNew ||
        Request->Role == SuManifestNew || Request->Role == SuInventoryNew || Request->Role == SuMarkerNew ||
        Request->Role == SuEpochNew || Request->Role == SuAppendIntentNew || Request->Role == SuCompactionIntentNew;
    leaf.Buffer = (PWCHAR)Request->Leaf;
    leaf.Length = leaf.MaximumLength = (USHORT)Request->LeafBytes;
    if (output) {
        UNICODE_STRING tail;
        RtlInitUnicodeString(&tail, L".new");
        if (RtlSuffixUnicodeString(&tail, &leaf, TRUE)) baseChars -= 4;
        else {
            RtlInitUnicodeString(&tail, L".tmp");
            if (chars <= 37 || !RtlSuffixUnicodeString(&tail, &leaf, TRUE) ||
                Request->Leaf[chars - 37] != L'.' || !MetadataHex(Request->Leaf + chars - 36, 32)) return FALSE;
            baseChars -= 37;
        }
        leaf.Length = leaf.MaximumLength = (USHORT)(baseChars * sizeof(WCHAR));
    }
    switch (Request->Role) {
    case SuEpochCurrent: case SuEpochNew: fixed = L"driver-epoch.state"; break;
    case SuInventoryCurrent: case SuInventoryNew: fixed = L"segments.state"; break;
    case SuMarkerCurrent: case SuMarkerNew: fixed = L"resource-format.marker"; break;
    case SuAppendIntentCurrent: case SuAppendIntentNew: fixed = L"append.intent"; break;
    case SuCompactionIntentCurrent: case SuCompactionIntentNew: fixed = L"compaction.intent"; break;
    case SuLedgerCurrent: case SuLedgerNew: case SuLegacyNegative:
    case SuManifestCurrent: case SuManifestNew: suffix = L".json"; break;
    case SuLegacySecurity: suffix = L".security"; break;
    case SuHistoryCandidate: suffix = L".resource"; break;
    case SuCompanionCurrent: case SuCompanionNew:
        RtlInitUnicodeString(&expected, L".space");
        return baseChars > 38 && MetadataHex(Request->Leaf, 32) && Request->Leaf[32] == L'.' &&
            RtlSuffixUnicodeString(&expected, &leaf, TRUE);
    case SuSegment:
        RtlInitUnicodeString(&expected, L".pack");
        return (baseChars == 13 || baseChars == 37) && MetadataHex(Request->Leaf, baseChars - 5) &&
            RtlSuffixUnicodeString(&expected, &leaf, TRUE);
    default: return FALSE;
    }
    if (fixed != NULL) {
        RtlInitUnicodeString(&expected, fixed);
        return RtlEqualUnicodeString(&leaf, &expected, TRUE);
    }
    RtlInitUnicodeString(&expected, suffix);
    return baseChars == 32 + expected.Length / sizeof(WCHAR) && MetadataHex(Request->Leaf, 32) &&
        RtlSuffixUnicodeString(&expected, &leaf, TRUE);
}

/* MetadataLock held. No child completion may retain this credit: this pass
 * refuses every claimed child CREATE synchronously, before lower dispatch. */
static VOID MetadataRemoveChildLocked(_Inout_ SU_METADATA_GROUP *Group, _In_ ULONG ChildIndex)
{
    SU_METADATA_CHILD *child = &Group->Children[ChildIndex];
    SU_METADATA_TRANSACTION *transaction = &Group->Transactions[ChildIndex / SU_METADATA_CHILDREN_PER_TRANSACTION];
    NT_ASSERT(child->State == SuMetadataPendingOpen || child->State == SuMetadataOpening);
    if (child->State == SuMetadataPendingOpen) transaction->Pending = FALSE;
    RtlZeroMemory(child, sizeof(*child));
    NT_ASSERT(transaction->Children != 0);
    if (--transaction->Children == 0) RtlZeroMemory(transaction, sizeof(*transaction));
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS MetadataFoldLeaf(_In_reads_bytes_(Bytes) const WCHAR *Leaf, _In_ USHORT Bytes,
    _Out_writes_bytes_(512) WCHAR *Folded)
{
    UNICODE_STRING source, destination;
    source.Buffer = (PWCHAR)Leaf;
    source.Length = source.MaximumLength = Bytes;
    destination.Buffer = Folded;
    destination.Length = 0;
    destination.MaximumLength = 512;
    RtlZeroMemory(Folded, 512);
    return RtlUpcaseUnicodeString(&destination, &source, FALSE);
}

static BOOLEAN MetadataTransactionClass(_In_ const GUID *Id, _In_ ULONG Role,
    _Out_ GUID *Masked, _Out_ PBOOLEAN Growth)
{
    *Masked = *Id;
    *Growth = BooleanFlagOn(((const UCHAR *)Id)[15], 0x80);
    ((PUCHAR)Masked)[15] &= 0x7f;
    return !MetadataZero(Masked, sizeof(*Masked)) && Role >= SuLedgerCurrent &&
        Role <= SuCompactionIntentNew && (!*Growth || Role <= SuCompanionNew);
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS MetadataRegisterChild(_In_ SU_METADATA_GROUP *Group,
    _In_ const SU_RESOURCE_CHILD_REQUEST *Request, _Out_ SU_RESOURCE_CHILD_REPLY *Reply)
{
    GUID masked, other;
    ULONG i, root = SU_METADATA_ROOTS, transaction = SU_METADATA_TRANSACTIONS;
    ULONG first, end, childIndex = SU_METADATA_CHILDREN;
    BOOLEAN growth;
    WCHAR folded[256];
    NTSTATUS status;
    KIRQL irql;
    Reply->Result = 2;
    status = MetadataChildShape(Request);
    if (!NT_SUCCESS(status)) return status;
    if (!MetadataTransactionClass(&Request->TransactionId, Request->Role, &masked, &growth) ||
        !MetadataLeafRole(Request)) return STATUS_INVALID_PARAMETER;
    status = MetadataFoldLeaf(Request->Leaf, (USHORT)Request->LeafBytes, folded);
    if (!NT_SUCCESS(status)) return status;
    KeAcquireSpinLock(&MetadataLock, &irql);
    if (Group->Revoked) { status = STATUS_ACCESS_DENIED; goto Unlock; }
    for (i = 0; i < SU_METADATA_ROOTS; ++i)
        if (Group->Roots[i].Id == Request->RootId && Group->Roots[i].Key != NULL && !Group->Roots[i].Cleaned) { root = i; break; }
    if (root == SU_METADATA_ROOTS || !MetadataRoleRoot(Request->Role, root + 1)) {
        status = STATUS_INVALID_PARAMETER; goto Unlock;
    }
    first = growth ? 0 : 8;
    end = first + 8;
    for (i = 0; i < SU_METADATA_TRANSACTIONS; ++i) {
        if (Group->Transactions[i].Children == 0) continue;
        other = Group->Transactions[i].Id;
        ((PUCHAR)&other)[15] &= 0x7f;
        if (!RtlEqualMemory(&masked, &other, sizeof(masked))) continue;
        if (!RtlEqualMemory(&Request->TransactionId, &Group->Transactions[i].Id, sizeof(GUID))) {
            status = STATUS_INVALID_PARAMETER; goto Unlock;
        }
        transaction = i;
    }
    /* Short pending namespace claim. Native target-handle exclusion is not
     * implemented; every child open is still refused before lower dispatch. */
    for (i = 0; i < SU_METADATA_CHILDREN; ++i) {
        const SU_METADATA_CHILD *held = &Group->Children[i];
        if (held->State == 0 || held->Request.RootId != Request->RootId) continue;
        if ((held->Request.LeafBytes == Request->LeafBytes &&
             RtlEqualMemory(held->FoldedLeaf, folded, Request->LeafBytes)) ||
            (!MetadataZero(&Request->ReplaceTargetIdentity, sizeof(Request->ReplaceTargetIdentity)) &&
             (RtlEqualMemory(&Request->ReplaceTargetIdentity, &held->Request.ReplaceTargetIdentity,
                 sizeof(Request->ReplaceTargetIdentity)) ||
              RtlEqualMemory(&Request->ReplaceTargetIdentity, &held->Request.ExpectedIdentity,
                 sizeof(Request->ReplaceTargetIdentity)))) ||
            (!MetadataZero(&held->Request.ReplaceTargetIdentity, sizeof(held->Request.ReplaceTargetIdentity)) &&
             RtlEqualMemory(&held->Request.ReplaceTargetIdentity, &Request->ExpectedIdentity,
                 sizeof(Request->ExpectedIdentity)))) {
            if (held->State == SuMetadataPendingOpen && RtlEqualMemory(&held->Request, Request, sizeof(*Request))) {
                Reply->Result = 1; Reply->ChildIntentId = held->Id; status = STATUS_SUCCESS;
            } else status = RtlEqualMemory(&held->Request.TransactionId, &Request->TransactionId, sizeof(GUID)) ?
                STATUS_INVALID_PARAMETER : STATUS_DEVICE_BUSY;
            goto Unlock;
        }
    }
    if (transaction == SU_METADATA_TRANSACTIONS) {
        for (i = first; i < end; ++i)
            if (Group->Transactions[i].Children == 0) { transaction = i; break; }
        if (transaction == SU_METADATA_TRANSACTIONS) { status = STATUS_DEVICE_BUSY; goto Unlock; }
    }
    first = transaction * SU_METADATA_CHILDREN_PER_TRANSACTION;
    end = first + SU_METADATA_CHILDREN_PER_TRANSACTION;
    for (i = first; i < end; ++i) {
        SU_METADATA_CHILD *child = &Group->Children[i];
        if (child->State == 0) { childIndex = i; continue; }
        if (child->Request.RootId == Request->RootId && child->Request.LeafBytes == Request->LeafBytes &&
            RtlEqualMemory(child->Request.Leaf, Request->Leaf, Request->LeafBytes)) {
            if (child->State == SuMetadataPendingOpen && RtlEqualMemory(&child->Request, Request, sizeof(*Request))) {
                Reply->Result = 1; Reply->ChildIntentId = child->Id; status = STATUS_SUCCESS;
            } else status = STATUS_INVALID_PARAMETER;
            goto Unlock;
        }
    }
    if (Group->Transactions[transaction].Pending || childIndex == SU_METADATA_CHILDREN) {
        status = STATUS_DEVICE_BUSY; goto Unlock;
    }
    if (Group->NextChildId == (UINT64)MAXLONGLONG) { status = STATUS_TOO_MANY_CONTEXT_IDS; goto Unlock; }
    Group->Transactions[transaction].Id = Request->TransactionId;
    ++Group->Transactions[transaction].Children;
    Group->Transactions[transaction].Pending = TRUE;
    Group->Children[childIndex].Id = ++Group->NextChildId;
    Group->Children[childIndex].Request = *Request;
    RtlCopyMemory(Group->Children[childIndex].FoldedLeaf, folded, Request->LeafBytes);
    Group->Children[childIndex].State = SuMetadataPendingOpen;
    Reply->Result = 1;
    Reply->ChildIntentId = Group->Children[childIndex].Id;
    status = STATUS_SUCCESS;
Unlock:
    KeReleaseSpinLock(&MetadataLock, irql);
    return status;
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
#pragma warning(suppress: 6001) /* ProbeForWrite never reads the buffer; same idiom as Communication.c */
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
            if (group == NULL) { status = STATUS_ACCESS_DENIED; break; }
            status = MetadataRegisterRoot(group, &buffer->Request.Root, &buffer->Reply.Root);
            /* A root refusal has a typed reply and zero authority. Native
             * access/shape failures also refuse, never a successful map entry. */
            if (status != STATUS_DEVICE_BUSY && !NT_SUCCESS(status)) status = STATUS_SUCCESS;
            break;
        case SU_RESOURCE_REGISTER_CHILD:
            if (group == NULL) { status = STATUS_ACCESS_DENIED; break; }
            status = MetadataRegisterChild(group, &buffer->Request.Child, &buffer->Reply.Child);
            if (status != STATUS_DEVICE_BUSY && !NT_SUCCESS(status)) status = STATUS_SUCCESS;
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
        KeSetEvent(&MetadataWork, IO_NO_INCREMENT, FALSE);
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

_Use_decl_annotations_
VOID SafeUploadMetadataNoteRefusal(const SU_METADATA_DISPATCH *Dispatch, UCHAR MajorFunction, NTSTATUS Status)
{
    SU_METADATA_REFUSAL_RECORD *record;
    KIRQL irql;
    if (!Dispatch->Handled || NT_SUCCESS(Status)) return;
    KeAcquireSpinLock(&MetadataLock, &irql);
    if (MetadataRefusalSequence < (UINT64)MAXLONGLONG) ++MetadataRefusalSequence;
    record = &MetadataRefusals[MetadataRefusalSequence % RTL_NUMBER_OF(MetadataRefusals)];
    record->Sequence = MetadataRefusalSequence;
    record->Cookie = Dispatch->Cookie;
    record->RootId = Dispatch->RootId;
    record->ChildId = Dispatch->ChildId;
    record->Role = Dispatch->Role;
    record->Status = Status;
    record->Operation = MajorFunction;
    KeReleaseSpinLock(&MetadataLock, irql);
}

_Use_decl_annotations_
VOID SafeUploadMetadataInstanceTeardown(PFLT_INSTANCE Instance)
{
    BOOLEAN revoke = FALSE;
    KIRQL irql;
    if (InterlockedCompareExchange(&MetadataInitialized, 0, 0) == 0) return;
    KeAcquireSpinLock(&MetadataLock, &irql);
    if (MetadataRoutingGroup != NULL &&
        (MetadataRoutingGroup->Instance == Instance || MetadataRoutingGroup->RootBusy)) {
        MetadataRoutingGroup->ForceForgetKeys = TRUE;
        revoke = TRUE;
    }
    KeReleaseSpinLock(&MetadataLock, irql);
    if (revoke) SafeUploadMetadataRevoke(NULL);
    KeSetEvent(&MetadataWork, IO_NO_INCREMENT, FALSE);
}

/* Only exact embedded owners can be decoded; never dereference an arbitrary
 * tagged address, or reinterpret an epoch/legacy completion as metadata. */
_Use_decl_annotations_
BOOLEAN SafeUploadMetadataIsContext(PVOID Context)
{
    SU_METADATA_GROUP *group;
    ULONG i;
    BOOLEAN found = FALSE;
    KIRQL irql;
    if (InterlockedCompareExchange(&MetadataInitialized, 0, 0) == 0 ||
        (ULONG_PTR)Context < (ULONG_PTR)MmSystemRangeStart || ((ULONG_PTR)Context & 15) != 3) return FALSE;
    KeAcquireSpinLock(&MetadataLock, &irql);
    group = MetadataRoutingGroup;
    if (group != NULL) {
        for (i = 0; i < SU_METADATA_ROOTS; ++i) {
            SU_METADATA_COMPLETION *completion = &group->Roots[i].Cleanup;
            if ((PVOID)((ULONG_PTR)completion | 3) == Context && completion->InUse &&
                completion->Signature == SU_METADATA_CONTEXT_SIGNATURE && completion->Group == group &&
                completion->RootIndex == i && completion->Incarnation == group->Roots[i].Id &&
                completion->Object != NULL && completion->Operation == IRP_MJ_CLEANUP) { found = TRUE; break; }
        }
    }
    KeReleaseSpinLock(&MetadataLock, irql);
    return found;
}

_Use_decl_annotations_
FLT_PREOP_CALLBACK_STATUS SafeUploadMetadataPre(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS Objects,
    PVOID *Context, SU_METADATA_DISPATCH *Dispatch)
{
    SU_METADATA_GROUP *group;
    SU_METADATA_ROOT *root;
    ULONG i, index = SU_METADATA_ROOTS, child = SU_METADATA_CHILDREN;
    PFILE_OBJECT object, related;
    UCHAR operation = Data->Iopb->MajorFunction;
    WCHAR leaf[256];
    WCHAR folded[256];
    USHORT leafBytes = 0;
    BOOLEAN validSubject = FALSE, live = FALSE, inputValid = FALSE;
    NTSTATUS refusal = STATUS_DEVICE_NOT_READY;
    KIRQL irql;
    RtlZeroMemory(Dispatch, sizeof(*Dispatch));
    *Context = NULL;
    if (InterlockedCompareExchange(&MetadataInitialized, 0, 0) == 0 || Objects->FileObject == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    object = Objects->FileObject;
    related = operation == IRP_MJ_CREATE ? object->RelatedFileObject : NULL;
    KeAcquireSpinLock(&MetadataLock, &irql);
    group = MetadataRoutingGroup;
    if (group != NULL) {
        for (i = 0; i < SU_METADATA_ROOTS; ++i) {
            if (group->Roots[i].Key != NULL &&
                group->Roots[i].Key == (operation == IRP_MJ_CREATE ? related : object)) { index = i; break; }
        }
    }
    if (index == SU_METADATA_ROOTS || !ExAcquireRundownProtection(&group->Rundown)) {
        KeReleaseSpinLock(&MetadataLock, irql);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    root = &group->Roots[index];
    Dispatch->Handled = TRUE;
    Dispatch->Cookie = (UINT64)(ULONG_PTR)group->MainCookie;
    Dispatch->RootId = root->Id;
    live = !group->Revoked && !root->Cleaned && Objects->Instance == group->Instance;
    if (operation == IRP_MJ_CLOSE) {
        root->Key = NULL; /* before the original FILE_OBJECT address can recycle */
        KeReleaseSpinLock(&MetadataLock, irql);
        ExReleaseRundownProtection(&group->Rundown);
        KeSetEvent(&MetadataWork, IO_NO_INCREMENT, FALSE);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (operation == IRP_MJ_CLEANUP) {
        root->Cleaned = TRUE;
        for (i = 0; i < SU_METADATA_CHILDREN; ++i)
            if (group->Children[i].State == SuMetadataPendingOpen &&
                group->Children[i].Request.RootId == root->Id) MetadataRemoveChildLocked(group, i);
        if (!root->Cleanup.InUse) {
            root->Cleanup.Signature = SU_METADATA_CONTEXT_SIGNATURE;
            root->Cleanup.Group = group;
            root->Cleanup.Object = object;
            root->Cleanup.Incarnation = root->Id;
            root->Cleanup.RootIndex = index;
            root->Cleanup.Operation = operation;
            root->Cleanup.InUse = TRUE;
            ++group->PostOwners;
            *Context = (PVOID)((ULONG_PTR)&root->Cleanup | 3);
            KeReleaseSpinLock(&MetadataLock, irql);
            return FLT_PREOP_SUCCESS_WITH_CALLBACK; /* context owns the pin */
        }
        KeReleaseSpinLock(&MetadataLock, irql);
        ExReleaseRundownProtection(&group->Rundown);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    KeReleaseSpinLock(&MetadataLock, irql);
    if (FLT_IS_FASTIO_OPERATION(Data)) {
        ExReleaseRundownProtection(&group->Rundown);
        return FLT_PREOP_DISALLOW_FASTIO;
    }
    if (operation == IRP_MJ_CREATE && KeGetCurrentIrql() == PASSIVE_LEVEL && live) {
        validSubject = PsGetCurrentProcess() == group->Process && FltGetRequestorProcess(Data) == group->Process &&
            MetadataAuthenticate(group);
        if (validSubject && object->FileName.Buffer != NULL && object->FileName.Length != 0 &&
            object->FileName.Length <= 510 && (object->FileName.Length & 1) == 0) {
            leafBytes = object->FileName.Length;
            RtlCopyMemory(leaf, object->FileName.Buffer, leafBytes);
            inputValid = NT_SUCCESS(MetadataFoldLeaf(leaf, leafBytes, folded));
        }
        KeAcquireSpinLock(&MetadataLock, &irql);
        if (validSubject && inputValid && !group->Revoked && !root->Cleaned) {
            for (i = 0; i < SU_METADATA_CHILDREN; ++i) {
                SU_METADATA_CHILD *intent = &group->Children[i];
                if (intent->State == SuMetadataPendingOpen && intent->Request.RootId == root->Id &&
                    intent->Request.LeafBytes == leafBytes && RtlEqualMemory(intent->FoldedLeaf, folded, leafBytes)) {
                    child = i;
                    Dispatch->ChildId = intent->Id;
                    Dispatch->Role = intent->Request.Role;
                    /* Claim and consume before refusing. No lower CREATE, new
                     * context or FILE_OBJECT reference is retained in this pass. */
                    intent->State = SuMetadataOpening;
                    group->Transactions[i / SU_METADATA_CHILDREN_PER_TRANSACTION].Pending = FALSE;
                    break;
                }
            }
        }
        if (child != SU_METADATA_CHILDREN) MetadataRemoveChildLocked(group, child);
        else refusal = STATUS_ACCESS_DENIED;
        KeReleaseSpinLock(&MetadataLock, irql);
    } else if (operation != IRP_MJ_CREATE) refusal = STATUS_NOT_SUPPORTED;
    /* No lower native child operation is implemented. This also refuses
     * unmatched leaves under a registered root without generic name/policy work. */
    Data->IoStatus.Status = refusal;
    Data->IoStatus.Information = 0;
    ExReleaseRundownProtection(&group->Rundown);
    KeSetEvent(&MetadataWork, IO_NO_INCREMENT, FALSE);
    return FLT_PREOP_COMPLETE;
}

_Use_decl_annotations_
FLT_POSTOP_CALLBACK_STATUS SafeUploadMetadataPost(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS Objects,
    PVOID Context, FLT_POST_OPERATION_FLAGS Flags)
{
    SU_METADATA_COMPLETION *completion = (SU_METADATA_COMPLETION *)((ULONG_PTR)Context & ~(ULONG_PTR)15);
    SU_METADATA_GROUP *group = completion->Group;
    BOOLEAN revoke;
    KIRQL irql;
    /* No paged pre-input, lower I/O, cancellation or object release at drain.
     * The exact embedded owner retains group storage through this return. */
    KeAcquireSpinLock(&MetadataLock, &irql);
    NT_ASSERT(completion->InUse && completion->Signature == SU_METADATA_CONTEXT_SIGNATURE);
    revoke = completion->RootIndex >= SU_METADATA_ROOTS || completion->Group != MetadataRoutingGroup ||
        completion->Object != Objects->FileObject || completion->Operation != Data->Iopb->MajorFunction ||
        (completion->RootIndex < SU_METADATA_ROOTS &&
         completion->Incarnation != group->Roots[completion->RootIndex].Id) ||
        completion->Operation != IRP_MJ_CLEANUP ||
        FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) || !NT_SUCCESS(Data->IoStatus.Status);
    completion->InUse = FALSE;
    completion->Signature = 0;
    NT_ASSERT(group->PostOwners != 0);
    --group->PostOwners;
    KeReleaseSpinLock(&MetadataLock, irql);
    if (revoke) SafeUploadMetadataRevoke(group->MainCookie);
    ExReleaseRundownProtection(&group->Rundown);
    KeSetEvent(&MetadataWork, IO_NO_INCREMENT, FALSE);
    return FLT_POSTOP_FINISHED_PROCESSING;
}
