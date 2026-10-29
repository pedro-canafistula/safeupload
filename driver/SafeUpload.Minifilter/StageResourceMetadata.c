/* Dormant opaque metadata I/O substrate. Forwarding conveys only the exact
 * registered metadata role; negotiation never conveys resource authority. */
#include "Filter.h"
#include "StageNativeRecords.h"
#include "StageResourceMetadata.h"

#define SU_METADATA_NODES 7UL
#define SU_METADATA_SD_BYTES 65536UL
#define SU_METADATA_CONTEXT_SIGNATURE 0x334d5553UL

/* First decisive refusal only. Node 0..6 identifies the fixed ancestry,
 * node 7 a child, node 8 its held replacement target, MAXULONG unresolved. For a security edge, low byte
 * is the parent node and upper bytes are (child node + 1): this distinguishes
 * SafeUpload -> staging from SafeUpload -> staging-journal. Role is RootRole
 * for RegisterRoot/root I/O, child Role for child controls/I/O, otherwise 0.
 * A call owns its record; an embedded completion transfers it with Deferred.
 * Under M these helpers only copy bounded scalar fields. Print is PASSIVE,
 * outside M, once at the outer return/release; no paths/pointers are printed.
 */
#define SU_METADATA_UNKNOWN_NODE MAXULONG
#define SU_METADATA_CHILD_NODE SU_METADATA_NODES
#define SU_METADATA_TARGET_NODE (SU_METADATA_NODES + 1UL)
#define SU_METADATA_EDGE_NODE(Parent, Child) ((Parent) | (((Child) + 1UL) << 8))
typedef struct _SU_METADATA_DIAGNOSTIC {
    ULONG Line;
    NTSTATUS Status;
    ULONG Node, Role;
} SU_METADATA_DIAGNOSTIC;

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID MetadataDiagnosticReset(_Out_ SU_METADATA_DIAGNOSTIC *Diagnostic, _In_ ULONG Node, _In_ ULONG Role)
{
    Diagnostic->Line = 0; Diagnostic->Status = STATUS_SUCCESS;
    Diagnostic->Node = Node; Diagnostic->Role = Role;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID MetadataDiagnosticNode(_Inout_opt_ SU_METADATA_DIAGNOSTIC *Diagnostic, _In_ ULONG Node)
{
    if (Diagnostic != NULL && Diagnostic->Line == 0) Diagnostic->Node = Node;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static NTSTATUS MetadataDiagnosticStatus(_Inout_opt_ SU_METADATA_DIAGNOSTIC *Diagnostic,
    _In_ NTSTATUS Status, _In_ ULONG Line)
{
    if (Status != STATUS_SUCCESS && Diagnostic != NULL && Diagnostic->Line == 0) {
        Diagnostic->Line = Line; Diagnostic->Status = Status;
    }
    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN MetadataDiagnosticBoolean(_Inout_opt_ SU_METADATA_DIAGNOSTIC *Diagnostic,
    _In_ BOOLEAN Value, _In_ NTSTATUS Status, _In_ ULONG Line)
{
    if (!Value) (VOID)MetadataDiagnosticStatus(Diagnostic, Status, Line);
    return Value;
}

_IRQL_requires_(PASSIVE_LEVEL)
static VOID MetadataDiagnosticPrint(_In_z_ PCSTR Control, _In_ const SU_METADATA_DIAGNOSTIC *Diagnostic)
{
    if (Diagnostic->Line != 0)
        (VOID)DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "SafeUpload: metadata %s refused status=0x%08X line=%u node=%u role=%u\n",
            Control, (unsigned int)Diagnostic->Status, (unsigned int)Diagnostic->Line,
            (unsigned int)Diagnostic->Node, (unsigned int)Diagnostic->Role);
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS MetadataDiagnosticControlReturn(_Inout_ SU_METADATA_DIAGNOSTIC *Diagnostic,
    _In_ ULONG Opcode, _In_ NTSTATUS Status, _In_ BOOLEAN Refused, _In_ ULONG Line)
{
    if ((Opcode == SU_RESOURCE_REGISTER_ROOT || Opcode == SU_RESOURCE_REGISTER_CHILD) &&
        (Refused || !NT_SUCCESS(Status))) {
        (VOID)MetadataDiagnosticStatus(Diagnostic, Status == STATUS_SUCCESS ? STATUS_ACCESS_DENIED : Status, Line);
        MetadataDiagnosticPrint(Opcode == SU_RESOURCE_REGISTER_ROOT ? "RegisterRoot" : "RegisterChildIntent", Diagnostic);
    }
    return Status;
}

#define METADATA_STATUS(Status) MetadataDiagnosticStatus(Diagnostic, (Status), __LINE__)
#define METADATA_BOOLEAN(Value, Status) MetadataDiagnosticBoolean(Diagnostic, (Value), (Status), __LINE__)
/* Keep constant-false exits visible to SAL null/output-flow analysis. */
#define METADATA_FALSE(Status) ((VOID)MetadataDiagnosticStatus(Diagnostic, (Status), __LINE__), FALSE)

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
    ULONG RootIndex, ChildIndex, TargetIndex;
    UINT64 TargetId, Value;
    ULONG InformationClass, Length;
    PFILE_OBJECT Reference, TargetReference;
    HANDLE TargetHandle;
    NTSTATUS NativeStatus;
    ULONG_PTR NativeInformation;
    BOOLEAN Deferred, NativeValidation;
    SU_METADATA_DIAGNOSTIC Diagnostic;
    ULONG RenameBytes;
    WCHAR RenameLeaf[256];
    UCHAR Operation;
    BOOLEAN InUse;
} SU_METADATA_COMPLETION;

typedef struct _SU_METADATA_ROOT {
    UINT64 Id;
    PFILE_OBJECT Original; /* owned until PASSIVE revoke; Key is nonowning */
    PFILE_OBJECT Key;
    BOOLEAN Cleaned;
    SU_METADATA_COMPLETION Cleanup;
    SU_METADATA_COMPLETION Io;
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
    PFILE_OBJECT Key;
    SAFEUPLOAD_STAGE_IDENTITY_V19 Identity;
    PSECURITY_DESCRIPTOR Security;
    ULONG SecurityBytes, Pins, TargetPins, ReplacementIndex;
    UINT64 ReplacementId, PaddedExtent, Nominal, Peak, Retained, EndOfFile, Allocation, Preallocated, LogicalEof;
    ULONG ShareAccess, LiveLeafBytes;
    BOOLEAN Closed, Cleaned, Uncertain, Retiring, Renamed, NeedF3, F1, F2, EofSet, Frozen, Unlinked, Deleted;
    SU_METADATA_COMPLETION Io, Cleanup;
} SU_METADATA_CHILD;

typedef struct _SU_METADATA_GROUP {
    EX_RUNDOWN_REF Rundown;
    PEPROCESS Process;
    PACCESS_TOKEN Token;
    PFLT_PORT ResourcePort;
    PVOID MainCookie;
    GUID DriverInstance;
    SU_RESOURCE_NEGOTIATE_REQUEST Probe;
    BOOLEAN Revoked, AccountingHeld;
    BOOLEAN Paired;
    LONG MetadataControls;
    BOOLEAN RootBusy, AnchorsClosed, ForceForgetKeys;
    /* Non-authorizing capture key; the RootBusy control owns its reference. */
    PFILE_OBJECT CaptureKey;
    BOOLEAN CaptureCleaned;
    UINT64 NextRootId, NextChildId;
    ULONG PostOwners;
    PFLT_VOLUME Volume;
    PFLT_INSTANCE Instance;
    ULONG IoAlignment, AllocationUnit;
    UINT64 LiveRetained, RetiredRetained, ObservedPeak, UnknownOutcomes;
    SU_METADATA_NODE Nodes[SU_METADATA_NODES];
    SU_METADATA_ROOT Roots[SU_METADATA_ROOTS];
    SU_METADATA_TRANSACTION Transactions[SU_METADATA_TRANSACTIONS];
    SU_METADATA_CHILD Children[SU_METADATA_CHILDREN];
    UINT64 RequestIds[SU_METADATA_CONTROLS + 2]; /* metadata, revoke, bootstrap */
} SU_METADATA_GROUP;
C_ASSERT(__alignof(SU_METADATA_COMPLETION) >= 16);
C_ASSERT((FIELD_OFFSET(SU_METADATA_ROOT, Cleanup) & 15) == 0);
C_ASSERT((FIELD_OFFSET(SU_METADATA_ROOT, Io) & 15) == 0);
C_ASSERT((FIELD_OFFSET(SU_METADATA_CHILD, Io) & 15) == 0);
C_ASSERT((FIELD_OFFSET(SU_METADATA_CHILD, Cleanup) & 15) == 0);
C_ASSERT((FIELD_OFFSET(SU_METADATA_GROUP, Roots) & 15) == 0);
C_ASSERT((FIELD_OFFSET(SU_METADATA_GROUP, Children) & 15) == 0);
C_ASSERT(MEMORY_ALLOCATION_ALIGNMENT >= 16);
C_ASSERT(sizeof(FILE_END_OF_FILE_INFORMATION) == sizeof(LARGE_INTEGER));
C_ASSERT(sizeof(FILE_ALLOCATION_INFORMATION) == sizeof(LARGE_INTEGER));
C_ASSERT(sizeof(FILE_DISPOSITION_INFORMATION) == sizeof(BOOLEAN));
C_ASSERT(FileRenameInformationEx == 65);
C_ASSERT((FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS) == 3);
C_ASSERT(FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName) == 20); /* selected x64 native ABI */

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
_IRQL_requires_(PASSIVE_LEVEL)
static VOID MetadataServiceChildren(_Inout_ SU_METADATA_GROUP *Group);
_IRQL_requires_(PASSIVE_LEVEL)
static __declspec(noinline) NTSTATUS MetadataCaptureAlignment(_In_ PFLT_INSTANCE Instance, _In_ PFLT_VOLUME Volume,
    _Out_ PULONG Alignment, _Out_ PULONG Unit, _Inout_opt_ SU_METADATA_DIAGNOSTIC *Diagnostic);

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

/* M held. Teardown cannot rely on another CLOSE through this instance.
 * Withdraw ALL membership at that transition, before references are released
 * or callback coverage disappears. Credit/context retirement remains separate. */
_IRQL_requires_(DISPATCH_LEVEL)
static VOID MetadataForgetKeysLocked(_Inout_ SU_METADATA_GROUP *Group)
{
    ULONG i;
    Group->ForceForgetKeys = TRUE;
    Group->Revoked = TRUE;
    Group->CaptureKey = NULL; Group->CaptureCleaned = TRUE;
    for (i = 0; i < SU_METADATA_ROOTS; ++i) {
        Group->Roots[i].Key = NULL; Group->Roots[i].Cleaned = TRUE;
    }
    for (i = 0; i < SU_METADATA_CHILDREN; ++i) {
        SU_METADATA_CHILD *child = &Group->Children[i];
        if (child->State == 0) continue;
        child->Key = NULL; child->Closed = TRUE; child->Uncertain = TRUE;
        /* Revoke's pending-intent owner still releases its replacement edge. */
        if (child->State != SuMetadataPendingOpen) child->State = SuMetadataRevoked;
    }
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
    if (Group->ForceForgetKeys) MetadataForgetKeysLocked(Group);
    if (Group->RootBusy || Group->PostOwners != 0) { KeReleaseSpinLock(&MetadataLock, irql); return; }
    for (i = 0; i < SU_METADATA_CHILDREN; ++i)
        if (Group->Children[i].State != 0) ready = FALSE;
    if (!ready) { KeReleaseSpinLock(&MetadataLock, irql); return; }
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
        /* Normal retirement retains keys to route native CLOSE. Forced
         * teardown has already withdrawn them while owning these references.
         * No filesystem or object release under M. */
        for (i = 0; i < SU_METADATA_ROOTS; ++i)
            if (originals[i] != NULL) ObDereferenceObject(originals[i]);
    }
    KeAcquireSpinLock(&MetadataLock, &irql);
    for (i = 0; i < SU_METADATA_ROOTS; ++i) {
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
    BOOLEAN stop, pinned;
    KIRQL irql;
    UNREFERENCED_PARAMETER(Parameter);
    for (;;) {
        (VOID)KeWaitForSingleObject(&MetadataWork, Executive, KernelMode, FALSE, NULL);
        KeAcquireSpinLock(&MetadataLock, &irql);
        group = MetadataRoutingGroup;
        pinned = group != NULL && ExAcquireRundownProtection(&group->Rundown);
        stop = MetadataWorkerStopping;
        KeReleaseSpinLock(&MetadataLock, irql);
        if (pinned) {
            MetadataServiceChildren(group);
            ExReleaseRundownProtection(&group->Rundown);
        }
        KeAcquireSpinLock(&MetadataLock, &irql);
        group = MetadataRetiringGroup;
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
        for (i = 0; i < SU_METADATA_CHILDREN; ++i) {
            SU_METADATA_CHILD *child = &group->Children[i];
            if (child->State == SuMetadataPendingOpen) MetadataRemoveChildLocked(group, i);
            else if (child->State != 0) child->State = SuMetadataRevoked;
        }
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
    if (MetadataRoutingGroup != NULL) MetadataForgetKeysLocked(MetadataRoutingGroup);
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
    /* Filter Manager hands ConnectNotify the connection context from the create
     * EA buffer, which the I/O manager has already captured into kernel memory,
     * at an offset that need not be aligned. It is not a user address:
     * ProbeForRead refused every real pair (N-U5-01 nu501c2, ERROR_NOACCESS).
     * Copy the exact size; every field is validated below. */
    RtlCopyMemory(&pair, Context, sizeof(pair));
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
    ULONG IoAlignment, AllocationUnit;
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
    _Outptr_ PSID *Owner, _Outptr_ PACL *Dacl, _Out_ PBOOLEAN Protected, _Inout_opt_ SU_METADATA_DIAGNOSTIC *Diagnostic)
{
    BOOLEAN defaulted, present;
    PISECURITY_DESCRIPTOR_RELATIVE relative = Security;
    *Owner = NULL;
    *Dacl = NULL;
    *Protected = FALSE;
    if (!NT_SUCCESS(RtlGetOwnerSecurityDescriptor(Security, Owner, &defaulted)) ||
        *Owner == NULL || !RtlValidSid(*Owner) ||
        !NT_SUCCESS(RtlGetDaclSecurityDescriptor(Security, &present, Dacl, &defaulted)) ||
        !present || *Dacl == NULL) return METADATA_FALSE(STATUS_INVALID_SECURITY_DESCR);
    *Protected = BooleanFlagOn(relative->Control, SE_DACL_PROTECTED);
    return METADATA_BOOLEAN(relative->Revision == SECURITY_DESCRIPTOR_REVISION &&
        FlagOn(relative->Control, SE_SELF_RELATIVE), STATUS_INVALID_SECURITY_DESCR);
}

/* No deny-cancellation inference: an unsafe allow refuses even if another ACE
 * might deny it. Generic masks are expanded before either predicate. */
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN MetadataSecurityPredicate(_In_ const SU_METADATA_NODE *Node,
    _In_ BOOLEAN WindowsAncestor, _In_ BOOLEAN InstallationParent,
    _In_opt_ const SU_METADATA_NODE *Child, _Inout_opt_ SU_METADATA_DIAGNOSTIC *Diagnostic)
{
    PSID owner, childOwner = NULL;
    PACL dacl, childDacl;
    BOOLEAN protectedDacl, childProtected = FALSE;
    ULONG i;
    const ACCESS_MASK mutations = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
        FILE_WRITE_ATTRIBUTES | DELETE | FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER;
    const ACCESS_MASK destructive = DELETE | FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER |
        FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES;
    /* Design 8.7.1 AncestorEdge: on the Windows ancestor itself only untrusted
     * DELETE, FILE_DELETE_CHILD, WRITE_DAC and WRITE_OWNER refuse. Stock
     * C:\ProgramData grants BUILTIN\Users (CI)(WD,AD,WEA,WA) on itself, which
     * the wider set wrongly refused (N-U5-01 nu501c3). Inheritable grants that
     * reach an unprotected child keep the wider set below. */
    const ACCESS_MASK ancestorAuthority = DELETE | FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER;
    GENERIC_MAPPING mapping = {FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
    if (!MetadataSecurityParts(Node->Security, &owner, &dacl, &protectedDacl, Diagnostic) ||
        !MetadataTrustedSid(owner, WindowsAncestor && !InstallationParent) ||
        (!WindowsAncestor && !protectedDacl)) return METADATA_FALSE(STATUS_ACCESS_DENIED);
    if (Child != NULL && !MetadataSecurityParts(Child->Security, &childOwner, &childDacl, &childProtected, Diagnostic))
        return METADATA_FALSE(STATUS_ACCESS_DENIED);
    for (i = 0; i < dacl->AceCount; ++i) {
        PVOID ace = NULL;
        PACCESS_ALLOWED_ACE allow;
        PACE_HEADER header;
        PSID sid;
        ACCESS_MASK mask;
        BOOLEAN trusted;
        if (!NT_SUCCESS(RtlGetAce(dacl, i, &ace)) || ace == NULL) return METADATA_FALSE(STATUS_ACCESS_DENIED);
        header = ace;
        if ((header->AceType != ACCESS_ALLOWED_ACE_TYPE && header->AceType != ACCESS_DENIED_ACE_TYPE) ||
            (header->AceFlags & ~(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE |
                INHERIT_ONLY_ACE | INHERITED_ACE)) != 0 ||
            header->AceSize < FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + 8) return METADATA_FALSE(STATUS_ACCESS_DENIED);
        allow = ace;
        sid = (PSID)&allow->SidStart;
        if (((PISID)sid)->SubAuthorityCount > SID_MAX_SUB_AUTHORITIES ||
            FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + 8UL +
                4UL * ((PISID)sid)->SubAuthorityCount != header->AceSize || !RtlValidSid(sid))
            return METADATA_FALSE(STATUS_ACCESS_DENIED);
        mask = allow->Mask;
        RtlMapGenericMask(&mask, &mapping);
        if ((mask & ~FILE_ALL_ACCESS) != 0) return METADATA_FALSE(STATUS_ACCESS_DENIED);
        if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
        trusted = MetadataTrustedSid(sid, WindowsAncestor && !InstallationParent);
        if (!WindowsAncestor) {
            if (!trusted && (mask & mutations) != 0) return METADATA_FALSE(STATUS_ACCESS_DENIED);
        } else {
            if (!trusted && !FlagOn(header->AceFlags, INHERIT_ONLY_ACE) && (mask & ancestorAuthority) != 0)
                return METADATA_FALSE(STATUS_ACCESS_DENIED);
            if (!trusted && Child != NULL && !childProtected &&
                FlagOn(header->AceFlags, CONTAINER_INHERIT_ACE) && (mask & destructive) != 0) {
                /* CREATOR_OWNER substitutes the already trusted next owner;
                 * it is not accepted as an effective ACE on this ancestor. */
                if (!RtlEqualSid(sid, SeExports->SeCreatorOwnerSid) || childOwner == NULL ||
                    !MetadataTrustedSid(childOwner, TRUE)) return METADATA_FALSE(STATUS_ACCESS_DENIED);
            }
        }
    }
    return TRUE;
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS MetadataQueryDirectory(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT Object,
    _Out_ SAFEUPLOAD_STAGE_IDENTITY_V19 *Identity, _Inout_opt_ SU_METADATA_DIAGNOSTIC *Diagnostic)
{
    FILE_ID_INFORMATION id;
    FILE_STANDARD_INFORMATION standard;
    FILE_ATTRIBUTE_TAG_INFORMATION tag;
    ULONG bytes = 0;
    NTSTATUS status;
    /* Set the _Out_ identity on every path: PREfast cannot see that the
     * diagnostic wrapper returns its argument unchanged (C6101). */
    RtlZeroMemory(Identity, sizeof(*Identity));
    RtlZeroMemory(&id, sizeof(id));
    RtlZeroMemory(&standard, sizeof(standard));
    RtlZeroMemory(&tag, sizeof(tag));
    status = FltQueryInformationFile(Instance, Object, &standard, sizeof(standard), FileStandardInformation, &bytes);
    if (!NT_SUCCESS(status)) return METADATA_STATUS(status);
    if (bytes != sizeof(standard) || !standard.Directory || standard.DeletePending) return METADATA_STATUS(STATUS_NOT_A_DIRECTORY);
    status = FltQueryInformationFile(Instance, Object, &tag, sizeof(tag), FileAttributeTagInformation, &bytes);
    if (!NT_SUCCESS(status)) return METADATA_STATUS(status);
    /* ReparseTag is undefined unless the attribute is set; the attribute decides. */
    if (bytes != sizeof(tag) || FlagOn(tag.FileAttributes, FILE_ATTRIBUTE_REPARSE_POINT))
        return METADATA_STATUS(STATUS_REPARSE_POINT_ENCOUNTERED);
    status = FltQueryInformationFile(Instance, Object, &id, sizeof(id), FileIdInformation, &bytes);
    if (!NT_SUCCESS(status)) return METADATA_STATUS(status);
    if (bytes != sizeof(id)) return METADATA_STATUS(STATUS_INFO_LENGTH_MISMATCH);
    Identity->VolumeSerialNumber = id.VolumeSerialNumber;
    Identity->FileId = id.FileId;
    return METADATA_STATUS(MetadataZero(Identity, sizeof(*Identity)) ? STATUS_INVALID_PARAMETER : STATUS_SUCCESS);
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS MetadataCaptureSecurity(_In_ PFLT_INSTANCE Instance, _Inout_ SU_METADATA_NODE *Node, _Inout_opt_ SU_METADATA_DIAGNOSTIC *Diagnostic)
{
    ULONG needed = 0;
    NTSTATUS status;
    SECURITY_INFORMATION information = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    status = FltQuerySecurityObject(Instance, Node->Object, information, NULL, 0, &needed);
    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW)
        return METADATA_STATUS(NT_SUCCESS(status) ? STATUS_INVALID_SECURITY_DESCR : status);
    if (needed < sizeof(SECURITY_DESCRIPTOR_RELATIVE) || needed > SU_METADATA_SD_BYTES)
        return METADATA_STATUS(STATUS_INVALID_SECURITY_DESCR);
    Node->Security = ExAllocatePool2(POOL_FLAG_PAGED, needed, SU_METADATA_TAG);
    if (Node->Security == NULL) return METADATA_STATUS(STATUS_INSUFFICIENT_RESOURCES);
    Node->SecurityBytes = needed;
    status = FltQuerySecurityObject(Instance, Node->Object, information, Node->Security, needed, &needed);
    if (!NT_SUCCESS(status)) return METADATA_STATUS(status);
    if (!RtlValidRelativeSecurityDescriptor(Node->Security, Node->SecurityBytes, information))
        return METADATA_STATUS(STATUS_INVALID_SECURITY_DESCR);
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS MetadataReadLink(_In_ PCUNICODE_STRING Name, _Inout_ PUNICODE_STRING Target)
{
    OBJECT_ATTRIBUTES attributes;
    HANDLE handle;
    NTSTATUS status;
    InitializeObjectAttributes(&attributes, (PUNICODE_STRING)Name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = ZwOpenSymbolicLinkObject(&handle, SYMBOLIC_LINK_QUERY, &attributes);
    if (!NT_SUCCESS(status)) return status;
    status = ZwQuerySymbolicLinkObject(handle, Target, NULL);
    ZwClose(handle);
    if (NT_SUCCESS(status) && (Target->Length == 0 || (Target->Length & 1) != 0)) status = STATUS_INVALID_PARAMETER;
    return status;
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS MetadataCheckProgramData(_Inout_ SU_METADATA_CAPTURE *Capture, _Inout_opt_ SU_METADATA_DIAGNOSTIC *Diagnostic)
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
    if (!NT_SUCCESS(status)) return METADATA_STATUS(status);
    status = ZwQueryValueKey(key, &valueName, KeyValuePartialInformation, data, sizeof(Capture->Scratch), &returned);
    ZwClose(key);
    if (!NT_SUCCESS(status)) return METADATA_STATUS(status);
    if (returned < (ULONG)FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) ||
        (data->Type != REG_SZ && data->Type != REG_EXPAND_SZ) || data->DataLength < 2 ||
        data->DataLength > 512 * sizeof(WCHAR) || (data->DataLength & 1) != 0 ||
        data->DataLength > returned - (ULONG)FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data)) return METADATA_STATUS(STATUS_INVALID_PARAMETER);
    value.Buffer = (PWCHAR)data->Data;
    value.MaximumLength = (USHORT)data->DataLength;
    value.Length = (USHORT)(value.MaximumLength - (USHORT)sizeof(WCHAR));
    if (value.Buffer[value.Length / sizeof(WCHAR)] != 0) return METADATA_STATUS(STATUS_INVALID_PARAMETER);
    RtlInitUnicodeString(&literal, L"C:\\ProgramData");
    RtlInitUnicodeString(&expanded, L"%SystemDrive%\\ProgramData");
    return METADATA_STATUS(RtlEqualUnicodeString(&value, &literal, TRUE) || RtlEqualUnicodeString(&value, &expanded, TRUE) ?
        STATUS_SUCCESS : STATUS_NOT_SUPPORTED);
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS MetadataCaptureInstallation(_Inout_ SU_METADATA_CAPTURE *Capture, _Inout_opt_ SU_METADATA_DIAGNOSTIC *Diagnostic)
{
    UNICODE_STRING device, system, name, actualVolume, systemDevice, resolved;
    UNICODE_STRING driveLink = RTL_CONSTANT_STRING(L"\\GLOBAL??\\C:");
    UNICODE_STRING systemLink = RTL_CONSTANT_STRING(L"\\SystemRoot");
    USHORT slash, slashes = 0;
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
    MetadataDiagnosticNode(Diagnostic, 0);
    status = MetadataReadLink(&driveLink, &device);
    if (!NT_SUCCESS(status)) return METADATA_STATUS(status);
    status = MetadataReadLink(&systemLink, &system);
    if (!NT_SUCCESS(status)) return METADATA_STATUS(status);
    /* Windows 10 names \SystemRoot as \Device\BootDevice\Windows, and
     * \Device\BootDevice is itself a link to the volume (measured on 19045,
     * N-U5-01 nu501c4), so a literal prefix never matched. Resolve exactly one
     * hop of the system path's device component, then require it to equal C:.
     * A second hop, or any other device, refuses. */
    for (slash = 1; slash < system.Length / sizeof(WCHAR); ++slash)
        if (system.Buffer[slash] == L'\\' && ++slashes == 2) break;
    if (slashes != 2 || system.Buffer[0] != L'\\' || (USHORT)((slash + 1) * sizeof(WCHAR)) >= system.Length)
        return METADATA_STATUS(STATUS_NOT_SUPPORTED);
    systemDevice.Buffer = system.Buffer;
    systemDevice.Length = systemDevice.MaximumLength = (USHORT)(slash * sizeof(WCHAR));
    resolved.Buffer = (PWCHAR)Capture->Scratch;
    resolved.Length = 0;
    resolved.MaximumLength = 1024;
    status = MetadataReadLink(&systemDevice, &resolved);
    if (status == STATUS_OBJECT_TYPE_MISMATCH) resolved = systemDevice; /* already a device object */
    else if (!NT_SUCCESS(status)) return METADATA_STATUS(status);
    if (!RtlEqualUnicodeString(&resolved, &device, TRUE)) return METADATA_STATUS(STATUS_NOT_SUPPORTED);
    MetadataDiagnosticNode(Diagnostic, 1);
    status = MetadataCheckProgramData(Capture, Diagnostic);
    if (!NT_SUCCESS(status)) return METADATA_STATUS(status);
    MetadataDiagnosticNode(Diagnostic, 0);
    status = FltGetVolumeFromName(SafeUploadData.Filter, &device, &Capture->Volume);
    if (!NT_SUCCESS(status)) return METADATA_STATUS(status);
    actualVolume.Buffer = (PWCHAR)Capture->Scratch;
    actualVolume.Length = 0;
    actualVolume.MaximumLength = 1024;
    status = FltGetVolumeName(Capture->Volume, &actualVolume, NULL);
    if (!NT_SUCCESS(status)) return METADATA_STATUS(status);
    if (!RtlEqualUnicodeString(&actualVolume, &device, TRUE)) return METADATA_STATUS(STATUS_NOT_SUPPORTED);
    status = FltGetVolumeInstanceFromName(SafeUploadData.Filter, Capture->Volume, NULL, &Capture->Instance);
    if (!NT_SUCCESS(status)) return METADATA_STATUS(status);
    status = FltGetInstanceContext(Capture->Instance, (PFLT_CONTEXT *)&context);
    if (!NT_SUCCESS(status)) return METADATA_STATUS(status);
    status = METADATA_STATUS(context->VolumeKind == SafeUploadVolumeFixed ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED);
    FltReleaseContext(context);
    if (!NT_SUCCESS(status)) return METADATA_STATUS(status);
    status = FltGetFileSystemType(Capture->Instance, &type);
    if (!NT_SUCCESS(status)) return METADATA_STATUS(status);
    if (type != FLT_FSTYPE_NTFS) return METADATA_STATUS(STATUS_NOT_SUPPORTED);
    device.Buffer[device.Length / sizeof(WCHAR)] = L'\\';
    device.Length = (USHORT)(device.Length + (USHORT)sizeof(WCHAR));
    device.MaximumLength = sizeof(Capture->DeviceBuffer);
    for (i = 0; i < SU_METADATA_NODES; ++i) {
        SU_METADATA_NODE *node = &Capture->Nodes[i];
        MetadataDiagnosticNode(Diagnostic, i);
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
        if (status != STATUS_SUCCESS) return METADATA_STATUS(NT_SUCCESS(status) ? STATUS_NOT_SUPPORTED : status);
        if (io.Information != FILE_OPENED) return METADATA_STATUS(STATUS_INVALID_PARAMETER);
        status = MetadataQueryDirectory(Capture->Instance, node->Object, &node->Identity, Diagnostic);
        if (!NT_SUCCESS(status)) return METADATA_STATUS(status);
        if (i != 0 && node->Identity.VolumeSerialNumber != Capture->Nodes[0].Identity.VolumeSerialNumber)
            return METADATA_STATUS(STATUS_NOT_SAME_DEVICE);
        status = MetadataCaptureSecurity(Capture->Instance, node, Diagnostic);
        if (!NT_SUCCESS(status)) return METADATA_STATUS(status);
    }
    if (!(MetadataDiagnosticNode(Diagnostic, SU_METADATA_EDGE_NODE(0, 1)), MetadataSecurityPredicate(&Capture->Nodes[0], TRUE, FALSE, &Capture->Nodes[1], Diagnostic)) ||
        !(MetadataDiagnosticNode(Diagnostic, SU_METADATA_EDGE_NODE(1, 2)), MetadataSecurityPredicate(&Capture->Nodes[1], TRUE, FALSE, &Capture->Nodes[2], Diagnostic)) ||
        !(MetadataDiagnosticNode(Diagnostic, SU_METADATA_EDGE_NODE(2, 3)), MetadataSecurityPredicate(&Capture->Nodes[2], TRUE, TRUE, &Capture->Nodes[3], Diagnostic)) ||
        !(MetadataDiagnosticNode(Diagnostic, SU_METADATA_EDGE_NODE(2, 5)), MetadataSecurityPredicate(&Capture->Nodes[2], TRUE, TRUE, &Capture->Nodes[5], Diagnostic))) return METADATA_STATUS(STATUS_ACCESS_DENIED);
    for (i = 3; i < SU_METADATA_NODES; ++i) {
        MetadataDiagnosticNode(Diagnostic, i);
        if (!MetadataSecurityPredicate(&Capture->Nodes[i], FALSE, FALSE, NULL, Diagnostic)) return METADATA_STATUS(STATUS_ACCESS_DENIED);
    }
    return METADATA_STATUS(MetadataCaptureAlignment(Capture->Instance, Capture->Volume,
        &Capture->IoAlignment, &Capture->AllocationUnit, Diagnostic));
}

static BOOLEAN MetadataRootShape(_In_ const SU_RESOURCE_ROOT_REQUEST *Request, _Inout_opt_ SU_METADATA_DIAGNOSTIC *Diagnostic)
{
    return METADATA_BOOLEAN(Request->RootRole >= 1 && Request->RootRole <= 4 && Request->Flags == 0 && Request->Handle != 0 &&
        (UINT64)(ULONG_PTR)Request->Handle == Request->Handle && Request->SecurityContractVersion == 1 &&
        MetadataZero(Request->Reserved, sizeof(Request->Reserved)) &&
        !MetadataZero(&Request->Identity, sizeof(Request->Identity)) &&
        ((Request->RootRole == 1 || Request->RootRole == 3) == (Request->ParentRootId == 0)), STATUS_INVALID_PARAMETER);
}

_IRQL_requires_(PASSIVE_LEVEL)
static __declspec(noinline) NTSTATUS MetadataRegisterRoot(_In_ SU_METADATA_GROUP *Group,
    _In_ const SU_RESOURCE_ROOT_REQUEST *Request, _Out_ SU_RESOURCE_ROOT_REPLY *Reply, _Inout_opt_ SU_METADATA_DIAGNOSTIC *Diagnostic)
{
    SU_METADATA_CAPTURE *capture = NULL;
    SU_METADATA_NODE *node;
    PFILE_OBJECT original = NULL, bridgeObject = NULL;
    HANDLE bridge = NULL;
    PFLT_VOLUME volume = NULL;
    SAFEUPLOAD_STAGE_IDENTITY_V19 identity;
    ULONG index, bytes = 0;
    BOOLEAN captureNeeded, publish = FALSE, revoke = FALSE;
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    KIRQL irql;
    if (Diagnostic != NULL && Diagnostic->Line == 0) Diagnostic->Role = Request->RootRole;
    Reply->Result = 2;
    if (!MetadataRootShape(Request, Diagnostic)) return METADATA_STATUS(status);
    index = Request->RootRole - 1;
    MetadataDiagnosticNode(Diagnostic, MetadataRoleNodes[index]);
    KeAcquireSpinLock(&MetadataLock, &irql);
    if (Group->Revoked || !Group->Paired) status = METADATA_STATUS(STATUS_ACCESS_DENIED);
    else if (Group->RootBusy) status = METADATA_STATUS(STATUS_DEVICE_BUSY);
    else if ((index == 1 && (Group->Roots[0].Id == 0 || Group->Roots[0].Id != Request->ParentRootId ||
                         Group->Roots[0].Key == NULL || Group->Roots[0].Cleaned)) ||
             (index == 3 && (Group->Roots[2].Id == 0 || Group->Roots[2].Id != Request->ParentRootId ||
                         Group->Roots[2].Key == NULL || Group->Roots[2].Cleaned)))
        status = METADATA_STATUS(STATUS_INVALID_PARAMETER);
    else { Group->RootBusy = TRUE; status = STATUS_SUCCESS; }
    captureNeeded = Group->Instance == NULL;
    KeReleaseSpinLock(&MetadataLock, irql);
    if (!NT_SUCCESS(status)) return METADATA_STATUS(status);
    status = ObReferenceObjectByHandle((HANDLE)(ULONG_PTR)Request->Handle,
        READ_CONTROL | SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY,
        *IoFileObjectType, UserMode, (PVOID *)&original, NULL);
    if (!NT_SUCCESS(status)) { (VOID)METADATA_STATUS(status); goto Exit; }
    /* Atomically duplicate the proven ORIGINAL handle before installing a
     * provisional key. Opening its pointer could resurrect an already-cleaned
     * object. The source handle may have been closed/reused since UserMode
     * proof, so compare the duplicated object before trusting the bridge. */
    status = ZwDuplicateObject(ZwCurrentProcess(), (HANDLE)(ULONG_PTR)Request->Handle,
        ZwCurrentProcess(), &bridge, 0, OBJ_KERNEL_HANDLE, DUPLICATE_SAME_ACCESS);
    if (status != STATUS_SUCCESS) { (VOID)METADATA_STATUS(status); goto Exit; }
    status = ObReferenceObjectByHandle(bridge, 0, *IoFileObjectType, KernelMode, (PVOID *)&bridgeObject, NULL);
    if (status != STATUS_SUCCESS) { (VOID)METADATA_STATUS(status); goto Exit; }
    if (bridgeObject != original) { status = METADATA_STATUS(STATUS_INVALID_HANDLE); goto Exit; }
    ObDereferenceObject(bridgeObject); bridgeObject = NULL;
    if (!FlagOn(original->Flags, FO_HANDLE_CREATED) || FlagOn(original->Flags, FO_CLEANUP_COMPLETE)) {
        status = METADATA_STATUS(STATUS_INVALID_HANDLE);
        goto Exit;
    }
    KeAcquireSpinLock(&MetadataLock, &irql);
    if (Group->Revoked) status = METADATA_STATUS(STATUS_ACCESS_DENIED);
    else {
        NT_ASSERT(Group->CaptureKey == NULL);
        Group->CaptureKey = original;
        Group->CaptureCleaned = FALSE;
    }
    KeReleaseSpinLock(&MetadataLock, irql);
    if (status != STATUS_SUCCESS) { (VOID)METADATA_STATUS(status); goto Exit; }
    /* Any last-handle CLEANUP can now see the non-authorizing capture key.
     * It cannot be missed between an unlocked flag check and promotion. */
    ZwClose(bridge); bridge = NULL;
    /* Publication copies the bounded node/instance fields under M. Keep
     * their backing resident; descriptor contents are still PASSIVE-only. */
    capture = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*capture), SU_METADATA_TAG);
    if (capture == NULL) { status = METADATA_STATUS(STATUS_INSUFFICIENT_RESOURCES); goto Exit; }
    if (captureNeeded) {
        status = MetadataCaptureInstallation(capture, Diagnostic);
        if (status != STATUS_SUCCESS) {
            if (NT_SUCCESS(status)) status = METADATA_STATUS(STATUS_DEVICE_NOT_READY);
            goto Exit;
        }
    }
    MetadataDiagnosticNode(Diagnostic, MetadataRoleNodes[index]);
    node = captureNeeded ? &capture->Nodes[MetadataRoleNodes[index]] : &Group->Nodes[MetadataRoleNodes[index]];
    status = FltGetVolumeFromFileObject(SafeUploadData.Filter, original, &volume);
    if (!NT_SUCCESS(status)) { (VOID)METADATA_STATUS(status); goto Exit; }
    if (volume != (captureNeeded ? capture->Volume : Group->Volume)) {
        status = METADATA_STATUS(STATUS_NOT_SAME_DEVICE);
        revoke = TRUE;
        goto Exit;
    }
    status = MetadataQueryDirectory(captureNeeded ? capture->Instance : Group->Instance, original, &identity, Diagnostic);
    if (!NT_SUCCESS(status)) { (VOID)METADATA_STATUS(status); goto Exit; }
    if (!RtlEqualMemory(&identity, &Request->Identity, sizeof(identity)) ||
        !RtlEqualMemory(&identity, &node->Identity, sizeof(identity))) {
        status = METADATA_STATUS(STATUS_INVALID_PARAMETER);
        revoke = TRUE;
        goto Exit;
    }
    RtlZeroMemory(capture->Scratch, node->SecurityBytes);
    status = FltQuerySecurityObject(captureNeeded ? capture->Instance : Group->Instance, original,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, capture->Scratch, node->SecurityBytes, &bytes);
    if (!NT_SUCCESS(status)) { (VOID)METADATA_STATUS(status); goto Exit; }
    /* LengthNeeded is documented for the buffer-too-small case only; a
     * successful query may leave it 0 (ux-k12 in StageSecurity.c; refused every
     * real root in N-U5-01 nu501c7). Derive both lengths from the validated
     * descriptors and compare exactly those bytes, so no stale tail counts. */
    if (!RtlValidRelativeSecurityDescriptor(capture->Scratch, node->SecurityBytes,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION) ||
        RtlLengthSecurityDescriptor(capture->Scratch) != RtlLengthSecurityDescriptor(node->Security) ||
        !RtlEqualMemory(capture->Scratch, node->Security, RtlLengthSecurityDescriptor(node->Security))) {
        status = METADATA_STATUS(STATUS_INVALID_SECURITY_DESCR);
        revoke = TRUE;
        goto Exit;
    }
    /* Recheck original subject after the bounded native capture, outside the
     * map lock. The final publication latch checks live revocation again. */
    if (!MetadataAuthenticate(Group) || FlagOn(original->Flags, FO_CLEANUP_COMPLETE)) {
        status = METADATA_STATUS(STATUS_ACCESS_DENIED);
        goto Exit;
    }
    KeAcquireSpinLock(&MetadataLock, &irql);
    if (Group->Revoked || Group->CaptureKey != original || Group->CaptureCleaned ||
        FlagOn(original->Flags, FO_CLEANUP_COMPLETE)) status = METADATA_STATUS(STATUS_ACCESS_DENIED);
    else if (Group->Roots[index].Id != 0) {
        if (Group->Roots[index].Key != original || Group->Roots[index].Cleaned) status = METADATA_STATUS(STATUS_INVALID_PARAMETER);
        else { Reply->RootId = Group->Roots[index].Id; publish = TRUE; }
    } else if (Group->NextRootId == (UINT64)MAXLONGLONG) status = METADATA_STATUS(STATUS_TOO_MANY_CONTEXT_IDS);
    else {
        if (captureNeeded) {
            RtlCopyMemory(Group->Nodes, capture->Nodes, sizeof(Group->Nodes));
            RtlZeroMemory(capture->Nodes, sizeof(capture->Nodes));
            Group->IoAlignment = capture->IoAlignment;
            Group->AllocationUnit = capture->AllocationUnit;
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
        Group->CaptureKey = NULL; /* atomic handoff to the registered root */
        Reply->Result = 1;
        Reply->Identity = identity;
        status = STATUS_SUCCESS;
    }
    KeReleaseSpinLock(&MetadataLock, irql);
Exit:
    /* Withdraw provisional membership BEFORE any reference/handle release.
     * RootBusy still prevents another capture or anchor retirement here. */
    KeAcquireSpinLock(&MetadataLock, &irql);
    Group->CaptureKey = NULL;
    Group->CaptureCleaned = FALSE;
    KeReleaseSpinLock(&MetadataLock, irql);
    if (bridgeObject != NULL) ObDereferenceObject(bridgeObject);
    if (bridge != NULL) ZwClose(bridge);
    if (volume != NULL) FltObjectDereference(volume);
    if (original != NULL) ObDereferenceObject(original);
    if (capture != NULL) MetadataFreeCapture(capture);
    KeAcquireSpinLock(&MetadataLock, &irql);
    Group->RootBusy = FALSE;
    KeReleaseSpinLock(&MetadataLock, irql);
    if (revoke) SafeUploadMetadataRevoke(Group->MainCookie);
    KeSetEvent(&MetadataWork, IO_NO_INCREMENT, FALSE);
    return METADATA_STATUS(status);
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS MetadataChildShape(_In_ const SU_RESOURCE_CHILD_REQUEST *Request, _Inout_opt_ SU_METADATA_DIAGNOSTIC *Diagnostic)
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
         (Request->CreateDisposition == FILE_CREATE))) return METADATA_STATUS(STATUS_INVALID_PARAMETER);
    for (i = 0; i < Request->LeafBytes / sizeof(WCHAR); ++i) {
        WCHAR c = Request->Leaf[i];
        if (c == 0 || c == L'\\' || c == L'/' || c == L':' || c == L'*' || c == L'?')
            return METADATA_STATUS(STATUS_INVALID_PARAMETER);
    }
    if ((Request->LeafBytes == 2 && Request->Leaf[0] == L'.') ||
        (Request->LeafBytes == 4 && Request->Leaf[0] == L'.' && Request->Leaf[1] == L'.') ||
        !MetadataZero((const UCHAR *)Request->Leaf + Request->LeafBytes,
            sizeof(Request->Leaf) - Request->LeafBytes)) return METADATA_STATUS(STATUS_INVALID_PARAMETER);
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
        (Request->CreateDisposition == FILE_CREATE && !output)) return METADATA_STATUS(STATUS_ACCESS_DENIED);
    /* Reopening a candidate is recovery/read custody, not evidence that an
     * existing immutable commit may be rewritten. Only its creating handle
     * receives the bounded pre-F2 output phase. */
    if (Request->Role == SuHistoryCandidate && Request->CreateDisposition == FILE_OPEN &&
        (Request->AccessMask & FILE_WRITE_DATA) != 0) return METADATA_STATUS(STATUS_ACCESS_DENIED);
    if (!MetadataZero(&Request->ReplaceTargetIdentity, sizeof(Request->ReplaceTargetIdentity)) &&
        (!output || Request->Role == SuSegment || Request->Role == SuHistoryCandidate ||
         (Request->AccessMask & (DELETE | FILE_WRITE_DATA)) != (DELETE | FILE_WRITE_DATA)))
        return METADATA_STATUS(STATUS_INVALID_PARAMETER);
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
    if (Request->MaximumLogicalBytes > maximum) return METADATA_STATUS(STATUS_INVALID_PARAMETER);
    return STATUS_SUCCESS;
}

static BOOLEAN MetadataRoleRoot(_In_ ULONG Role, _In_ ULONG RootRole, _Inout_opt_ SU_METADATA_DIAGNOSTIC *Diagnostic)
{
    switch (Role) {
    case SuLedgerCurrent: case SuLedgerNew: return METADATA_BOOLEAN(RootRole == 2, STATUS_INVALID_PARAMETER);
    case SuCompanionCurrent: case SuCompanionNew: return METADATA_BOOLEAN(RootRole == 1, STATUS_INVALID_PARAMETER);
    case SuManifestCurrent: case SuManifestNew: case SuLegacySecurity:
    case SuEpochCurrent: case SuEpochNew: case SuHistoryCandidate: return METADATA_BOOLEAN(RootRole == 3, STATUS_INVALID_PARAMETER);
    case SuMarkerCurrent: case SuMarkerNew: return METADATA_BOOLEAN(RootRole == 2, STATUS_INVALID_PARAMETER);
    case SuLegacyNegative: return METADATA_BOOLEAN(RootRole == 1 || RootRole == 2, STATUS_INVALID_PARAMETER);
    default: return METADATA_BOOLEAN(RootRole == 4, STATUS_INVALID_PARAMETER);
    }
}

static BOOLEAN MetadataHex(_In_reads_(Chars) const WCHAR *Text, _In_ ULONG Chars, _Inout_opt_ SU_METADATA_DIAGNOSTIC *Diagnostic)
{
    ULONG i;
    for (i = 0; i < Chars; ++i)
        if (!((Text[i] >= L'0' && Text[i] <= L'9') || (Text[i] >= L'a' && Text[i] <= L'f') ||
            (Text[i] >= L'A' && Text[i] <= L'F'))) return METADATA_FALSE(STATUS_INVALID_PARAMETER);
    return METADATA_BOOLEAN(Chars != 0, STATUS_INVALID_PARAMETER);
}

_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN MetadataLeafRole(_In_ const SU_RESOURCE_CHILD_REQUEST *Request, _Inout_opt_ SU_METADATA_DIAGNOSTIC *Diagnostic)
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
                Request->Leaf[chars - 37] != L'.' || !MetadataHex(Request->Leaf + chars - 36, 32, Diagnostic)) return METADATA_FALSE(STATUS_INVALID_PARAMETER);
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
        return METADATA_BOOLEAN(baseChars > 38 && MetadataHex(Request->Leaf, 32, Diagnostic) && Request->Leaf[32] == L'.' &&
            RtlSuffixUnicodeString(&expected, &leaf, TRUE), STATUS_INVALID_PARAMETER);
    case SuSegment:
        RtlInitUnicodeString(&expected, L".pack");
        return METADATA_BOOLEAN((baseChars == 13 || baseChars == 37) && MetadataHex(Request->Leaf, baseChars - 5, Diagnostic) &&
            RtlSuffixUnicodeString(&expected, &leaf, TRUE), STATUS_INVALID_PARAMETER);
    default: return METADATA_FALSE(STATUS_INVALID_PARAMETER);
    }
    if (fixed != NULL) {
        RtlInitUnicodeString(&expected, fixed);
        return METADATA_BOOLEAN(RtlEqualUnicodeString(&leaf, &expected, TRUE), STATUS_INVALID_PARAMETER);
    }
    RtlInitUnicodeString(&expected, suffix);
    return METADATA_BOOLEAN(baseChars == 32 + expected.Length / sizeof(WCHAR) && MetadataHex(Request->Leaf, 32, Diagnostic) &&
        RtlSuffixUnicodeString(&expected, &leaf, TRUE), STATUS_INVALID_PARAMETER);
}

/* M held. Slot retirement is legal only after all contexts/target pins and
 * PASSIVE-only resources have gone. Closing moves diagnostic charge; it is
 * never a storage-release receipt and cannot reduce retained accounting. */
static VOID MetadataRemoveChildLocked(_Inout_ SU_METADATA_GROUP *Group, _In_ ULONG ChildIndex)
{
    SU_METADATA_CHILD *child = &Group->Children[ChildIndex];
    SU_METADATA_TRANSACTION *transaction = &Group->Transactions[ChildIndex / SU_METADATA_CHILDREN_PER_TRANSACTION];
    NT_ASSERT(child->Pins == 0 && child->TargetPins == 0 && child->Key == NULL && child->Security == NULL);
    if (child->ReplacementIndex != 0) {
        SU_METADATA_CHILD *target = &Group->Children[child->ReplacementIndex - 1];
        NT_ASSERT(target->Id == child->ReplacementId && target->TargetPins != 0);
        --target->TargetPins;
    }
    if (child->State == SuMetadataPendingOpen) transaction->Pending = FALSE;
    NT_ASSERT(Group->AccountingHeld || Group->LiveRetained >= child->Retained);
    if (!Group->AccountingHeld) Group->LiveRetained -= child->Retained;
    if (Group->RetiredRetained <= (UINT64)MAXLONGLONG - child->Retained)
        Group->RetiredRetained += child->Retained;
    else { Group->RetiredRetained = (UINT64)MAXLONGLONG; Group->AccountingHeld = TRUE; }
    RtlZeroMemory(child, sizeof(*child));
    NT_ASSERT(transaction->Children != 0);
    if (--transaction->Children == 0) RtlZeroMemory(transaction, sizeof(*transaction));
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS MetadataFoldLeaf(_In_reads_bytes_(Bytes) const WCHAR *Leaf, _In_ USHORT Bytes,
    _Out_writes_bytes_(512) WCHAR *Folded, _Inout_opt_ SU_METADATA_DIAGNOSTIC *Diagnostic)
{
    UNICODE_STRING source, destination;
    NTSTATUS status;
    source.Buffer = (PWCHAR)Leaf;
    source.Length = source.MaximumLength = Bytes;
    destination.Buffer = Folded;
    destination.Length = 0;
    destination.MaximumLength = 512;
    RtlZeroMemory(Folded, 512);
    status = RtlUpcaseUnicodeString(&destination, &source, FALSE);
    if (!NT_SUCCESS(status)) (VOID)METADATA_STATUS(status);
    return status;
}

static BOOLEAN MetadataTransactionClass(_In_ const GUID *Id, _In_ ULONG Role,
    _Out_ GUID *Masked, _Out_ PBOOLEAN Growth, _Inout_opt_ SU_METADATA_DIAGNOSTIC *Diagnostic)
{
    *Masked = *Id;
    *Growth = BooleanFlagOn(((const UCHAR *)Id)[15], 0x80);
    ((PUCHAR)Masked)[15] &= 0x7f;
    return METADATA_BOOLEAN(!MetadataZero(Masked, sizeof(*Masked)) && Role >= SuLedgerCurrent &&
        Role <= SuCompactionIntentNew && (!*Growth || Role <= SuCompanionNew), STATUS_INVALID_PARAMETER);
}

static ULONG MetadataCurrentRole(_In_ ULONG Role)
{
    switch (Role) {
    case SuLedgerNew: return SuLedgerCurrent;
    case SuCompanionNew: return SuCompanionCurrent;
    case SuManifestNew: return SuManifestCurrent;
    case SuInventoryNew: return SuInventoryCurrent;
    case SuMarkerNew: return SuMarkerCurrent;
    case SuEpochNew: return SuEpochCurrent;
    case SuAppendIntentNew: return SuAppendIntentCurrent;
    case SuCompactionIntentNew: return SuCompactionIntentCurrent;
    default: return 0;
    }
}

_IRQL_requires_(PASSIVE_LEVEL)
static __declspec(noinline) NTSTATUS MetadataRegisterChild(_In_ SU_METADATA_GROUP *Group,
    _In_ const SU_RESOURCE_CHILD_REQUEST *Request, _Out_ SU_RESOURCE_CHILD_REPLY *Reply, _Inout_opt_ SU_METADATA_DIAGNOSTIC *Diagnostic)
{
    GUID masked, other;
    ULONG i, root = SU_METADATA_ROOTS, transaction = SU_METADATA_TRANSACTIONS;
    ULONG first, end, childIndex = SU_METADATA_CHILDREN;
    BOOLEAN growth;
    ULONG replacement = 0;
    SU_METADATA_OUTPUT_PLAN plan;
    WCHAR folded[256];
    NTSTATUS status;
    KIRQL irql;
    if (Diagnostic != NULL && Diagnostic->Line == 0) Diagnostic->Role = Request->Role;
    MetadataDiagnosticNode(Diagnostic, SU_METADATA_CHILD_NODE);
    Reply->Result = 2;
    status = MetadataChildShape(Request, Diagnostic);
    if (!NT_SUCCESS(status)) return METADATA_STATUS(status);
    if (!MetadataTransactionClass(&Request->TransactionId, Request->Role, &masked, &growth, Diagnostic) ||
        !MetadataLeafRole(Request, Diagnostic)) return METADATA_STATUS(STATUS_INVALID_PARAMETER);
    status = SafeUploadMetadataPlanOutput(1, Request->MaximumLogicalBytes, Request->MaximumLogicalBytes,
        Group->IoAlignment, Group->AllocationUnit, &plan);
    if (!NT_SUCCESS(status)) return METADATA_STATUS(status);
    status = MetadataFoldLeaf(Request->Leaf, (USHORT)Request->LeafBytes, folded, Diagnostic);
    if (!NT_SUCCESS(status)) return METADATA_STATUS(status);
    KeAcquireSpinLock(&MetadataLock, &irql);
    if (Group->Revoked || Group->AccountingHeld) { status = METADATA_STATUS(STATUS_ACCESS_DENIED); goto Unlock; }
    for (i = 0; i < SU_METADATA_ROOTS; ++i)
        if (Group->Roots[i].Id == Request->RootId && Group->Roots[i].Key != NULL && !Group->Roots[i].Cleaned) { root = i; break; }
    if (root < SU_METADATA_ROOTS) MetadataDiagnosticNode(Diagnostic, MetadataRoleNodes[root]);
    if (root == SU_METADATA_ROOTS || !MetadataRoleRoot(Request->Role, root + 1, Diagnostic)) {
        status = METADATA_STATUS(STATUS_INVALID_PARAMETER); goto Unlock;
    }
    first = growth ? 0 : 8;
    end = first + 8;
    for (i = 0; i < SU_METADATA_TRANSACTIONS; ++i) {
        if (Group->Transactions[i].Children == 0) continue;
        other = Group->Transactions[i].Id;
        ((PUCHAR)&other)[15] &= 0x7f;
        if (!RtlEqualMemory(&masked, &other, sizeof(masked))) continue;
        if (!RtlEqualMemory(&Request->TransactionId, &Group->Transactions[i].Id, sizeof(GUID))) {
            status = METADATA_STATUS(STATUS_INVALID_PARAMETER); goto Unlock;
        }
        transaction = i;
    }
    /* A replacement's existing target pin belongs to its pending intent.
     * Recognize exact replay BEFORE treating that pin as competing ownership. */
    for (i = 0; i < SU_METADATA_CHILDREN; ++i) {
        const SU_METADATA_CHILD *held = &Group->Children[i];
        if (held->State != SuMetadataPendingOpen || held->Request.RootId != Request->RootId ||
            held->LiveLeafBytes != Request->LeafBytes || !RtlEqualMemory(held->FoldedLeaf, folded, Request->LeafBytes)) continue;
        if (RtlEqualMemory(&held->Request, Request, sizeof(*Request))) {
            Reply->Result = 1; Reply->ChildIntentId = held->Id; status = STATUS_SUCCESS;
        } else status = METADATA_STATUS(RtlEqualMemory(&held->Request.TransactionId, &Request->TransactionId, sizeof(GUID)) ?
            STATUS_INVALID_PARAMETER : STATUS_DEVICE_BUSY);
        goto Unlock;
    }
    /* Exclusive store claim spans pending/active/retiring objects. One exact
     * New -> Current pair in the same transaction shares its replacement
     * claim; the current credit stays pinned until that new owner retires. */
    for (i = 0; i < SU_METADATA_CHILDREN; ++i) {
        const SU_METADATA_CHILD *held = &Group->Children[i];
        if (held->State == 0 || held->Request.RootId != Request->RootId) continue;
        if (!MetadataZero(&Request->ReplaceTargetIdentity, sizeof(Request->ReplaceTargetIdentity)) &&
            held->State == SuMetadataActive && !held->Cleaned && held->Key != NULL &&
            held->Request.Role == MetadataCurrentRole(Request->Role) &&
            RtlEqualMemory(&held->Request.TransactionId, &Request->TransactionId, sizeof(GUID)) &&
            RtlEqualMemory(&held->Identity, &Request->ReplaceTargetIdentity, sizeof(held->Identity))) {
            if (held->TargetPins != 0) { status = METADATA_STATUS(STATUS_DEVICE_BUSY); goto Unlock; }
            replacement = i + 1;
            continue;
        }
        if ((held->LiveLeafBytes == Request->LeafBytes &&
             RtlEqualMemory(held->FoldedLeaf, folded, Request->LeafBytes)) ||
            (!MetadataZero(&Request->ReplaceTargetIdentity, sizeof(Request->ReplaceTargetIdentity)) &&
             (RtlEqualMemory(&Request->ReplaceTargetIdentity, &held->Request.ReplaceTargetIdentity,
                 sizeof(Request->ReplaceTargetIdentity)) ||
              RtlEqualMemory(&Request->ReplaceTargetIdentity, &held->Request.ExpectedIdentity,
                 sizeof(Request->ReplaceTargetIdentity)))) ||
            (!MetadataZero(&held->Request.ReplaceTargetIdentity, sizeof(held->Request.ReplaceTargetIdentity)) &&
             RtlEqualMemory(&held->Request.ReplaceTargetIdentity, &Request->ExpectedIdentity,
                 sizeof(Request->ExpectedIdentity)))) {
            status = METADATA_STATUS(RtlEqualMemory(&held->Request.TransactionId, &Request->TransactionId, sizeof(GUID)) ?
                STATUS_INVALID_PARAMETER : STATUS_DEVICE_BUSY);
            goto Unlock;
        }
    }
    if (!MetadataZero(&Request->ReplaceTargetIdentity, sizeof(Request->ReplaceTargetIdentity)) && replacement == 0) {
        status = METADATA_STATUS(STATUS_INVALID_PARAMETER); goto Unlock;
    }
    if (transaction == SU_METADATA_TRANSACTIONS) {
        for (i = first; i < end; ++i)
            if (Group->Transactions[i].Children == 0) { transaction = i; break; }
        if (transaction == SU_METADATA_TRANSACTIONS) { status = METADATA_STATUS(STATUS_DEVICE_BUSY); goto Unlock; }
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
            } else status = METADATA_STATUS(STATUS_INVALID_PARAMETER);
            goto Unlock;
        }
    }
    if (Group->Transactions[transaction].Pending || childIndex == SU_METADATA_CHILDREN) {
        status = METADATA_STATUS(STATUS_DEVICE_BUSY); goto Unlock;
    }
    if (Group->NextChildId == (UINT64)MAXLONGLONG) { status = METADATA_STATUS(STATUS_TOO_MANY_CONTEXT_IDS); goto Unlock; }
    Group->Transactions[transaction].Id = Request->TransactionId;
    ++Group->Transactions[transaction].Children;
    Group->Transactions[transaction].Pending = TRUE;
    Group->Children[childIndex].Id = ++Group->NextChildId;
    Group->Children[childIndex].Request = *Request;
    Group->Children[childIndex].LiveLeafBytes = Request->LeafBytes;
    RtlCopyMemory(Group->Children[childIndex].FoldedLeaf, folded, Request->LeafBytes);
    Group->Children[childIndex].State = SuMetadataPendingOpen;
    Group->Children[childIndex].PaddedExtent = plan.PaddedWriteExtent;
    Group->Children[childIndex].Nominal = plan.PeakAllocation;
    Group->Children[childIndex].ReplacementIndex = replacement;
    if (replacement != 0) {
        Group->Children[childIndex].ReplacementId = Group->Children[replacement - 1].Id;
        ++Group->Children[replacement - 1].TargetPins;
    }
    Reply->Result = 1;
    Reply->ChildIntentId = Group->Children[childIndex].Id;
    status = STATUS_SUCCESS;
Unlock:
    KeReleaseSpinLock(&MetadataLock, irql);
    return METADATA_STATUS(status);
}

/* Per-invocation scratch and a nonqueued metadata class. This routine has no
 * policy/epoch/namespace/service call and no wait for a credit or cleanup. */
_Use_decl_annotations_
NTSTATUS SafeUploadMetadataControl(PVOID Cookie, BOOLEAN ResourceChannel, PVOID Input,
    ULONG InputBytes, PVOID Output, ULONG OutputBytes, PULONG Returned)
{
    SU_METADATA_DIAGNOSTIC refusal;
    SU_METADATA_DIAGNOSTIC *Diagnostic = &refusal;
    SU_METADATA_CONTROL_BUFFER *buffer;
    SU_RESOURCE_CONTROL_HEADER header;
    SU_METADATA_GROUP *group = NULL;
    ULONG payload, replyBytes, slot = SU_METADATA_CONTROLS + 2, i, first, last;
    BOOLEAN revoke = FALSE, bootstrap = FALSE;
    GUID masked;
    BOOLEAN growth;
    BOOLEAN refused = FALSE;
    ULONG diagnosticOpcode = 0;
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    KIRQL irql;

    MetadataDiagnosticReset(Diagnostic, SU_METADATA_UNKNOWN_NODE, 0);
    *Returned = 0;
    if (Cookie == NULL || Input == NULL || Output == NULL || InputBytes < sizeof(header))
        return MetadataDiagnosticControlReturn(Diagnostic, diagnosticOpcode, STATUS_INVALID_BUFFER_SIZE, refused, __LINE__);
    __try {
        ProbeForRead(Input, sizeof(header), __alignof(SU_RESOURCE_CONTROL_HEADER));
        RtlCopyMemory(&header, Input, sizeof(header));
    } __except (EXCEPTION_EXECUTE_HANDLER) { return MetadataDiagnosticControlReturn(Diagnostic, diagnosticOpcode, GetExceptionCode(), refused, __LINE__); }
    diagnosticOpcode = header.Opcode;
    if (header.Version != SAFEUPLOAD_PROTOCOL_VERSION || header.StructSize != InputBytes ||
        header.Command != SAFEUPLOAD_CONTROL_RESOURCE || header.Reserved != 0 ||
        header.ResourceVersion != SAFEUPLOAD_RESOURCE_VERSION || header.ControlRequestId == 0 ||
        header.Flags != 0 || header.PayloadBytes != InputBytes - sizeof(header)) return MetadataDiagnosticControlReturn(Diagnostic, diagnosticOpcode, STATUS_INVALID_PARAMETER, refused, __LINE__);
    if (ResourceChannel != (header.Opcode != SU_RESOURCE_NEGOTIATE)) return MetadataDiagnosticControlReturn(Diagnostic, diagnosticOpcode, STATUS_INVALID_DEVICE_REQUEST, refused, __LINE__);
    if (header.Opcode >= SU_RESOURCE_FENCE) {
        group = MetadataPin(Cookie);
        if (group == NULL) return MetadataDiagnosticControlReturn(Diagnostic, diagnosticOpcode, STATUS_ACCESS_DENIED, refused, __LINE__);
        status = MetadataAuthenticate(group) && header.ConnectionCookie == (UINT64)(ULONG_PTR)Cookie &&
            RtlEqualMemory(&header.DriverInstance, &group->DriverInstance, sizeof(GUID)) ?
            STATUS_NOT_SUPPORTED : STATUS_ACCESS_DENIED;
        ExReleaseRundownProtection(&group->Rundown);
        return MetadataDiagnosticControlReturn(Diagnostic, diagnosticOpcode, status, refused, __LINE__);
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
    default: return MetadataDiagnosticControlReturn(Diagnostic, diagnosticOpcode, STATUS_NOT_SUPPORTED, refused, __LINE__);
    }
    if (header.PayloadBytes != payload || OutputBytes != sizeof(header) + replyBytes)
        return MetadataDiagnosticControlReturn(Diagnostic, diagnosticOpcode, STATUS_INVALID_BUFFER_SIZE, refused, __LINE__);
    if (header.Opcode == SU_RESOURCE_NEGOTIATE) {
        KeAcquireSpinLock(&MetadataLock, &irql);
        if (!MetadataClosing && !MetadataBootstrap) {
            MetadataBootstrap = TRUE;
            bootstrap = TRUE;
        }
        KeReleaseSpinLock(&MetadataLock, irql);
        if (!bootstrap) return MetadataDiagnosticControlReturn(Diagnostic, diagnosticOpcode, STATUS_DEVICE_BUSY, refused, __LINE__);
        if (!MetadataOriginalToken(NULL)) { status = METADATA_STATUS(STATUS_ACCESS_DENIED); goto Exit; }
    }
    if (header.Opcode != SU_RESOURCE_NEGOTIATE || header.ConnectionCookie != 0) {
        group = MetadataPin(Cookie);
        if (group == NULL) { status = METADATA_STATUS(STATUS_ACCESS_DENIED); goto Exit; }
        if (header.ConnectionCookie != (UINT64)(ULONG_PTR)Cookie ||
            !RtlEqualMemory(&header.DriverInstance, &group->DriverInstance, sizeof(GUID))) {
            status = METADATA_STATUS(STATUS_ACCESS_DENIED);
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
        if (slot == SU_METADATA_CONTROLS + 2) { status = METADATA_STATUS(STATUS_DEVICE_BUSY); goto Exit; }
        if (!MetadataAuthenticate(group)) { status = METADATA_STATUS(STATUS_ACCESS_DENIED); goto Exit; }
    } else if (!MetadataZero(&header.DriverInstance, sizeof(GUID))) {
        status = METADATA_STATUS(STATUS_INVALID_PARAMETER);
        goto Exit;
    }
    buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*buffer), SU_METADATA_TAG);
    if (buffer == NULL) { status = METADATA_STATUS(STATUS_INSUFFICIENT_RESOURCES); goto Exit; }
    __try {
        ProbeForRead(Input, InputBytes, __alignof(SU_RESOURCE_CONTROL_HEADER));
#pragma warning(suppress: 6001) /* ProbeForWrite never reads the buffer; same idiom as Communication.c */
        ProbeForWrite(Output, OutputBytes, __alignof(SU_RESOURCE_CONTROL_HEADER));
        RtlCopyMemory(buffer, Input, InputBytes);
        if (!RtlEqualMemory(&buffer->Header, &header, sizeof(header))) {
            status = METADATA_STATUS(STATUS_INVALID_PARAMETER);
            __leave;
        }
        buffer->ReplyHeader = header;
        buffer->ReplyHeader.PayloadBytes = replyBytes;
        buffer->ReplyHeader.StructSize = (ULONG)sizeof(header) + replyBytes;
        switch (header.Opcode) {
        case SU_RESOURCE_NEGOTIATE:
            if (!MetadataNegotiateShape(&buffer->Request.Negotiate)) { status = METADATA_STATUS(STATUS_INVALID_PARAMETER); break; }
            if (buffer->Request.Negotiate.Phase == 1) {
                if (header.ConnectionCookie != 0) { status = METADATA_STATUS(STATUS_INVALID_PARAMETER); break; }
                status = MetadataProbe(Cookie, &buffer->Request.Negotiate, &buffer->ReplyHeader.DriverInstance);
                if (!NT_SUCCESS(status)) break;
                buffer->ReplyHeader.ConnectionCookie = (UINT64)(ULONG_PTR)Cookie;
            } else {
                if (group == NULL || !RtlEqualMemory(&group->Probe, &buffer->Request.Negotiate,
                    FIELD_OFFSET(SU_RESOURCE_NEGOTIATE_REQUEST, ReadinessEpoch))) {
                    status = METADATA_STATUS(STATUS_INVALID_PARAMETER);
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
                buffer->Request.Revoke.ReasonOrResult > 3) { status = METADATA_STATUS(STATUS_INVALID_PARAMETER); break; }
            buffer->Reply.Revoke.ReasonOrResult = 1;
            revoke = TRUE;
            status = STATUS_SUCCESS;
            break;
        case SU_RESOURCE_REGISTER_ROOT:
            if (group == NULL) { status = METADATA_STATUS(STATUS_ACCESS_DENIED); break; }
            Diagnostic->Role = buffer->Request.Root.RootRole;
            if (!MetadataRootShape(&buffer->Request.Root, Diagnostic)) { status = METADATA_STATUS(STATUS_INVALID_PARAMETER); break; }
            status = MetadataRegisterRoot(group, &buffer->Request.Root, &buffer->Reply.Root, Diagnostic);
            refused = buffer->Reply.Root.Result == 2;
            /* Malformed wire was rejected above. Well-formed native authority
             * refusals are typed; exhaustion remains native Busy, with no ID. */
            if (status != STATUS_DEVICE_BUSY && !NT_SUCCESS(status)) status = STATUS_SUCCESS;
            break;
        case SU_RESOURCE_REGISTER_CHILD:
            if (group == NULL) { status = METADATA_STATUS(STATUS_ACCESS_DENIED); break; }
            Diagnostic->Role = buffer->Request.Child.Role;
            status = MetadataChildShape(&buffer->Request.Child, Diagnostic);
            if (status == STATUS_INVALID_PARAMETER ||
                !MetadataTransactionClass(&buffer->Request.Child.TransactionId, buffer->Request.Child.Role, &masked, &growth, Diagnostic) ||
                !MetadataLeafRole(&buffer->Request.Child, Diagnostic)) { status = METADATA_STATUS(STATUS_INVALID_PARAMETER); break; }
            status = MetadataRegisterChild(group, &buffer->Request.Child, &buffer->Reply.Child, Diagnostic);
            refused = buffer->Reply.Child.Result == 2;
            if (status != STATUS_DEVICE_BUSY && !NT_SUCCESS(status)) status = STATUS_SUCCESS;
            break;
        default: status = METADATA_STATUS(STATUS_NOT_SUPPORTED); break;
        }
        if (NT_SUCCESS(status)) {
            RtlCopyMemory(Output, &buffer->ReplyHeader, sizeof(header));
            RtlCopyMemory((PUCHAR)Output + sizeof(header), &buffer->Reply, replyBytes);
            *Returned = (ULONG)sizeof(header) + replyBytes;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { status = METADATA_STATUS(GetExceptionCode()); }
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
    return MetadataDiagnosticControlReturn(Diagnostic, diagnosticOpcode, status, refused, __LINE__);
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
        MetadataForgetKeysLocked(MetadataRoutingGroup);
        revoke = TRUE;
    }
    KeReleaseSpinLock(&MetadataLock, irql);
    if (revoke) SafeUploadMetadataRevoke(NULL);
    KeSetEvent(&MetadataWork, IO_NO_INCREMENT, FALSE);
}

_IRQL_requires_(PASSIVE_LEVEL)
static __declspec(noinline) NTSTATUS MetadataCheckName(_In_ SU_METADATA_GROUP *Group, _In_ ULONG Index, _In_ PFILE_OBJECT Object, _Inout_opt_ SU_METADATA_DIAGNOSTIC *Diagnostic);

_IRQL_requires_(PASSIVE_LEVEL)
static __declspec(noinline) NTSTATUS MetadataSameVolume(_In_ SU_METADATA_GROUP *Group, _In_ PFILE_OBJECT Object, _Inout_opt_ SU_METADATA_DIAGNOSTIC *Diagnostic)
{
    PFLT_VOLUME volume = NULL;
    NTSTATUS status = FltGetVolumeFromFileObject(SafeUploadData.Filter, Object, &volume);
    if (status != STATUS_SUCCESS) return METADATA_STATUS(status);
    status = METADATA_STATUS(volume == Group->Volume ? STATUS_SUCCESS : STATUS_NOT_SAME_DEVICE);
    FltObjectDereference(volume);
    return METADATA_STATUS(status);
}

typedef struct _SU_METADATA_MEASUREMENT {
    SAFEUPLOAD_STAGE_IDENTITY_V19 Identity;
    UINT64 Eof, Allocation;
    ULONG Links, SecurityBytes;
    BOOLEAN DeletePending, Observed;
    PSECURITY_DESCRIPTOR Security;
} SU_METADATA_MEASUREMENT;

static BOOLEAN MetadataPowerOfTwo(_In_ ULONG Value)
{
    return Value != 0 && (Value & (Value - 1)) == 0;
}

_IRQL_requires_(PASSIVE_LEVEL)
static __declspec(noinline) NTSTATUS MetadataCaptureAlignment(_In_ PFLT_INSTANCE Instance, _In_ PFLT_VOLUME Volume,
    _Out_ PULONG Alignment, _Out_ PULONG Unit, _Inout_opt_ SU_METADATA_DIAGNOSTIC *Diagnostic)
{
    FILE_FS_SECTOR_SIZE_INFORMATION sector;
    FILE_FS_SIZE_INFORMATION size;
    FLT_VOLUME_PROPERTIES properties;
    IO_STATUS_BLOCK io;
    ULONG returned = 0, a = 4096;
    UINT64 unit;
    NTSTATUS status;
    MetadataDiagnosticNode(Diagnostic, 0);
    *Alignment = *Unit = 0;
    RtlZeroMemory(&sector, sizeof(sector));
    RtlZeroMemory(&size, sizeof(size));
    RtlZeroMemory(&properties, sizeof(properties));
    RtlZeroMemory(&io, sizeof(io));
    status = FltQueryVolumeInformation(Instance, &io, &sector, sizeof(sector), FileFsSectorSizeInformation);
    if (status != STATUS_SUCCESS) return METADATA_STATUS(status);
    if (io.Information != sizeof(sector)) return METADATA_STATUS(STATUS_INFO_LENGTH_MISMATCH);
    status = FltQueryVolumeInformation(Instance, &io, &size, sizeof(size), FileFsSizeInformation);
    if (status != STATUS_SUCCESS) return METADATA_STATUS(status);
    if (io.Information != sizeof(size) || size.BytesPerSector != sector.LogicalBytesPerSector ||
        size.TotalAllocationUnits.QuadPart <= 0 || size.AvailableAllocationUnits.QuadPart < 0 ||
        size.AvailableAllocationUnits.QuadPart > size.TotalAllocationUnits.QuadPart)
        return METADATA_STATUS(STATUS_INFO_LENGTH_MISMATCH);
    /* FileAlignmentInformation is answered by the I/O manager from device
     * state, not by NTFS, so it is not sent below the filter. The volume
     * properties carry the same AlignmentRequirement; a fixed-size buffer
     * normally returns STATUS_BUFFER_OVERFLOW with the fixed fields valid. */
    status = FltGetVolumeProperties(Volume, &properties, sizeof(properties), &returned);
    if (status != STATUS_SUCCESS && status != STATUS_BUFFER_OVERFLOW) return METADATA_STATUS(status);
    if (properties.AlignmentRequirement >= 65536) return METADATA_STATUS(STATUS_NOT_SUPPORTED);
    if (!MetadataPowerOfTwo(sector.LogicalBytesPerSector) ||
        !MetadataPowerOfTwo(sector.PhysicalBytesPerSectorForAtomicity) ||
        !MetadataPowerOfTwo(sector.FileSystemEffectivePhysicalBytesPerSectorForAtomicity) ||
        !MetadataPowerOfTwo(properties.AlignmentRequirement + 1)) return METADATA_STATUS(STATUS_NOT_SUPPORTED);
    if (sector.LogicalBytesPerSector > a) a = sector.LogicalBytesPerSector;
    if (sector.PhysicalBytesPerSectorForAtomicity > a) a = sector.PhysicalBytesPerSectorForAtomicity;
    if (sector.FileSystemEffectivePhysicalBytesPerSectorForAtomicity > a)
        a = sector.FileSystemEffectivePhysicalBytesPerSectorForAtomicity;
    if (properties.AlignmentRequirement + 1 > a) a = properties.AlignmentRequirement + 1;
    unit = (UINT64)size.SectorsPerAllocationUnit * size.BytesPerSector;
    if (a > 65536 || unit > 65536 || !MetadataPowerOfTwo((ULONG)unit)) return METADATA_STATUS(STATUS_NOT_SUPPORTED);
    *Alignment = a;
    *Unit = (ULONG)unit;
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
static __declspec(noinline) NTSTATUS MetadataInspectChild(_In_ SU_METADATA_GROUP *Group, _In_ ULONG Index,
    _In_ PFILE_OBJECT Object, _In_ BOOLEAN Opening, _Out_ SU_METADATA_MEASUREMENT *Measurement, _Inout_opt_ SU_METADATA_DIAGNOSTIC *Diagnostic)
{
    FILE_ID_INFORMATION id;
    FILE_STANDARD_INFORMATION standard;
    FILE_ATTRIBUTE_TAG_INFORMATION tag;
    SU_METADATA_NODE security;
    ULONG bytes = 0;
    NTSTATUS status;
    RtlZeroMemory(Measurement, sizeof(*Measurement));
    RtlZeroMemory(&security, sizeof(security));
    RtlZeroMemory(&id, sizeof(id));
    RtlZeroMemory(&standard, sizeof(standard));
    RtlZeroMemory(&tag, sizeof(tag));
    status = MetadataSameVolume(Group, Object, Diagnostic);
    if (status != STATUS_SUCCESS) return METADATA_STATUS(status);
    status = FltQueryInformationFile(Group->Instance, Object, &id, sizeof(id), FileIdInformation, &bytes);
    if (status != STATUS_SUCCESS) return METADATA_STATUS(status);
    if (bytes != sizeof(id)) return METADATA_STATUS(STATUS_INFO_LENGTH_MISMATCH);
    Measurement->Identity.VolumeSerialNumber = id.VolumeSerialNumber;
    Measurement->Identity.FileId = id.FileId;
    status = FltQueryInformationFile(Group->Instance, Object, &standard, sizeof(standard), FileStandardInformation, &bytes);
    if (status != STATUS_SUCCESS) return METADATA_STATUS(status);
    if (bytes != sizeof(standard) || standard.Directory || standard.EndOfFile.QuadPart < 0 ||
        standard.AllocationSize.QuadPart < 0) return METADATA_STATUS(STATUS_FILE_INVALID);
    Measurement->Observed = TRUE;
    Measurement->Eof = (UINT64)standard.EndOfFile.QuadPart;
    Measurement->Allocation = (UINT64)standard.AllocationSize.QuadPart;
    Measurement->Links = standard.NumberOfLinks;
    Measurement->DeletePending = standard.DeletePending;
    status = FltQueryInformationFile(Group->Instance, Object, &tag, sizeof(tag), FileAttributeTagInformation, &bytes);
    if (status != STATUS_SUCCESS) return METADATA_STATUS(status);
    /* ReparseTag is undefined unless the attribute is set; the attribute decides. */
    if (bytes != sizeof(tag) || FlagOn(tag.FileAttributes,
        FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_SPARSE_FILE |
        FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_ENCRYPTED))
        return METADATA_STATUS(STATUS_FILE_INVALID);
    /* The original relative leaf excludes ADS. Requerying identity below this
     * instance supplies object authority; no name normalization is performed. */
    if (Opening) {
        if (!FlagOn(Object->Flags, FO_NO_INTERMEDIATE_BUFFERING) || !FlagOn(Object->Flags, FO_SYNCHRONOUS_IO) ||
            ((Group->Children[Index].Request.AccessMask & FILE_WRITE_DATA) != 0 && !FlagOn(Object->Flags, FO_WRITE_THROUGH)))
            return METADATA_STATUS(STATUS_INVALID_DEVICE_STATE);
        status = MetadataCheckName(Group, Index, Object, Diagnostic);
        if (status != STATUS_SUCCESS) return METADATA_STATUS(status);
        if (standard.NumberOfLinks != 1 || standard.DeletePending) return METADATA_STATUS(STATUS_FILE_INVALID);
        if (Group->Children[Index].Request.CreateDisposition == FILE_OPEN &&
            !RtlEqualMemory(&Measurement->Identity, &Group->Children[Index].Request.ExpectedIdentity, sizeof(id)))
            return METADATA_STATUS(STATUS_FILE_INVALID);
    } else {
        if (!RtlEqualMemory(&Measurement->Identity, &Group->Children[Index].Identity, sizeof(id))) return METADATA_STATUS(STATUS_FILE_INVALID);
        if (standard.NumberOfLinks != 1 && !(Group->Children[Index].Unlinked &&
            standard.NumberOfLinks == 0 && standard.DeletePending)) return METADATA_STATUS(STATUS_FILE_INVALID);
        if (standard.DeletePending && !Group->Children[Index].Unlinked && !Group->Children[Index].Deleted)
            return METADATA_STATUS(STATUS_FILE_INVALID);
    }
    if (Measurement->Identity.VolumeSerialNumber != Group->Nodes[0].Identity.VolumeSerialNumber)
        return METADATA_STATUS(STATUS_NOT_SAME_DEVICE);
    security.Object = Object;
    status = MetadataCaptureSecurity(Group->Instance, &security, Diagnostic);
    if (status == STATUS_SUCCESS && !MetadataSecurityPredicate(&security, FALSE, FALSE, NULL, Diagnostic)) status = METADATA_STATUS(STATUS_ACCESS_DENIED);
    if (status == STATUS_SUCCESS && !Opening && (security.SecurityBytes != Group->Children[Index].SecurityBytes ||
        !RtlEqualMemory(security.Security, Group->Children[Index].Security, security.SecurityBytes)))
        status = METADATA_STATUS(STATUS_INVALID_SECURITY_DESCR);
    if (status == STATUS_SUCCESS && Opening) {
        Measurement->Security = security.Security;
        Measurement->SecurityBytes = security.SecurityBytes;
        security.Security = NULL;
    }
    if (security.Security != NULL) ExFreePoolWithTag(security.Security, SU_METADATA_TAG);
    return METADATA_STATUS(status);
}

_IRQL_requires_(PASSIVE_LEVEL)
static __declspec(noinline) NTSTATUS MetadataCheckAnchors(_In_ SU_METADATA_GROUP *Group, _Inout_opt_ SU_METADATA_DIAGNOSTIC *Diagnostic)
{
    SU_METADATA_NODE security;
    SAFEUPLOAD_STAGE_IDENTITY_V19 id;
    ULONG i;
    ULONG savedNode = Diagnostic == NULL ? SU_METADATA_UNKNOWN_NODE : Diagnostic->Node;
    NTSTATUS status;
    for (i = 0; i < SU_METADATA_NODES; ++i) {
        MetadataDiagnosticNode(Diagnostic, i);
        status = MetadataQueryDirectory(Group->Instance, Group->Nodes[i].Object, &id, Diagnostic);
        if (status != STATUS_SUCCESS || !RtlEqualMemory(&id, &Group->Nodes[i].Identity, sizeof(id))) return METADATA_STATUS(STATUS_FILE_INVALID);
        RtlZeroMemory(&security, sizeof(security));
        security.Object = Group->Nodes[i].Object;
        status = MetadataCaptureSecurity(Group->Instance, &security, Diagnostic);
        if (status == STATUS_SUCCESS && (security.SecurityBytes != Group->Nodes[i].SecurityBytes ||
            !RtlEqualMemory(security.Security, Group->Nodes[i].Security, security.SecurityBytes)))
            status = METADATA_STATUS(STATUS_INVALID_SECURITY_DESCR);
        if (security.Security != NULL) ExFreePoolWithTag(security.Security, SU_METADATA_TAG);
        if (status != STATUS_SUCCESS) return METADATA_STATUS(status);
    }
    MetadataDiagnosticNode(Diagnostic, savedNode);
    return STATUS_SUCCESS;
}

/* M held. Statistics never confer charge authority or authorize a refund.
 * The agent must precharge Q derived from MaximumLogicalBytes BEFORE CREATE. */
static NTSTATUS MetadataAccountLocked(_Inout_ SU_METADATA_GROUP *Group, _Inout_ SU_METADATA_CHILD *Child,
    _In_ const SU_METADATA_MEASUREMENT *Measurement, _Inout_opt_ SU_METADATA_DIAGNOSTIC *Diagnostic)
{
    UINT64 retained, delta;
    if (Measurement->Allocation > (UINT64)MAXLONGLONG - (Group->AllocationUnit - 1)) {
        if (Measurement->Allocation > Child->Peak) Child->Peak = Measurement->Allocation;
        Child->Retained = (UINT64)MAXLONGLONG;
        Child->Uncertain = TRUE;
        Group->LiveRetained = (UINT64)MAXLONGLONG;
        Group->ObservedPeak = (UINT64)MAXLONGLONG;
        Group->AccountingHeld = TRUE;
        if (Group->UnknownOutcomes < (UINT64)MAXLONGLONG) ++Group->UnknownOutcomes;
        return METADATA_STATUS(STATUS_INTEGER_OVERFLOW);
    }
    retained = (Measurement->Allocation + Group->AllocationUnit - 1) & ~((UINT64)Group->AllocationUnit - 1);
    if (retained < Child->Nominal) retained = Child->Nominal;
    if (retained > Child->Retained) {
        delta = retained - Child->Retained;
        Child->Retained = retained;
        if (Group->LiveRetained > (UINT64)MAXLONGLONG - delta) {
            Group->LiveRetained = (UINT64)MAXLONGLONG;
            Group->AccountingHeld = TRUE;
        } else Group->LiveRetained += delta;
    }
    if (Measurement->Allocation > Child->Peak) Child->Peak = Measurement->Allocation;
    if (Group->LiveRetained > Group->ObservedPeak) Group->ObservedPeak = Group->LiveRetained;
    Child->EndOfFile = Measurement->Eof;
    Child->Allocation = Measurement->Allocation;
    return METADATA_STATUS(Group->AccountingHeld ? STATUS_INTEGER_OVERFLOW :
        (Measurement->Allocation > Child->Nominal || Measurement->Eof > Child->PaddedExtent) ? STATUS_DISK_FULL : STATUS_SUCCESS);
}

/* M held. The context consumes an existing reserved child credit. */
static VOID MetadataStartContextLocked(_Inout_ SU_METADATA_GROUP *Group, _Inout_ SU_METADATA_COMPLETION *Context,
    _In_ ULONG Root, _In_ ULONG Child, _In_ PFILE_OBJECT Object, _In_ UCHAR Operation)
{
    RtlZeroMemory(Context, sizeof(*Context));
    Context->Signature = SU_METADATA_CONTEXT_SIGNATURE;
    Context->Group = Group;
    Context->RootIndex = Root;
    Context->ChildIndex = Child;
    Context->Object = Object;
    Context->Operation = Operation;
    Context->Incarnation = Child == SU_METADATA_CHILDREN ? Group->Roots[Root].Id : Group->Children[Child].Id;
    MetadataDiagnosticReset(&Context->Diagnostic, Child == SU_METADATA_CHILDREN ? MetadataRoleNodes[Root] : SU_METADATA_CHILD_NODE,
        Child == SU_METADATA_CHILDREN ? Root + 1 : Group->Children[Child].Request.Role);
    Context->InUse = TRUE;
    if (Child != SU_METADATA_CHILDREN) ++Group->Children[Child].Pins;
    ++Group->PostOwners;
}

_IRQL_requires_(PASSIVE_LEVEL)
static VOID MetadataReleaseIo(_Inout_ SU_METADATA_COMPLETION *Context)
{
    SU_METADATA_GROUP *group = Context->Group;
    KIRQL irql;
    MetadataDiagnosticPrint(Context->Operation == IRP_MJ_CREATE ? "ChildCreate" :
        Context->ChildIndex == SU_METADATA_CHILDREN ? "RootIo" : "ChildIo", &Context->Diagnostic);
    /* Keep both record pins until releases finish, including reentrant CLOSE. */
    if (Context->TargetHandle != NULL) ZwClose(Context->TargetHandle);
    if (Context->TargetReference != NULL) ObDereferenceObject(Context->TargetReference);
    if (Context->Reference != NULL) ObDereferenceObject(Context->Reference);
    KeAcquireSpinLock(&MetadataLock, &irql);
    if (Context->TargetIndex != 0) {
        SU_METADATA_CHILD *target = &group->Children[Context->TargetIndex - 1];
        NT_ASSERT(target->Id == Context->TargetId && target->Pins != 0);
        --target->Pins;
    }
    if (Context->ChildIndex != SU_METADATA_CHILDREN) {
        NT_ASSERT(group->Children[Context->ChildIndex].Id == Context->Incarnation);
        --group->Children[Context->ChildIndex].Pins;
    }
    Context->InUse = FALSE;
    Context->Signature = 0;
    --group->PostOwners;
    KeReleaseSpinLock(&MetadataLock, irql);
    ExReleaseRundownProtection(&group->Rundown);
    KeSetEvent(&MetadataWork, IO_NO_INCREMENT, FALSE);
}

_IRQL_requires_(PASSIVE_LEVEL)
static VOID MetadataServiceChildren(_Inout_ SU_METADATA_GROUP *Group)
{
    ULONG i;
    KIRQL irql;
    KeAcquireSpinLock(&MetadataLock, &irql);
    if (Group->ForceForgetKeys) MetadataForgetKeysLocked(Group);
    KeReleaseSpinLock(&MetadataLock, irql);
    for (i = 0; i < SU_METADATA_ROOTS; ++i) {
        BOOLEAN deferred;
        KeAcquireSpinLock(&MetadataLock, &irql);
        deferred = Group->Roots[i].Io.InUse && Group->Roots[i].Io.Deferred;
        if (deferred) Group->Roots[i].Io.Deferred = FALSE;
        KeReleaseSpinLock(&MetadataLock, irql);
        if (deferred) MetadataReleaseIo(&Group->Roots[i].Io);
    }
    for (i = 0; i < SU_METADATA_CHILDREN; ++i) {
        SU_METADATA_CHILD *child = &Group->Children[i];
        PSECURITY_DESCRIPTOR security = NULL;
        BOOLEAN deferred, retire = FALSE;
        KeAcquireSpinLock(&MetadataLock, &irql);
        deferred = child->Io.InUse && child->Io.Deferred;
        if (deferred) child->Io.Deferred = FALSE;
        KeReleaseSpinLock(&MetadataLock, irql);
        if (deferred) MetadataReleaseIo(&child->Io);
        KeAcquireSpinLock(&MetadataLock, &irql);
        if (child->State != 0 && child->Closed && child->Pins == 0 && child->TargetPins == 0 &&
            !child->Io.InUse && !child->Cleanup.InUse && !child->Retiring) {
            child->Retiring = TRUE;
            security = child->Security;
            child->Security = NULL;
            retire = TRUE;
        }
        KeReleaseSpinLock(&MetadataLock, irql);
        if (security != NULL) ExFreePoolWithTag(security, SU_METADATA_TAG);
        if (retire) {
            KeAcquireSpinLock(&MetadataLock, &irql);
            MetadataRemoveChildLocked(Group, i);
            KeReleaseSpinLock(&MetadataLock, irql);
            KeSetEvent(&MetadataWork, IO_NO_INCREMENT, FALSE);
        }
    }
    KeAcquireSpinLock(&MetadataLock, &irql);
    {
        BOOLEAN held = Group->AccountingHeld && !Group->Revoked;
        KeReleaseSpinLock(&MetadataLock, irql);
        if (held) SafeUploadMetadataRevoke(Group->MainCookie);
    }
}

_IRQL_requires_(PASSIVE_LEVEL)
static __declspec(noinline) NTSTATUS MetadataCreateShape(_In_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS Objects,
    _In_ const SU_METADATA_CHILD *Child, _Inout_opt_ SU_METADATA_DIAGNOSTIC *Diagnostic)
{
    ULONG options = Data->Iopb->Parameters.Create.Options & 0xffffffUL;
    ULONG required = FILE_NO_INTERMEDIATE_BUFFERING | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT;
    ULONG allowed = required | FILE_WRITE_THROUGH | FILE_NON_DIRECTORY_FILE | FILE_COMPLETE_IF_OPLOCKED;
    ACCESS_MASK access;
    if (!FLT_IS_IRP_OPERATION(Data) || Data->Iopb->MinorFunction != 0 || Objects->Transaction != NULL ||
        Data->Iopb->OperationFlags != 0 || Data->Iopb->Parameters.Create.SecurityContext == NULL ||
        Data->Iopb->Parameters.Create.EaLength != 0 || Data->Iopb->Parameters.Create.AllocationSize.QuadPart != 0 ||
        (Data->Iopb->Parameters.Create.Options >> 24) != Child->Request.CreateDisposition ||
        (options & required) != required || (options & ~allowed) != 0) return METADATA_STATUS(STATUS_ACCESS_DENIED);
    access = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    if (access != Child->Request.AccessMask ||
        ((access & FILE_WRITE_DATA) != 0 && (options & FILE_WRITE_THROUGH) == 0)) return METADATA_STATUS(STATUS_ACCESS_DENIED);
    if ((Data->Iopb->Parameters.Create.ShareAccess & ~(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)) != 0 ||
        (Child->Request.CreateDisposition == FILE_OPEN && Data->Iopb->Parameters.Create.ShareAccess !=
            (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE))) return METADATA_STATUS(STATUS_SHARING_VIOLATION);
    return STATUS_SUCCESS;
}

/* Retain a native handle as well as the record/FILE_OBJECT pin across rename
 * or F3. A reference alone does not prevent the last handle's CLEANUP. */
_IRQL_requires_(PASSIVE_LEVEL)
static __declspec(noinline) NTSTATUS MetadataHoldTarget(_In_ SU_METADATA_GROUP *Group, _In_ ULONG Index,
    _Inout_ SU_METADATA_COMPLETION *Context, _In_ BOOLEAN Unlinked)
{
    SU_METADATA_DIAGNOSTIC *Diagnostic = &Context->Diagnostic;
    SU_METADATA_CHILD *child = &Group->Children[Index], *target;
    NTSTATUS status;
    KIRQL irql;
    ULONG savedNode = Diagnostic == NULL ? SU_METADATA_CHILD_NODE : Diagnostic->Node;
    MetadataDiagnosticNode(Diagnostic, SU_METADATA_TARGET_NODE);
    if (child->ReplacementIndex == 0) return METADATA_STATUS(STATUS_FILE_INVALID);
    KeAcquireSpinLock(&MetadataLock, &irql);
    target = &Group->Children[child->ReplacementIndex - 1];
    if (Group->Revoked || target->Id != child->ReplacementId || target->State != SuMetadataActive ||
        target->Cleaned || target->Key == NULL || target->Unlinked != Unlinked ||
        target->ShareAccess != (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)) status = METADATA_STATUS(STATUS_ACCESS_DENIED);
    else if (target->Io.InUse || target->Pins != 0 || !FlagOn(target->Key->Flags, FO_HANDLE_CREATED))
        status = METADATA_STATUS(STATUS_DEVICE_BUSY);
    else {
        ++target->Pins;
        Context->TargetIndex = child->ReplacementIndex;
        Context->TargetId = target->Id;
        Context->TargetReference = target->Key;
        /* Nonblocking reference under M prevents a CLOSE/address-reuse race.
         * All dereferences/handle work occur after releasing M. */
        ObReferenceObject(Context->TargetReference);
        status = STATUS_SUCCESS;
    }
    KeReleaseSpinLock(&MetadataLock, irql);
    if (status != STATUS_SUCCESS) return METADATA_STATUS(status);
    /* A zero-access handle adds lifetime only, never caller authority. */
    status = ObOpenObjectByPointer(Context->TargetReference, OBJ_KERNEL_HANDLE, NULL, 0,
        *IoFileObjectType, KernelMode, &Context->TargetHandle);
    if (status != STATUS_SUCCESS) return METADATA_STATUS(status);
    KeAcquireSpinLock(&MetadataLock, &irql);
    if (Group->Revoked || target->Cleaned || target->Key != Context->TargetReference || target->Id != Context->TargetId)
        status = METADATA_STATUS(STATUS_ACCESS_DENIED);
    KeReleaseSpinLock(&MetadataLock, irql);
    MetadataDiagnosticNode(Diagnostic, savedNode);
    return METADATA_STATUS(status);
}

_IRQL_requires_(PASSIVE_LEVEL)
static __declspec(noinline) NTSTATUS MetadataRenamePre(_In_ SU_METADATA_GROUP *Group, _In_ ULONG Index,
    _Inout_ SU_METADATA_COMPLETION *Context, _In_ PFLT_CALLBACK_DATA Data)
{
    SU_METADATA_DIAGNOSTIC *Diagnostic = &Context->Diagnostic;
    SU_METADATA_CHILD *child = &Group->Children[Index], *target;
    PFILE_RENAME_INFORMATION rename = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    PFILE_OBJECT parent = NULL;
    SU_METADATA_MEASUREMENT measurement;
    SAFEUPLOAD_STAGE_IDENTITY_V19 parentId;
    ULONG bytes = Data->Iopb->Parameters.SetFileInformation.Length;
    ULONG header = (ULONG)FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName);
    HANDLE rootHandle;
    NTSTATUS status;
    KIRQL irql;
    if (rename == NULL || bytes < header || bytes > header + 510 || child->ReplacementIndex == 0 ||
        child->Renamed || !child->F2 || MetadataCurrentRole(child->Request.Role) == 0) return METADATA_STATUS(STATUS_ACCESS_DENIED);
    if (rename->Flags != (FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS) ||
        rename->RootDirectory == NULL || rename->FileNameLength == 0 || rename->FileNameLength != bytes - header)
        return METADATA_STATUS(STATUS_ACCESS_DENIED);
    Context->RenameBytes = rename->FileNameLength;
    RtlCopyMemory(Context->RenameLeaf, rename->FileName, Context->RenameBytes);
    rootHandle = rename->RootDirectory;
    Context->NativeValidation = TRUE;
    status = ObReferenceObjectByHandle(rootHandle, 0, *IoFileObjectType, UserMode, (PVOID *)&parent, NULL);
    if (status != STATUS_SUCCESS) return METADATA_STATUS(status);
    if (Data->Iopb->Parameters.SetFileInformation.ParentOfTarget != NULL) {
        status = MetadataQueryDirectory(Group->Instance, Data->Iopb->Parameters.SetFileInformation.ParentOfTarget, &parentId, Diagnostic);
        if (status != STATUS_SUCCESS || !RtlEqualMemory(&parentId,
            &Group->Nodes[MetadataRoleNodes[Context->RootIndex]].Identity, sizeof(parentId))) {
            ObDereferenceObject(parent);
            return METADATA_STATUS(STATUS_FILE_INVALID);
        }
    }
    KeAcquireSpinLock(&MetadataLock, &irql);
    target = &Group->Children[child->ReplacementIndex - 1];
    if (Group->Revoked || parent != Group->Roots[Context->RootIndex].Key || target->Id != child->ReplacementId ||
        Context->RenameBytes != target->LiveLeafBytes ||
        !RtlEqualMemory(Context->RenameLeaf, target->Request.Leaf, target->LiveLeafBytes)) status = METADATA_STATUS(STATUS_ACCESS_DENIED);
    else status = STATUS_SUCCESS;
    KeReleaseSpinLock(&MetadataLock, irql);
    ObDereferenceObject(parent);
    if (status != STATUS_SUCCESS) return METADATA_STATUS(status);
    status = MetadataHoldTarget(Group, Index, Context, FALSE);
    if (status != STATUS_SUCCESS) return METADATA_STATUS(status);
    MetadataDiagnosticNode(Diagnostic, SU_METADATA_TARGET_NODE);
    status = MetadataCheckName(Group, Context->TargetIndex - 1, Context->TargetReference, Diagnostic);
    if (status != STATUS_SUCCESS) return METADATA_STATUS(status);
    status = MetadataInspectChild(Group, Context->TargetIndex - 1, Context->TargetReference, FALSE, &measurement, Diagnostic);
    KeAcquireSpinLock(&MetadataLock, &irql);
    if (measurement.Observed) {
        NTSTATUS account = MetadataAccountLocked(Group, target, &measurement, Diagnostic);
        if (status == STATUS_SUCCESS) status = account;
    } else {
        target->Uncertain = TRUE;
        if (Group->UnknownOutcomes < (UINT64)MAXLONGLONG) ++Group->UnknownOutcomes;
    }
    if (Group->Revoked || target->Cleaned || target->Key != Context->TargetReference ||
        target->Id != Context->TargetId) status = METADATA_STATUS(STATUS_ACCESS_DENIED);
    KeReleaseSpinLock(&MetadataLock, irql);
    MetadataDiagnosticNode(Diagnostic, SU_METADATA_CHILD_NODE);
    return METADATA_STATUS(status);
}

/* Captures all mutable pre-input before lower dispatch; completion never reads
 * SET_INFORMATION input or user buffers. Exactly one ordinary I/O per child. */
_IRQL_requires_(PASSIVE_LEVEL)
static __declspec(noinline) NTSTATUS MetadataOperationPre(_In_ SU_METADATA_GROUP *Group, _In_ ULONG Index,
    _Inout_ SU_METADATA_COMPLETION *Context, _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects)
{
    SU_METADATA_DIAGNOSTIC *Diagnostic = &Context->Diagnostic;
    SU_METADATA_CHILD *child = &Group->Children[Index];
    ULONG major = Data->Iopb->MajorFunction, length;
    PVOID buffer;
    LARGE_INTEGER offset;
    UINT64 end;
    NTSTATUS status;
    BOOLEAN mutation = FALSE;
    if (!FLT_IS_IRP_OPERATION(Data) || Data->Iopb->MinorFunction != 0 || Objects->Transaction != NULL ||
        FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO)) return METADATA_STATUS(STATUS_ACCESS_DENIED);
    switch (major) {
    case IRP_MJ_READ: case IRP_MJ_WRITE:
        if (!FlagOn(Data->Iopb->IrpFlags, IRP_NOCACHE)) return METADATA_STATUS(STATUS_ACCESS_DENIED);
        if (major == IRP_MJ_WRITE) {
            if ((child->Request.AccessMask & FILE_WRITE_DATA) == 0 || child->Renamed || child->Frozen || child->Deleted)
                return METADATA_STATUS(STATUS_ACCESS_DENIED);
            length = Data->Iopb->Parameters.Write.Length; offset = Data->Iopb->Parameters.Write.ByteOffset;
            buffer = Data->Iopb->Parameters.Write.WriteBuffer;
            if (Data->Iopb->Parameters.Write.MdlAddress != NULL) return METADATA_STATUS(STATUS_NOT_SUPPORTED);
            mutation = TRUE;
        } else {
            if ((child->Request.AccessMask & FILE_READ_DATA) == 0) return METADATA_STATUS(STATUS_ACCESS_DENIED);
            length = Data->Iopb->Parameters.Read.Length; offset = Data->Iopb->Parameters.Read.ByteOffset;
            buffer = Data->Iopb->Parameters.Read.ReadBuffer;
            if (Data->Iopb->Parameters.Read.MdlAddress != NULL) return METADATA_STATUS(STATUS_NOT_SUPPORTED);
        }
        if (offset.QuadPart < 0 || (UINT64)offset.QuadPart > child->PaddedExtent ||
            length > child->PaddedExtent - (UINT64)offset.QuadPart ||
            (((UINT64)offset.QuadPart | length | (UINT64)(ULONG_PTR)buffer) & (Group->IoAlignment - 1)) != 0 ||
            (length != 0 && buffer == NULL)) return METADATA_STATUS(STATUS_INVALID_PARAMETER);
        end = (UINT64)offset.QuadPart + length;
        if (mutation && end > child->Preallocated) return METADATA_STATUS(STATUS_DEVICE_NOT_READY);
        Context->Length = length;
        Context->Value = end;
        break;
    case IRP_MJ_QUERY_INFORMATION:
        Context->InformationClass = Data->Iopb->Parameters.QueryFileInformation.FileInformationClass;
        length = Data->Iopb->Parameters.QueryFileInformation.Length;
        switch (Context->InformationClass) {
        case FileIdInformation: Context->Length = sizeof(FILE_ID_INFORMATION); break;
        case FileStandardInformation: Context->Length = sizeof(FILE_STANDARD_INFORMATION); break;
        case FileAttributeTagInformation: Context->Length = sizeof(FILE_ATTRIBUTE_TAG_INFORMATION); break;
        default: return METADATA_STATUS(STATUS_NOT_SUPPORTED);
        }
        if (length < Context->Length || length > SU_METADATA_SD_BYTES) return METADATA_STATUS(STATUS_INVALID_BUFFER_SIZE);
        break;
    case IRP_MJ_QUERY_SECURITY:
        if ((child->Request.AccessMask & READ_CONTROL) == 0 ||
            Data->Iopb->Parameters.QuerySecurity.SecurityInformation == 0 ||
            (Data->Iopb->Parameters.QuerySecurity.SecurityInformation &
                ~(OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)) != 0 ||
            Data->Iopb->Parameters.QuerySecurity.Length > SU_METADATA_SD_BYTES) return METADATA_STATUS(STATUS_ACCESS_DENIED);
        Context->Length = Data->Iopb->Parameters.QuerySecurity.Length;
        break;
    case IRP_MJ_FLUSH_BUFFERS:
        if ((child->Request.AccessMask & FILE_WRITE_DATA) == 0 || child->Deleted ||
            ((child->Renamed || child->Frozen) && !child->NeedF3)) return METADATA_STATUS(STATUS_ACCESS_DENIED);
        mutation = TRUE;
        if (child->NeedF3) {
            Context->NativeValidation = TRUE;
            if (child->ReplacementIndex == 0) return METADATA_STATUS(STATUS_FILE_INVALID);
            status = MetadataHoldTarget(Group, Index, Context, TRUE);
            if (status != STATUS_SUCCESS) return METADATA_STATUS(status);
        }
        break;
    case IRP_MJ_SET_INFORMATION:
        Context->InformationClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
        buffer = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        length = Data->Iopb->Parameters.SetFileInformation.Length;
        if (buffer == NULL || child->Deleted) return METADATA_STATUS(STATUS_ACCESS_DENIED);
        switch (Context->InformationClass) {
        case FileEndOfFileInformation: case FileAllocationInformation:
            if ((child->Request.AccessMask & FILE_WRITE_DATA) == 0 || child->Renamed || child->Frozen ||
                length != sizeof(FILE_END_OF_FILE_INFORMATION)) return METADATA_STATUS(STATUS_ACCESS_DENIED);
            RtlCopyMemory(&offset, buffer, sizeof(offset)); /* both native classes carry one LARGE_INTEGER */
            if (offset.QuadPart < 0 || (UINT64)offset.QuadPart > child->PaddedExtent) return METADATA_STATUS(STATUS_INVALID_PARAMETER);
            Context->Value = (UINT64)offset.QuadPart;
            if (Context->InformationClass == FileEndOfFileInformation) {
                if (!child->F1 || Context->Value > child->Preallocated || Context->Value > child->Request.MaximumLogicalBytes ||
                    (child->Request.Role == SuSegment && (Context->Value < child->EndOfFile ||
                     (Context->Value & (Group->IoAlignment - 1)) != 0))) return METADATA_STATUS(STATUS_ACCESS_DENIED);
            } else {
                if (Context->Value < child->EndOfFile || (Context->Value & (Group->IoAlignment - 1)) != 0 ||
                    (child->Request.Role == SuSegment && (Context->Value < child->Preallocated ||
                    ((Context->Value + Group->AllocationUnit - 1) & ~((UINT64)Group->AllocationUnit - 1)) < child->Allocation)))
                    return METADATA_STATUS(STATUS_ACCESS_DENIED);
            }
            break;
        case FileRenameInformationEx:
            if ((child->Request.AccessMask & DELETE) == 0) return METADATA_STATUS(STATUS_ACCESS_DENIED);
            status = MetadataRenamePre(Group, Index, Context, Data);
            if (status != STATUS_SUCCESS) return METADATA_STATUS(status);
            break;
        case FileDispositionInformation:
            if ((child->Request.AccessMask & DELETE) == 0 || (child->Renamed ? MetadataCurrentRole(child->Request.Role) : child->Request.Role) == SuMarkerCurrent ||
                child->Request.Role == SuLegacySecurity || child->Request.Role == SuLegacyNegative ||
                child->Request.Role == SuSegment || child->TargetPins != 0 || child->Unlinked || length != sizeof(FILE_DISPOSITION_INFORMATION) ||
                !((PFILE_DISPOSITION_INFORMATION)buffer)->DeleteFile) return METADATA_STATUS(STATUS_ACCESS_DENIED);
            break;
        default: return METADATA_STATUS(STATUS_NOT_SUPPORTED);
        }
        mutation = TRUE;
        break;
    default: return METADATA_STATUS(STATUS_NOT_SUPPORTED);
    }
    if (mutation) { Context->NativeValidation = TRUE; return METADATA_STATUS(MetadataCheckAnchors(Group, Diagnostic)); }
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
static __declspec(noinline) NTSTATUS MetadataRootIoPre(_Inout_ SU_METADATA_COMPLETION *Context, _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects)
{
    SU_METADATA_DIAGNOSTIC *Diagnostic = &Context->Diagnostic;
    ULONG length;
    if (!FLT_IS_IRP_OPERATION(Data) || Objects->Transaction != NULL ||
        (Data->Iopb->MajorFunction != IRP_MJ_DIRECTORY_CONTROL && Data->Iopb->MinorFunction != 0) ||
        FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO)) return METADATA_STATUS(STATUS_ACCESS_DENIED);
    switch (Data->Iopb->MajorFunction) {
    case IRP_MJ_QUERY_VOLUME_INFORMATION:
        Context->InformationClass = Data->Iopb->Parameters.QueryVolumeInformation.FsInformationClass;
        length = Data->Iopb->Parameters.QueryVolumeInformation.Length;
        switch (Context->InformationClass) {
        case FileFsSizeInformation: Context->Length = sizeof(FILE_FS_SIZE_INFORMATION); break;
        case FileFsFullSizeInformation: Context->Length = sizeof(FILE_FS_FULL_SIZE_INFORMATION); break;
        case FileFsSectorSizeInformation: Context->Length = sizeof(FILE_FS_SECTOR_SIZE_INFORMATION); break;
        default: return METADATA_STATUS(STATUS_NOT_SUPPORTED);
        }
        return METADATA_STATUS(length >= Context->Length && length <= SU_METADATA_SD_BYTES ? STATUS_SUCCESS : STATUS_INVALID_BUFFER_SIZE);
    case IRP_MJ_QUERY_INFORMATION:
        Context->InformationClass = Data->Iopb->Parameters.QueryFileInformation.FileInformationClass;
        length = Data->Iopb->Parameters.QueryFileInformation.Length;
        switch (Context->InformationClass) {
        case FileIdInformation: Context->Length = sizeof(FILE_ID_INFORMATION); break;
        case FileStandardInformation: Context->Length = sizeof(FILE_STANDARD_INFORMATION); break;
        case FileAttributeTagInformation: Context->Length = sizeof(FILE_ATTRIBUTE_TAG_INFORMATION); break;
        default: return METADATA_STATUS(STATUS_NOT_SUPPORTED);
        }
        return METADATA_STATUS(length >= Context->Length && length <= SU_METADATA_SD_BYTES ? STATUS_SUCCESS : STATUS_INVALID_BUFFER_SIZE);
    case IRP_MJ_QUERY_SECURITY:
        Context->Length = Data->Iopb->Parameters.QuerySecurity.Length;
        return METADATA_STATUS(Context->Length <= SU_METADATA_SD_BYTES && Data->Iopb->Parameters.QuerySecurity.SecurityInformation != 0 &&
            (Data->Iopb->Parameters.QuerySecurity.SecurityInformation &
             ~(OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)) == 0 ?
             STATUS_SUCCESS : STATUS_ACCESS_DENIED);
    case IRP_MJ_DIRECTORY_CONTROL:
        if (Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY) return METADATA_STATUS(STATUS_NOT_SUPPORTED);
        Context->Length = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.Length;
        Context->InformationClass = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass;
        if (Context->InformationClass != FileDirectoryInformation && Context->InformationClass != FileFullDirectoryInformation &&
            Context->InformationClass != FileIdBothDirectoryInformation && Context->InformationClass != FileIdFullDirectoryInformation &&
            Context->InformationClass != FileNamesInformation) return METADATA_STATUS(STATUS_NOT_SUPPORTED);
        return METADATA_STATUS(Context->Length != 0 && Context->Length <= SU_METADATA_SD_BYTES ? STATUS_SUCCESS : STATUS_INVALID_BUFFER_SIZE);
    default: return METADATA_STATUS(STATUS_NOT_SUPPORTED);
    }
}

_IRQL_requires_(PASSIVE_LEVEL)
static __declspec(noinline) NTSTATUS MetadataRootIoPost(_In_ SU_METADATA_COMPLETION *Context)
{
    SU_METADATA_DIAGNOSTIC *Diagnostic = &Context->Diagnostic;
    ULONG alignment, unit;
    NTSTATUS status;
    if (Context->NativeStatus != STATUS_SUCCESS) return STATUS_SUCCESS; /* native read-only failure is preserved */
    if (Context->NativeInformation > Context->Length ||
        ((Context->Operation == IRP_MJ_QUERY_INFORMATION || Context->Operation == IRP_MJ_QUERY_VOLUME_INFORMATION) &&
         Context->NativeInformation != Context->Length)) return METADATA_STATUS(STATUS_INFO_LENGTH_MISMATCH);
    if (Context->Operation != IRP_MJ_QUERY_VOLUME_INFORMATION) return STATUS_SUCCESS;
    status = MetadataCaptureAlignment(Context->Group->Instance, Context->Group->Volume, &alignment, &unit, Diagnostic);
    if (status != STATUS_SUCCESS) return METADATA_STATUS(status);
    return METADATA_STATUS(alignment == Context->Group->IoAlignment && unit == Context->Group->AllocationUnit ?
        STATUS_SUCCESS : STATUS_FILE_INVALID);
}

_IRQL_requires_(PASSIVE_LEVEL)
static __declspec(noinline) NTSTATUS MetadataCheckName(_In_ SU_METADATA_GROUP *Group, _In_ ULONG Index, _In_ PFILE_OBJECT Object, _Inout_opt_ SU_METADATA_DIAGNOSTIC *Diagnostic)
{
    static const PCWSTR roots[SU_METADATA_ROOTS] = {
        L"\\ProgramData\\SafeUpload\\staging", L"\\ProgramData\\SafeUpload\\staging\\.space-reservations",
        L"\\ProgramData\\SafeUpload\\staging-journal", L"\\ProgramData\\SafeUpload\\staging-journal\\completed"
    };
    PFILE_NAME_INFORMATION name;
    UNICODE_STRING prefix, actual, leaf, expected;
    ULONG bytes = 0, i, root = SU_METADATA_ROOTS;
    const ULONG capacity = (ULONG)FIELD_OFFSET(FILE_NAME_INFORMATION, FileName) + 1024UL;
    NTSTATUS status;
    for (i = 0; i < SU_METADATA_ROOTS; ++i)
        if (Group->Roots[i].Id == Group->Children[Index].Request.RootId) { root = i; break; }
    if (root == SU_METADATA_ROOTS) return METADATA_STATUS(STATUS_FILE_INVALID);
    name = ExAllocatePool2(POOL_FLAG_PAGED, capacity, SU_METADATA_TAG);
    if (name == NULL) return METADATA_STATUS(STATUS_INSUFFICIENT_RESOURCES);
    status = FltQueryInformationFile(Group->Instance, Object, name, capacity, FileNameInformation, &bytes);
    if (status == STATUS_SUCCESS) {
        if (bytes < (ULONG)FIELD_OFFSET(FILE_NAME_INFORMATION, FileName) || name->FileNameLength > 1024 ||
            (name->FileNameLength & 1) != 0 || name->FileNameLength > bytes - (ULONG)FIELD_OFFSET(FILE_NAME_INFORMATION, FileName))
            status = METADATA_STATUS(STATUS_INFO_LENGTH_MISMATCH);
        else {
            RtlInitUnicodeString(&prefix, roots[root]);
            actual.Buffer = name->FileName;
            actual.Length = actual.MaximumLength = prefix.Length;
            if (name->FileNameLength != (ULONG)prefix.Length + sizeof(WCHAR) + Group->Children[Index].LiveLeafBytes ||
                !RtlEqualUnicodeString(&prefix, &actual, TRUE) ||
                name->FileName[prefix.Length / sizeof(WCHAR)] != L'\\') status = METADATA_STATUS(STATUS_FILE_INVALID);
            else {
                leaf.Buffer = name->FileName + prefix.Length / sizeof(WCHAR) + 1;
                leaf.Length = leaf.MaximumLength = (USHORT)Group->Children[Index].LiveLeafBytes;
                expected.Buffer = Group->Children[Index].FoldedLeaf;
                expected.Length = expected.MaximumLength = leaf.Length;
                if (!RtlEqualUnicodeString(&leaf, &expected, TRUE)) status = METADATA_STATUS(STATUS_FILE_INVALID);
            }
            for (i = 0; i < name->FileNameLength / sizeof(WCHAR); ++i)
                if (name->FileName[i] == L':') { status = METADATA_STATUS(STATUS_ACCESS_DENIED); break; }
        }
    }
    ExFreePoolWithTag(name, SU_METADATA_TAG);
    return METADATA_STATUS(status);
}

/* Address membership precedes every dereference. Contexts remain resident and
 * unreusable through their native completion, including deferred PASSIVE release. */
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
        for (i = 0; i < SU_METADATA_ROOTS + SU_METADATA_CHILDREN; ++i) {
            SU_METADATA_COMPLETION *io = i < SU_METADATA_ROOTS ? &group->Roots[i].Io :
                &group->Children[i - SU_METADATA_ROOTS].Io;
            SU_METADATA_COMPLETION *cleanup = i < SU_METADATA_ROOTS ? &group->Roots[i].Cleanup :
                &group->Children[i - SU_METADATA_ROOTS].Cleanup;
            SU_METADATA_COMPLETION *c = (PVOID)((ULONG_PTR)io | 3) == Context ? io :
                (PVOID)((ULONG_PTR)cleanup | 3) == Context ? cleanup : NULL;
            if (c != NULL && c->InUse && !c->Deferred && c->Signature == SU_METADATA_CONTEXT_SIGNATURE &&
                c->Group == group && c->RootIndex < SU_METADATA_ROOTS && c->Object != NULL &&
                ((i < SU_METADATA_ROOTS && c->ChildIndex == SU_METADATA_CHILDREN &&
                  c->RootIndex == i && c->Incarnation == group->Roots[i].Id) ||
                 (i >= SU_METADATA_ROOTS && c->ChildIndex == i - SU_METADATA_ROOTS &&
                  c->Incarnation == group->Children[i - SU_METADATA_ROOTS].Id))) { found = TRUE; break; }
        }
    }
    KeReleaseSpinLock(&MetadataLock, irql);
    return found;
}

_IRQL_requires_max_(APC_LEVEL)
static FLT_PREOP_CALLBACK_STATUS MetadataRefuse(_Inout_ PFLT_CALLBACK_DATA Data, _In_ NTSTATUS Status)
{
    Data->IoStatus.Status = Status;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

_IRQL_requires_max_(APC_LEVEL)
static FLT_PREOP_CALLBACK_STATUS MetadataDiagnosticPreReturn(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ NTSTATUS Status, _Inout_ SU_METADATA_DIAGNOSTIC *Diagnostic, _In_ ULONG Line)
{
    (VOID)MetadataDiagnosticStatus(Diagnostic, Status, Line);
    /* No new deferral/admission owner for a context-free high-IRQL refusal. */
    if (KeGetCurrentIrql() == PASSIVE_LEVEL) MetadataDiagnosticPrint(Data->Iopb->MajorFunction == IRP_MJ_CREATE ? "ChildCreate" : "MetadataPre", Diagnostic);
    return MetadataRefuse(Data, Status);
}


/* FsFilter lifecycle callbacks are not ordinary service I/O. Lower NTFS owns
 * its synchronization: neither subject/IRQL admission nor a metadata context
 * may obstruct release, modified-writer/CC work or SyncTypeOther. Only new
 * section creation is failed, using the section callback's supported status.
 * QUERY_OPEN requests an IRP fallback; it never fabricates an open result. */
_IRQL_requires_max_(APC_LEVEL)
static BOOLEAN MetadataFsFilterPre(_Inout_ PFLT_CALLBACK_DATA Data, _Out_ FLT_PREOP_CALLBACK_STATUS *Result)
{
    *Result = FLT_PREOP_SUCCESS_NO_CALLBACK;
    switch (Data->Iopb->MajorFunction) {
    case IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION:
        if (Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType == SyncTypeCreateSection)
            *Result = MetadataRefuse(Data, STATUS_INSUFFICIENT_RESOURCES);
        return TRUE;
    case IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION:
    case IRP_MJ_ACQUIRE_FOR_MOD_WRITE: case IRP_MJ_RELEASE_FOR_MOD_WRITE:
    case IRP_MJ_ACQUIRE_FOR_CC_FLUSH: case IRP_MJ_RELEASE_FOR_CC_FLUSH:
        return TRUE;
    case IRP_MJ_QUERY_OPEN:
        *Result = FLT_PREOP_DISALLOW_FSFILTER_IO;
        return TRUE;
    default:
        return FALSE;
    }
}

_Use_decl_annotations_
FLT_PREOP_CALLBACK_STATUS SafeUploadMetadataPre(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS Objects,
    PVOID *Context, SU_METADATA_DISPATCH *Dispatch)
{
    SU_METADATA_DIAGNOSTIC refusal;
    SU_METADATA_DIAGNOSTIC *Diagnostic = &refusal;
    SU_METADATA_GROUP *group;
    SU_METADATA_COMPLETION *completion = NULL;
    SU_METADATA_CHILD *entry;
    SU_METADATA_MEASUREMENT measured;
    ULONG i, root = SU_METADATA_ROOTS, child = SU_METADATA_CHILDREN;
    PFILE_OBJECT object, related;
    UCHAR major = Data->Iopb->MajorFunction;
    WCHAR folded[256];
    USHORT bytes = 0;
    BOOLEAN live, subject = FALSE, fault = FALSE, capturing = FALSE;
    FLT_PREOP_CALLBACK_STATUS callbackResult;
    NTSTATUS status = STATUS_ACCESS_DENIED;
    KIRQL irql;
    MetadataDiagnosticReset(Diagnostic, SU_METADATA_UNKNOWN_NODE, 0);
    RtlZeroMemory(Dispatch, sizeof(*Dispatch));
    *Context = NULL;
    if (InterlockedCompareExchange(&MetadataInitialized, 0, 0) == 0 || Objects->FileObject == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    object = Objects->FileObject;
    related = major == IRP_MJ_CREATE ? object->RelatedFileObject : NULL;
    KeAcquireSpinLock(&MetadataLock, &irql);
    group = MetadataRoutingGroup;
    if (group != NULL) {
        if (major != IRP_MJ_CREATE) {
            for (i = 0; i < SU_METADATA_CHILDREN; ++i)
                if (group->Children[i].Key == object && group->Children[i].State != 0) { child = i; break; }
        }
        for (i = 0; i < SU_METADATA_ROOTS; ++i)
            if (group->Roots[i].Key != NULL && group->Roots[i].Key == (major == IRP_MJ_CREATE ? related : object))
                { root = i; break; }
        if (child != SU_METADATA_CHILDREN) {
            for (i = 0; i < SU_METADATA_ROOTS; ++i)
                if (group->Roots[i].Id == group->Children[child].Request.RootId) { root = i; break; }
        }
        capturing = root == SU_METADATA_ROOTS && major != IRP_MJ_CREATE &&
            group->RootBusy && group->CaptureKey == object;
    }
    if (group == NULL || (root == SU_METADATA_ROOTS && !capturing) || !ExAcquireRundownProtection(&group->Rundown)) {
        KeReleaseSpinLock(&MetadataLock, irql);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    Dispatch->Handled = TRUE; Dispatch->Cookie = (UINT64)(ULONG_PTR)group->MainCookie;
    Dispatch->RootId = capturing ? 0 : group->Roots[root].Id;
    if (child != SU_METADATA_CHILDREN) {
        Dispatch->ChildId = group->Children[child].Id;
        Dispatch->Role = group->Children[child].Request.Role;
    }
    Diagnostic->Node = child == SU_METADATA_CHILDREN ? (capturing ? SU_METADATA_UNKNOWN_NODE : MetadataRoleNodes[root]) : SU_METADATA_CHILD_NODE;
    Diagnostic->Role = child == SU_METADATA_CHILDREN ? (capturing ? 0 : root + 1) : group->Children[child].Request.Role;
    live = !capturing && !group->Revoked && Objects->Instance == group->Instance &&
        (child != SU_METADATA_CHILDREN || !group->Roots[root].Cleaned);
    if (major == IRP_MJ_CLOSE) {
        if (group->CaptureKey == object) { group->CaptureKey = NULL; group->CaptureCleaned = TRUE; }
        if (!capturing) {
            if (child == SU_METADATA_CHILDREN) group->Roots[root].Key = NULL;
            else { group->Children[child].Key = NULL; group->Children[child].Closed = TRUE; }
        }
        KeReleaseSpinLock(&MetadataLock, irql);
        ExReleaseRundownProtection(&group->Rundown);
        KeSetEvent(&MetadataWork, IO_NO_INCREMENT, FALSE);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (major == IRP_MJ_CLEANUP) {
        if (group->CaptureKey == object) group->CaptureCleaned = TRUE;
        if (capturing) {
            KeReleaseSpinLock(&MetadataLock, irql);
            ExReleaseRundownProtection(&group->Rundown);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        if (child == SU_METADATA_CHILDREN) {
            group->Roots[root].Cleaned = TRUE;
            for (i = 0; i < SU_METADATA_CHILDREN; ++i)
                if (group->Children[i].State == SuMetadataPendingOpen &&
                    group->Children[i].Request.RootId == group->Roots[root].Id) MetadataRemoveChildLocked(group, i);
            completion = &group->Roots[root].Cleanup;
        } else { group->Children[child].Cleaned = TRUE; completion = &group->Children[child].Cleanup; }
        if (!completion->InUse) {
            MetadataStartContextLocked(group, completion, root, child, object, major);
            Diagnostic = &completion->Diagnostic;
            *Context = (PVOID)((ULONG_PTR)completion | 3);
            KeReleaseSpinLock(&MetadataLock, irql);
            return FLT_PREOP_SUCCESS_WITH_CALLBACK;
        }
        KeReleaseSpinLock(&MetadataLock, irql);
        ExReleaseRundownProtection(&group->Rundown);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    KeReleaseSpinLock(&MetadataLock, irql);
    if (MetadataFsFilterPre(Data, &callbackResult)) {
        ExReleaseRundownProtection(&group->Rundown);
        return callbackResult;
    }
    if (FLT_IS_FASTIO_OPERATION(Data)) {
        ExReleaseRundownProtection(&group->Rundown);
        return FLT_PREOP_DISALLOW_FASTIO;
    }
    if (capturing) {
        ExReleaseRundownProtection(&group->Rundown);
        return MetadataDiagnosticPreReturn(Data, STATUS_DEVICE_NOT_READY, Diagnostic, __LINE__);
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || !live) {
        ExReleaseRundownProtection(&group->Rundown);
        return MetadataDiagnosticPreReturn(Data, STATUS_DEVICE_NOT_READY, Diagnostic, __LINE__);
    }
    subject = PsGetCurrentProcess() == group->Process && FltGetRequestorProcess(Data) == group->Process &&
        MetadataAuthenticate(group);
    if (!subject) {
        ExReleaseRundownProtection(&group->Rundown);
        return MetadataDiagnosticPreReturn(Data, STATUS_ACCESS_DENIED, Diagnostic, __LINE__);
    }
    if (major == IRP_MJ_CREATE && object->FileName.Buffer != NULL && object->FileName.Length != 0 &&
        object->FileName.Length <= 510 && (object->FileName.Length & 1) == 0) {
        bytes = object->FileName.Length;
        status = MetadataFoldLeaf(object->FileName.Buffer, bytes, folded, Diagnostic);
    }
    KeAcquireSpinLock(&MetadataLock, &irql);
    if (group->Revoked || (group->Roots[root].Cleaned && child == SU_METADATA_CHILDREN)) status = METADATA_STATUS(STATUS_DEVICE_NOT_READY);
    else if (major == IRP_MJ_CREATE) {
        if (status == STATUS_SUCCESS) {
            for (i = 0; i < SU_METADATA_CHILDREN; ++i)
                if (group->Children[i].State == SuMetadataPendingOpen && group->Children[i].Request.RootId == Dispatch->RootId &&
                    group->Children[i].Request.LeafBytes == bytes && RtlEqualMemory(group->Children[i].FoldedLeaf, folded, bytes))
                    { child = i; break; }
        }
        if (child == SU_METADATA_CHILDREN) status = METADATA_STATUS(STATUS_ACCESS_DENIED);
        else {
            entry = &group->Children[child];
            entry->State = SuMetadataOpening; entry->Key = object;
            group->Transactions[child / SU_METADATA_CHILDREN_PER_TRANSACTION].Pending = FALSE;
            completion = &entry->Io;
            MetadataStartContextLocked(group, completion, root, child, object, major);
            Diagnostic = &completion->Diagnostic;
            Dispatch->ChildId = entry->Id; Dispatch->Role = entry->Request.Role;
            RtlZeroMemory(&measured, sizeof(measured));
            status = MetadataAccountLocked(group, entry, &measured, Diagnostic); /* precharge before native CREATE */
        }
    } else if (child != SU_METADATA_CHILDREN) {
        entry = &group->Children[child];
        if (entry->State != SuMetadataActive || entry->Cleaned || entry->Uncertain) status = METADATA_STATUS(STATUS_DEVICE_NOT_READY);
        else if (entry->Io.InUse || entry->Pins != 0) status = METADATA_STATUS(STATUS_DEVICE_BUSY);
        else {
            completion = &entry->Io;
            MetadataStartContextLocked(group, completion, root, child, object, major);
            Diagnostic = &completion->Diagnostic;
            status = STATUS_SUCCESS;
        }
    } else if (group->Roots[root].Io.InUse) status = METADATA_STATUS(STATUS_DEVICE_BUSY);
    else {
        completion = &group->Roots[root].Io;
        MetadataStartContextLocked(group, completion, root, SU_METADATA_CHILDREN, object, major);
        Diagnostic = &completion->Diagnostic;
        status = STATUS_SUCCESS;
    }
    KeReleaseSpinLock(&MetadataLock, irql);
    if (completion == NULL) {
        ExReleaseRundownProtection(&group->Rundown);
        return MetadataDiagnosticPreReturn(Data, status, Diagnostic, __LINE__);
    }
    /* The reservation and callback-owned original object precede this extra
     * reference. Worker retirement cannot reuse the slot while it is pinned. */
    ObReferenceObject(object);
    completion->Reference = object;
    if (status == STATUS_SUCCESS && major == IRP_MJ_CREATE) {
        status = MetadataCreateShape(Data, Objects, &group->Children[child], Diagnostic);
        if (status == STATUS_SUCCESS) {
            status = MetadataCheckAnchors(group, Diagnostic);
            if (status != STATUS_SUCCESS) fault = TRUE;
        }
    } else if (status == STATUS_SUCCESS && child == SU_METADATA_CHILDREN) {
        status = MetadataRootIoPre(completion, Data, Objects);
    } else if (status == STATUS_SUCCESS) {
        status = MetadataInspectChild(group, child, object, FALSE, &measured, Diagnostic);
        KeAcquireSpinLock(&MetadataLock, &irql);
        if (measured.Observed) {
            NTSTATUS account = MetadataAccountLocked(group, &group->Children[child], &measured, Diagnostic);
            if (status == STATUS_SUCCESS) status = account;
        } else {
            group->Children[child].Uncertain = TRUE;
            if (group->UnknownOutcomes < (UINT64)MAXLONGLONG) ++group->UnknownOutcomes;
        }
        KeReleaseSpinLock(&MetadataLock, irql);
        if (status != STATUS_SUCCESS) fault = TRUE;
        if (status == STATUS_SUCCESS) {
            status = MetadataOperationPre(group, child, completion, Data, Objects);
            if (status != STATUS_SUCCESS && status != STATUS_DEVICE_BUSY && completion->NativeValidation) fault = TRUE;
        }
    }
    KeAcquireSpinLock(&MetadataLock, &irql);
    if (group->Revoked || (child != SU_METADATA_CHILDREN &&
        (group->Children[child].Cleaned || group->Children[child].Key != object))) status = METADATA_STATUS(STATUS_DEVICE_NOT_READY);
    if (status != STATUS_SUCCESS && major == IRP_MJ_CREATE) {
        group->Children[child].Key = NULL; group->Children[child].Closed = TRUE;
        group->Children[child].State = SuMetadataRevoked;
    }
    if (status == STATUS_SUCCESS && major == IRP_MJ_CREATE)
        group->Children[child].ShareAccess = Data->Iopb->Parameters.Create.ShareAccess;
    KeReleaseSpinLock(&MetadataLock, irql);
    if (status != STATUS_SUCCESS) {
        if (fault) SafeUploadMetadataRevoke(group->MainCookie);
        MetadataReleaseIo(completion);
        return MetadataRefuse(Data, status);
    }
    *Context = (PVOID)((ULONG_PTR)completion | 3);
    return major == IRP_MJ_CREATE ? FLT_PREOP_SUCCESS_WITH_CALLBACK : FLT_PREOP_SYNCHRONIZE;
}

_IRQL_requires_(PASSIVE_LEVEL)
static __declspec(noinline) NTSTATUS MetadataPostNative(_Inout_ SU_METADATA_COMPLETION *Context, _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects)
{
    SU_METADATA_DIAGNOSTIC *Diagnostic = &Context->Diagnostic;
    SU_METADATA_GROUP *group = Context->Group;
    SU_METADATA_CHILD *child = &group->Children[Context->ChildIndex];
    SU_METADATA_MEASUREMENT measured;
    NTSTATUS status;
    BOOLEAN opening = Context->Operation == IRP_MJ_CREATE;
    KIRQL irql;
    /* Preserve the first native failure unless this exact read/security
     * probe status is explicitly tolerated by the existing settlement. */
    if (Context->NativeStatus != STATUS_SUCCESS &&
        !(Context->Operation == IRP_MJ_READ && Context->NativeStatus == STATUS_END_OF_FILE) &&
        !(Context->Operation == IRP_MJ_QUERY_SECURITY && (Context->NativeStatus == STATUS_BUFFER_TOO_SMALL ||
          Context->NativeStatus == STATUS_BUFFER_OVERFLOW))) (VOID)METADATA_STATUS(Context->NativeStatus);
    if (Objects->Instance != group->Instance || Objects->FileObject != Context->Object) return METADATA_STATUS(STATUS_FILE_INVALID);
    if (opening && (Context->NativeStatus != STATUS_SUCCESS || Context->NativeInformation !=
        (child->Request.CreateDisposition == FILE_CREATE ? FILE_CREATED : FILE_OPENED))) return METADATA_STATUS(STATUS_FILE_INVALID);
    /* Native successful mutation is recorded BEFORE observations/bookkeeping.
     * No observation failure changes it into permission to repeat the call. */
    KeAcquireSpinLock(&MetadataLock, &irql);
    if (Context->NativeStatus == STATUS_SUCCESS && Context->Operation == IRP_MJ_SET_INFORMATION) {
        if (Context->InformationClass == FileRenameInformationEx) {
            SU_METADATA_CHILD *target = &group->Children[Context->TargetIndex - 1];
            child->Renamed = TRUE; child->NeedF3 = TRUE;
            child->LiveLeafBytes = target->LiveLeafBytes;
            RtlCopyMemory(child->FoldedLeaf, target->FoldedLeaf, target->LiveLeafBytes);
            group->Children[Context->TargetIndex - 1].Unlinked = TRUE;
        } else if (Context->InformationClass == FileDispositionInformation) child->Deleted = TRUE;
    }
    KeReleaseSpinLock(&MetadataLock, irql);
    status = MetadataInspectChild(group, Context->ChildIndex, Objects->FileObject, opening, &measured, Diagnostic);
    KeAcquireSpinLock(&MetadataLock, &irql);
    if (measured.Observed) {
        NTSTATUS account = MetadataAccountLocked(group, child, &measured, Diagnostic);
        if (status == STATUS_SUCCESS) status = account;
    } else {
        child->Uncertain = TRUE;
        if (group->UnknownOutcomes < (UINT64)MAXLONGLONG) ++group->UnknownOutcomes;
    }
    if (group->Revoked || child->Key != Context->Object || child->Cleaned) status = METADATA_STATUS(STATUS_DEVICE_NOT_READY);
    if (status == STATUS_SUCCESS && opening) {
        if (measured.Eof > child->Request.MaximumLogicalBytes) status = METADATA_STATUS(STATUS_FILE_INVALID);
        else {
            child->Identity = measured.Identity;
            child->Security = measured.Security; measured.Security = NULL;
            child->SecurityBytes = measured.SecurityBytes;
            child->State = SuMetadataActive;
        }
    } else if (status == STATUS_SUCCESS && Context->NativeStatus == STATUS_SUCCESS) {
        if ((Context->Operation == IRP_MJ_WRITE || Context->Operation == IRP_MJ_READ) &&
            Context->NativeInformation > Context->Length) status = METADATA_STATUS(STATUS_INFO_LENGTH_MISMATCH);
        if (Context->Operation == IRP_MJ_WRITE && Context->NativeInformation != Context->Length)
            status = METADATA_STATUS(STATUS_UNEXPECTED_IO_ERROR);
        if (Context->Operation == IRP_MJ_QUERY_INFORMATION && Context->NativeInformation != Context->Length)
            status = METADATA_STATUS(STATUS_INFO_LENGTH_MISMATCH);
        if (Context->Operation == IRP_MJ_QUERY_SECURITY && Context->NativeInformation > Context->Length)
            status = METADATA_STATUS(STATUS_INFO_LENGTH_MISMATCH);
        if (Context->Operation == IRP_MJ_WRITE) { child->F1 = FALSE; child->F2 = FALSE; child->EofSet = FALSE; }
        if (Context->Operation == IRP_MJ_FLUSH_BUFFERS) {
            if (child->EofSet && child->EndOfFile != child->LogicalEof) status = METADATA_STATUS(STATUS_FILE_INVALID);
            child->F1 = TRUE;
            if (child->EofSet) child->F2 = TRUE;
            if (child->NeedF3) child->NeedF3 = FALSE;
            if (child->Request.Role == SuHistoryCandidate && child->F2) child->Frozen = TRUE;
        }
        if (Context->Operation == IRP_MJ_SET_INFORMATION) {
            if (Context->InformationClass == FileAllocationInformation) {
                if (child->Allocation < Context->Value) status = METADATA_STATUS(STATUS_DISK_FULL);
                else child->Preallocated = Context->Value;
                child->F2 = FALSE;
            } else if (Context->InformationClass == FileEndOfFileInformation) {
                if (child->EndOfFile != Context->Value) status = METADATA_STATUS(STATUS_FILE_INVALID);
                child->LogicalEof = Context->Value;
                child->EofSet = TRUE; child->F2 = FALSE;
            }
        }
    }
    KeReleaseSpinLock(&MetadataLock, irql);
    if (measured.Security != NULL) ExFreePoolWithTag(measured.Security, SU_METADATA_TAG);
    if (Context->TargetIndex != 0) {
        NTSTATUS targetStatus;
        BOOLEAN replaced = Context->Operation == IRP_MJ_FLUSH_BUFFERS || Context->NativeStatus == STATUS_SUCCESS;
        if (Context->Operation == IRP_MJ_SET_INFORMATION && Context->NativeStatus == STATUS_SUCCESS) {
            NTSTATUS nameStatus = MetadataCheckName(group, Context->ChildIndex, Objects->FileObject, Diagnostic);
            if (status == STATUS_SUCCESS) status = nameStatus;
        }
        /* Even a failed rename may leave uncertain target custody. Observe
         * both exact objects before dropping the exclusion handle. F3 holds
         * the predecessor again and verifies the measured unlink separately. */
        MetadataDiagnosticNode(Diagnostic, SU_METADATA_TARGET_NODE);
        targetStatus = MetadataInspectChild(group, Context->TargetIndex - 1, Context->TargetReference, FALSE, &measured, Diagnostic);
        KeAcquireSpinLock(&MetadataLock, &irql);
        if (measured.Observed) {
            NTSTATUS account = MetadataAccountLocked(group, &group->Children[Context->TargetIndex - 1], &measured, Diagnostic);
            if (targetStatus == STATUS_SUCCESS) targetStatus = account;
        } else {
            group->Children[Context->TargetIndex - 1].Uncertain = TRUE;
            if (group->UnknownOutcomes < (UINT64)MAXLONGLONG) ++group->UnknownOutcomes;
        }
        if (replaced && (measured.Links != 0 || !measured.DeletePending)) targetStatus = METADATA_STATUS(STATUS_FILE_INVALID);
        if (group->Children[Context->TargetIndex - 1].Cleaned ||
            group->Children[Context->TargetIndex - 1].Key != Context->TargetReference) targetStatus = METADATA_STATUS(STATUS_FILE_INVALID);
        KeReleaseSpinLock(&MetadataLock, irql);
        if (status == STATUS_SUCCESS) status = targetStatus;
        MetadataDiagnosticNode(Diagnostic, SU_METADATA_CHILD_NODE);
        if (status == STATUS_SUCCESS) status = MetadataCheckAnchors(group, Diagnostic);
    }
    if (status == STATUS_SUCCESS && Context->NativeStatus == STATUS_SUCCESS &&
        Context->Operation == IRP_MJ_FLUSH_BUFFERS) status = MetadataCheckAnchors(group, Diagnostic);
    /* Native errors retain measured peaks, then hold; never retry a mutation. */
    if (Context->NativeStatus != STATUS_SUCCESS && status == STATUS_SUCCESS &&
        !(Context->Operation == IRP_MJ_READ && Context->NativeStatus == STATUS_END_OF_FILE) &&
        !(Context->Operation == IRP_MJ_QUERY_SECURITY && (Context->NativeStatus == STATUS_BUFFER_TOO_SMALL ||
          Context->NativeStatus == STATUS_BUFFER_OVERFLOW))) status = Context->NativeStatus;
    UNREFERENCED_PARAMETER(Data);
    return METADATA_STATUS(status);
}

_Use_decl_annotations_
FLT_POSTOP_CALLBACK_STATUS SafeUploadMetadataPost(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS Objects,
    PVOID Context, FLT_POST_OPERATION_FLAGS Flags)
{
    SU_METADATA_COMPLETION *c = (SU_METADATA_COMPLETION *)((ULONG_PTR)Context & ~(ULONG_PTR)15);
    SU_METADATA_GROUP *group = c->Group;
    SU_METADATA_CHILD *child = c->ChildIndex == SU_METADATA_CHILDREN ? NULL : &group->Children[c->ChildIndex];
    BOOLEAN draining = BooleanFlagOn(Flags, FLTFL_POST_OPERATION_DRAINING), revoke = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
    KIRQL irql;
    SU_METADATA_DIAGNOSTIC *Diagnostic = &c->Diagnostic;
    if (c->Operation == IRP_MJ_CLEANUP) {
        KeAcquireSpinLock(&MetadataLock, &irql);
        if (child != NULL) {
            child->Cleaned = TRUE;
            if (draining || Data->IoStatus.Status != STATUS_SUCCESS) child->Uncertain = TRUE;
            --child->Pins;
        }
        c->InUse = FALSE; c->Signature = 0; --group->PostOwners;
        KeReleaseSpinLock(&MetadataLock, irql);
        if (draining) SafeUploadMetadataRevoke(group->MainCookie);
        ExReleaseRundownProtection(&group->Rundown);
        KeSetEvent(&MetadataWork, IO_NO_INCREMENT, FALSE);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    c->NativeStatus = draining ? STATUS_PENDING : Data->IoStatus.Status;
    c->NativeInformation = draining ? 0 : Data->IoStatus.Information;
    if (draining || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        (VOID)METADATA_STATUS(STATUS_DEVICE_NOT_READY);
        KeAcquireSpinLock(&MetadataLock, &irql);
        if (child != NULL) {
            child->State = SuMetadataRevoked; child->Uncertain = TRUE;
            /* No CLOSE is promised for an unknown/failed CREATE. Withdraw
             * its nonowning key while this post still owns the reference;
             * Deferred may let the worker release it immediately. No Active
             * metadata authority or native-success claim survives this cut. */
            if (c->Operation == IRP_MJ_CREATE) { child->Key = NULL; child->Closed = TRUE; }
        }
        if (group->UnknownOutcomes < (UINT64)MAXLONGLONG) ++group->UnknownOutcomes;
        KeReleaseSpinLock(&MetadataLock, irql);
        SafeUploadMetadataRevoke(group->MainCookie);
        KeAcquireSpinLock(&MetadataLock, &irql);
        c->Deferred = TRUE;
        KeReleaseSpinLock(&MetadataLock, irql);
        KeSetEvent(&MetadataWork, IO_NO_INCREMENT, FALSE);
        return FLT_POSTOP_FINISHED_PROCESSING; /* PASSIVE owner releases refs/pins */
    }
    if (c->Operation == IRP_MJ_CREATE && !NT_SUCCESS(c->NativeStatus)) {
        (VOID)METADATA_STATUS(c->NativeStatus);
        KeAcquireSpinLock(&MetadataLock, &irql);
        /* A CREATE completion always owns a child; guard anyway so a logic defect cannot dereference NULL. */
        if (child != NULL) { child->Key = NULL; child->Closed = TRUE; child->State = SuMetadataRevoked; }
        KeReleaseSpinLock(&MetadataLock, irql);
        MetadataReleaseIo(c);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (child != NULL) status = MetadataPostNative(c, Data, Objects);
    else status = MetadataRootIoPost(c);
    if (status != STATUS_SUCCESS) {
        (VOID)METADATA_STATUS(status);
        KeAcquireSpinLock(&MetadataLock, &irql);
        if (child != NULL) { child->Uncertain = TRUE; child->State = SuMetadataRevoked; }
        KeReleaseSpinLock(&MetadataLock, irql);
        revoke = TRUE;
        if (c->Operation == IRP_MJ_CREATE) {
            if (NT_SUCCESS(c->NativeStatus) && Objects->FileObject->FsContext != NULL)
                FltCancelFileOpen(Objects->Instance, Objects->FileObject);
            Data->IoStatus.Status = status; Data->IoStatus.Information = 0;
            KeAcquireSpinLock(&MetadataLock, &irql);
            if (child != NULL) { child->Key = NULL; child->Closed = TRUE; }
            KeReleaseSpinLock(&MetadataLock, irql);
        }
    }
    if (revoke) SafeUploadMetadataRevoke(group->MainCookie);
    MetadataReleaseIo(c);
    return FLT_POSTOP_FINISHED_PROCESSING;
}
