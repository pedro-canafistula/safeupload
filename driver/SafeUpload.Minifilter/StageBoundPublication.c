/* V26 original-operation permits and immutable native receipts. Normal builds
 * omit this translation unit. Source/security/readiness gates remain closed.
 * No RPC, token impersonation, privileged mutation or user handle is created. */
#include "StageBoundPublicationInternal.h"
#include "StagePublic.h"
#include "StageNativeRecords.h"
#include "Stage.h"

#if SAFEUPLOAD_STAGING_PROTOTYPE
#define BP_TAG 'bUpS'
#define BP_ACCESS ((ACCESS_MASK)0x00110082)
#define BP_OPTIONS 0x0020006AUL
#define BP_PREPARED 1UL
#define BP_CONSUMED 2UL
#define BP_REVOKED 3UL
#define BP_ACKNOWLEDGED 4UL
#define BP_UNKNOWN 5UL
#define BP_REJECTED 6UL
#define BP_NOT_READY 7UL
#define BP_CREATE_CONSUMED (1ULL << 0)
#define BP_CREATE_FORWARDED (1ULL << 1)
#define BP_CREATE_NOT_FORWARDED (1ULL << 2)
#define BP_CREATE_KNOWN (1ULL << 3)
#define BP_CREATE_ACCEPTED (1ULL << 4)
#define BP_ID_KNOWN (1ULL << 5)
#define BP_FENCED (1ULL << 6)
#define BP_DRAINED (1ULL << 7)
#define BP_FLUSH_KNOWN (1ULL << 8)
#define BP_FLUSH_SUCCEEDED (1ULL << 9)
#define BP_RENAME_ARMED (1ULL << 10)
#define BP_RENAME_CONSUMED (1ULL << 11)
#define BP_RENAME_FORWARDED (1ULL << 12)
#define BP_RENAME_NOT_FORWARDED (1ULL << 13)
#define BP_RENAME_KNOWN (1ULL << 14)
#define BP_RENAME_ACCEPTED (1ULL << 15)
#define BP_TARGET_KNOWN (1ULL << 16)
#define BP_TARGET_ABSENT (1ULL << 17)
#define BP_CLEANUP_ARMED (1ULL << 18)
#define BP_CLEANUP_FORWARDED (1ULL << 19)
#define BP_CLEANUP_NOT_FORWARDED (1ULL << 20)
#define BP_CLEANUP_KNOWN (1ULL << 21)
#define BP_CLEANUP_ACCEPTED (1ULL << 22)
#define BP_LAST_CLEANUP (1ULL << 23)
#define BP_COVERAGE_LOST (1ULL << 24)
#define BP_CALLBACK (1ULL << 25)
#define BP_DIRECTORY_BYTES (64UL * 1024)
#define BP_DIRECTORY_PAGES 64UL

typedef struct _BP_RECORD {
    LIST_ENTRY Link, WorkLink;
    SAFEUPLOAD_BOUND_PUBLICATION_FACTS_ROW Facts; /* Zeroed, fixed, pointer-free. */
    SAFEUPLOAD_PUBLICATION_SOURCE Source;
    PEPROCESS Creator; /* Referenced exact process; PID is replay metadata only. */
    PACCESS_TOKEN Token; /* Referenced primary, requires original unimpersonated service CREATE. */
    PVOID Cookie; /* Opaque monotonic key, not an owning pointer. */
    UINT64 Authority;
    PFILE_OBJECT Object; /* NON-OWNING; original callback/user lifetime, removed before CLOSE. */
    PSECURITY_DESCRIPTOR CallbackSecurity; /* Owned canonical capture through post-CREATE. */
    ULONG CallbackSecurityBytes;
    LONG Uses, Callbacks; /* BpLock: map + work/control/callback refs. */
    ULONG CreateResult, RenameResult, WorkKind;
    LONGLONG WriteLimit; /* Bounded aligned padding, truncated to exact EOF before rename. */
    BOOLEAN Queued, Working, Revoked, NameReserved, Exposed, ClosePending, CancelledClose;
} BP_RECORD, *PBP_RECORD;

typedef union _BP_INPUT {
    SAFEUPLOAD_BOUND_PUBLICATION_REQUEST Mutation;
    SAFEUPLOAD_BOUND_PUBLICATION_FACTS_REQUEST Facts;
    SAFEUPLOAD_BOUND_PUBLICATION_ACK_REQUEST Ack;
} BP_INPUT;

/* Fixed-size nonpaged port scratch: both request and reply are read/written
 * under BpLock. Never put the 960-byte request on the kernel stack. */
typedef struct _BP_CONTROL_WORK {
    BP_INPUT Request;
    SAFEUPLOAD_BOUND_PUBLICATION_REPLY Reply;
} BP_CONTROL_WORK, *PBP_CONTROL_WORK;

static KSPIN_LOCK BpLock; /* Also the per-record I/O-admission/fence lock. */
static LIST_ENTRY BpRecords, BpWork;
static KEVENT BpChanged, BpWake;
static EX_RUNDOWN_REF BpCalls;
static volatile LONG BpInitialized;
static GUID BpDriver;
static ULONG BpBoot, BpCount, BpFactories;
static UINT64 BpRevision;
static UINT64 BpTopologyRevision;
static BOOLEAN BpAccepting, BpReplayUsable, BpStopping, BpCallsDrained;
static BOOLEAN BpNamespaceUnknown; /* BpLock; sticky for this driver lifetime. */
static HANDLE BpThread;

_IRQL_requires_(PASSIVE_LEVEL)
static VOID BpDestroy(_In_ PBP_RECORD r);
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS BpTokenSession(_In_ PACCESS_TOKEN Token, _Out_ PULONG SessionId);
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS BpQuery(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT Object,
    _Out_writes_bytes_(Bytes) PVOID Buffer, _In_ ULONG Bytes, _In_ FILE_INFORMATION_CLASS Kind);
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS BpIdentity(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT Object,
    _In_ BOOLEAN Directory, _Out_ PSAFEUPLOAD_STAGE_IDENTITY_V19 Id, _Out_opt_ PNTSTATUS QueryStatus);
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS BpAnchors(_In_ PBP_RECORD r, _In_opt_ PFILE_OBJECT ActualParent);
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS BpCaptureSecurity(_In_ PSECURITY_DESCRIPTOR Input,
    _Outptr_result_nullonfailure_ PSECURITY_DESCRIPTOR *Copy, _Out_ PULONG Bytes);
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS BpStoredSecurity(_In_ PBP_RECORD r, _In_ PFILE_OBJECT Object);
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS BpObserve(_In_ PBP_RECORD r, _Out_ PSAFEUPLOAD_STAGE_IDENTITY_V19 Observed,
    _Out_ PNTSTATUS QueryStatus);
_IRQL_requires_(PASSIVE_LEVEL)
static VOID BpPrepare(_In_ PBP_RECORD r);
_IRQL_requires_(PASSIVE_LEVEL)
static VOID BpDrainAndFlush(_In_ PBP_RECORD r, _In_ BOOLEAN Cleanup);
_IRQL_requires_(PASSIVE_LEVEL)
static KSTART_ROUTINE BpWorker;
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS BpMutation(_In_ const SAFEUPLOAD_BOUND_PUBLICATION_REQUEST *Request,
    _In_ PVOID Cookie, _In_ PEPROCESS Process, _In_ UINT64 Epoch, _In_ UINT64 Authority,
    _Out_ PSAFEUPLOAD_BOUND_PUBLICATION_REPLY Reply);
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS BpCheckCreate(_In_ PBP_RECORD r, _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _Outptr_result_nullonfailure_ PSECURITY_DESCRIPTOR *Security,
    _Out_ PULONG Bytes);
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS BpCheckRename(_In_ PBP_RECORD r, _In_ PFLT_CALLBACK_DATA Data,
    _Out_ PSAFEUPLOAD_STAGE_IDENTITY_V19 Observed, _Out_ PNTSTATUS QueryStatus,
    _Out_ PBOOLEAN ObservationComplete);

/* Routines that own NativeLock/BpLock across statements stay resident.
 * Entry remains PASSIVE where required for I/O; no PAGE instruction may
 * execute after the spin-lock wrapper raises IRQL. */
#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, BpDestroy)
#pragma alloc_text(PAGE, BpTokenSession)
#pragma alloc_text(PAGE, BpQuery)
#pragma alloc_text(PAGE, BpIdentity)
#pragma alloc_text(PAGE, BpAnchors)
#pragma alloc_text(PAGE, BpCaptureSecurity)
#pragma alloc_text(PAGE, BpStoredSecurity)
#pragma alloc_text(PAGE, BpObserve)
#pragma alloc_text(PAGE, BpCheckCreate)
#pragma alloc_text(PAGE, BpCheckRename)
#pragma alloc_text(PAGE, SafeUploadBoundPublicationInitialize)
#pragma alloc_text(PAGE, SafeUploadBoundPublicationUninitialize)
#endif

_IRQL_requires_max_(DISPATCH_LEVEL) _IRQL_raises_(DISPATCH_LEVEL)
__declspec(noinline) static VOID BpAcquire(_Out_ _At_(*Irql, _IRQL_saves_) PKIRQL Irql)
{ KeAcquireSpinLock(&BpLock, Irql); }
_IRQL_requires_(DISPATCH_LEVEL)
__declspec(noinline) static VOID BpRelease(_In_ _IRQL_restores_ KIRQL Irql)
{ KeReleaseSpinLock(&BpLock, Irql); }
static BOOLEAN BpEnter(VOID)
{ return InterlockedCompareExchange(&BpInitialized, 0, 0) != 0 && ExAcquireRundownProtection(&BpCalls); }
static BOOLEAN BpEqual(const VOID *A, const VOID *B, SIZE_T Bytes)
{ return RtlEqualMemory(A, B, Bytes); }
static BOOLEAN BpZero(const VOID *Bytes, SIZE_T Count)
{
    const UCHAR *p = Bytes;
    SIZE_T i;
    for (i = 0; i < Count; ++i) if (p[i] != 0) return FALSE;
    return TRUE;
}
static BOOLEAN BpId(const SAFEUPLOAD_STAGE_IDENTITY_V19 *Id, UINT64 Serial)
{ return Id->VolumeSerialNumber == Serial && !BpZero(&Id->FileId, sizeof(Id->FileId)); }
static BOOLEAN BpLeaf(const WCHAR *Leaf, USHORT Bytes, ULONG Capacity)
{
    ULONG i, chars = Bytes / sizeof(WCHAR);
    if (chars == 0 || chars >= Capacity || (Bytes & 1) != 0 ||
        !BpZero(Leaf + chars, (Capacity - chars) * sizeof(WCHAR)) ||
        (chars == 1 && Leaf[0] == L'.') || (chars == 2 && Leaf[0] == L'.' && Leaf[1] == L'.')) return FALSE;
    for (i = 0; i < chars; ++i) {
        WCHAR c = Leaf[i];
        if (c == 0 || c == L'\\' || c == L'/' || c == L':' || c == L'*' || c == L'?') return FALSE;
        if (c >= 0xd800 && c <= 0xdbff) {
            if (++i >= chars || Leaf[i] < 0xdc00 || Leaf[i] > 0xdfff) return FALSE;
        } else if (c >= 0xdc00 && c <= 0xdfff) return FALSE;
    }
    return TRUE;
}
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN BpLeafEqual(const WCHAR *A, USHORT ABytes, const WCHAR *B, USHORT BBytes, BOOLEAN Sensitive)
{
    UNICODE_STRING a, b;
    a.Buffer = (PWCHAR)A; a.Length = a.MaximumLength = ABytes;
    b.Buffer = (PWCHAR)B; b.Length = b.MaximumLength = BBytes;
    if (Sensitive) return ABytes == BBytes && BpEqual(A, B, ABytes);
    return RtlEqualUnicodeString(&a, &b, TRUE);
}
static BOOLEAN BpValid(const SAFEUPLOAD_BOUND_PUBLICATION_REQUEST *r)
{
    static const UCHAR emptyDigest[32] = {0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,
        0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,
        0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55};
    UINT64 serial = r->VolumeRootIdentity.VolumeSerialNumber;
    if (r->Phase < SAFEUPLOAD_BOUND_PUBLICATION_CREATE || r->Phase > SAFEUPLOAD_BOUND_PUBLICATION_REVOKE ||
        BpZero(&r->TransferId, sizeof(GUID)) || BpZero(&r->DriverInstanceId, sizeof(GUID)) ||
        BpZero(&r->CreateNonce, sizeof(GUID)) || BpZero(&r->PermitNonce, sizeof(GUID)) ||
        BpZero(&r->OperationId, sizeof(GUID)) || BpZero(&r->MountManagerVolumeId, sizeof(GUID)) ||
        BpEqual(&r->TransferId, &r->CreateNonce, sizeof(GUID)) ||
        BpEqual(&r->OperationId, &r->CreateNonce, sizeof(GUID)) ||
        BpEqual(&r->OperationId, &r->TransferId, sizeof(GUID)) ||
        BpEqual(&r->OperationId, &r->PermitNonce, sizeof(GUID)) ||
        r->DestinationGeneration <= 0 || r->MeasuredLength < 0 ||
        r->ExpectedLatestPublished < 0 || r->ExpectedCommittedDelete < 0 ||
        r->ExpectedMaxAllocated < r->DestinationGeneration ||
        r->ExpectedMaxAllocated < r->ExpectedLatestPublished || r->ExpectedMaxAllocated < r->ExpectedCommittedDelete ||
        r->Flags > 1 || r->ParentCaseSensitive > 1 || !BpId(&r->VolumeRootIdentity, serial) ||
        !BpId(&r->ParentIdentity, serial) || !BpId(&r->StageIdentity, serial) ||
        (r->Flags == 0 ? !BpZero(&r->ExpectedPublicIdentity, sizeof(r->ExpectedPublicIdentity)) :
            !BpId(&r->ExpectedPublicIdentity, serial)) ||
        !BpLeaf(r->DestinationLeaf, r->DestinationLeafBytes, 256) || !BpLeaf(r->TemporaryLeaf, r->TemporaryLeafBytes, 64) ||
        BpLeafEqual(r->DestinationLeaf, r->DestinationLeafBytes, r->TemporaryLeaf, r->TemporaryLeafBytes, FALSE) ||
        BpZero(r->InspectedDigest, 32) || (r->MeasuredLength == 0 && !BpEqual(r->InspectedDigest, emptyDigest, 32))) return FALSE;
    if (r->Phase == SAFEUPLOAD_BOUND_PUBLICATION_CREATE)
        return BpZero(&r->TemporaryIdentity, sizeof(r->TemporaryIdentity)) && BpEqual(&r->PermitNonce, &r->CreateNonce, sizeof(GUID));
    if (r->Phase == SAFEUPLOAD_BOUND_PUBLICATION_RENAME)
        return BpId(&r->TemporaryIdentity, serial) && !BpEqual(&r->PermitNonce, &r->CreateNonce, sizeof(GUID));
    return BpEqual(&r->PermitNonce, &r->CreateNonce, sizeof(GUID)) &&
        (BpZero(&r->TemporaryIdentity, sizeof(r->TemporaryIdentity)) || BpId(&r->TemporaryIdentity, serial));
}
/* BpLock: revision changes include reference/count transitions visible as
 * CallbackOwned, not just successful filesystem mutations. Stop on wrap. */
static VOID BpChangedLocked(VOID)
{
    if (++BpRevision == 0) BpReplayUsable = FALSE;
    KeSetEvent(&BpChanged, IO_NO_INCREMENT, FALSE);
}
static PBP_RECORD BpFind(const GUID *Nonce)
{
    PLIST_ENTRY link;
    for (link = BpRecords.Flink; link != &BpRecords; link = link->Flink) {
        PBP_RECORD r = CONTAINING_RECORD(link, BP_RECORD, Link);
        if (BpEqual(&r->Facts.Create.CreateNonce, Nonce, sizeof(GUID))) return r;
    }
    return NULL;
}
static VOID BpCallback(PBP_RECORD r, LONG Delta)
{
    r->Callbacks += Delta; r->Uses += Delta;
    if (r->Callbacks != 0 || r->Queued || r->Working) r->Facts.Flags |= BP_CALLBACK;
    else r->Facts.Flags &= ~BP_CALLBACK;
    NT_ASSERT(r->Callbacks >= 0 && r->Uses >= 1);
    BpChangedLocked();
}
static VOID BpFence(PBP_RECORD r)
{
    /* Same lock as ALL write/resize admissions; NEVER clear this bit. */
    UINT64 before = r->Facts.Flags;
    r->Facts.Flags |= BP_FENCED;
    if (r->Facts.InFlightWrites == 0 && r->Facts.InFlightMutators == 0)
        r->Facts.Flags |= BP_DRAINED;
    if (before != r->Facts.Flags) BpChangedLocked();
}
static VOID BpQueue(PBP_RECORD r, ULONG Kind)
{
    if (r->Queued || r->Working || BpStopping) return;
    r->WorkKind = Kind; r->Queued = TRUE; ++r->Uses; r->Facts.Flags |= BP_CALLBACK;
    InsertTailList(&BpWork, &r->WorkLink);
    BpChangedLocked();
    KeSetEvent(&BpWake, IO_NO_INCREMENT, FALSE);
}
static VOID BpRevoke(PBP_RECORD r)
{
    r->Revoked = TRUE;
    BpFence(r);
    if (!(r->Facts.Flags & BP_CREATE_CONSUMED)) {
        r->Facts.Flags |= BP_CREATE_CONSUMED | BP_CREATE_NOT_FORWARDED;
        r->CreateResult = BP_NOT_READY;
    }
    if ((r->Facts.Flags & BP_RENAME_ARMED) && !(r->Facts.Flags & BP_RENAME_CONSUMED)) {
        r->Facts.Flags |= BP_RENAME_CONSUMED | BP_RENAME_NOT_FORWARDED;
        r->RenameResult = BP_REJECTED;
    }
    BpChangedLocked();
}
static BOOLEAN BpTerminal(PBP_RECORD r)
{
    UINT64 f = r->Facts.Flags;
    if (r->Uses != 1 || r->Object != NULL || r->Callbacks != 0 || r->Queued || r->Working ||
        r->Facts.InFlightWrites != 0 || r->Facts.InFlightMutators != 0 || (f & BP_COVERAGE_LOST)) return FALSE;
    if (f & BP_CREATE_NOT_FORWARDED) return !(f & BP_ID_KNOWN);
    if ((f & BP_CREATE_KNOWN) && !(f & BP_CREATE_ACCEPTED)) {
        NTSTATUS status = r->Facts.CreateStatus;
        UINT64 info = r->Facts.CreateInformation;
        return status < 0 && !(f & BP_ID_KNOWN) &&
            (info == 0 || (status == STATUS_OBJECT_NAME_COLLISION && info == FILE_EXISTS) ||
             ((status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND) && info == FILE_DOES_NOT_EXIST));
    }
    return (f & BP_LAST_CLEANUP) &&
        (!(f & BP_RENAME_FORWARDED) || ((f & BP_RENAME_KNOWN) && r->Facts.RenameStatus <= 0)) &&
        (!(f & BP_CLEANUP_FORWARDED) || ((f & BP_CLEANUP_KNOWN) && r->Facts.CleanupStatus <= 0));
}
_IRQL_requires_(PASSIVE_LEVEL)
static VOID BpDestroy(_In_ PBP_RECORD r)
{
    PAGED_CODE();
    NT_ASSERT(r->Object == NULL && r->Uses == 0);
    SafeUploadStagePublicationReleaseSource(&r->Source);
    if (r->CallbackSecurity != NULL) ExFreePoolWithTag(r->CallbackSecurity, BP_TAG);
    if (r->Token != NULL) PsDereferencePrimaryToken(r->Token);
    if (r->Creator != NULL) ObDereferenceObject(r->Creator);
    ExFreePoolWithTag(r, BP_TAG);
    SafeUploadStageWritersOwnerRelease();
}
/* V26 names the original authenticated service creator, not the staged app.
 * Read the exact retained primary token which pre-CREATE must also present;
 * never substitute a system worker's process/session or an effective token.
 * SeQueryInformationToken is documented in ntifs.h and returns caller-owned
 * paged storage. The output is defined even on query/allocation failure. */
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS BpTokenSession(_In_ PACCESS_TOKEN Token, _Out_ PULONG SessionId)
{
    PULONG session = NULL;
    NTSTATUS status;
    PAGED_CODE();
    *SessionId = 0;
    status = SeQueryInformationToken(Token, TokenSessionId, (PVOID *)&session);
    if (status == STATUS_SUCCESS) {
        if (session == NULL) status = STATUS_INVALID_BUFFER_SIZE;
        else *SessionId = *session;
    }
    if (session != NULL) ExFreePool(session);
    return status;
}
static VOID BpReply(const SAFEUPLOAD_BOUND_PUBLICATION_REQUEST *Request, UINT64 Epoch, UINT64 Authority,
    ULONG Result, PSAFEUPLOAD_BOUND_PUBLICATION_REPLY Reply)
{
    RtlZeroMemory(Reply, sizeof(*Reply));
    Reply->ExtensionVersion = SAFEUPLOAD_BOUND_PUBLICATION_VERSION;
    Reply->StructSize = sizeof(*Reply); Reply->Phase = Request->Phase;
    Reply->TransferId = Request->TransferId; Reply->DriverInstanceId = Request->DriverInstanceId;
    Reply->PermitNonce = Request->PermitNonce; Reply->CreateNonce = Request->CreateNonce; Reply->OperationId = Request->OperationId;
    Reply->DestinationGeneration = Request->DestinationGeneration;
    Reply->ConnectionEpoch = Epoch; Reply->AuthorityRevision = Authority; Reply->Result = Result;
}
static BOOLEAN BpSameSource(const SAFEUPLOAD_BOUND_PUBLICATION_REQUEST *a, const SAFEUPLOAD_BOUND_PUBLICATION_REQUEST *b)
{
    return BpEqual(&a->TransferId, &b->TransferId, sizeof(GUID)) &&
        BpEqual(&a->DriverInstanceId, &b->DriverInstanceId, sizeof(GUID)) &&
        BpEqual(&a->CreateNonce, &b->CreateNonce, sizeof(GUID)) && a->DestinationGeneration == b->DestinationGeneration &&
        BpEqual(&a->MountManagerVolumeId, &b->MountManagerVolumeId, sizeof(GUID)) &&
        BpEqual(&a->VolumeRootIdentity, &b->VolumeRootIdentity, 3 * sizeof(a->VolumeRootIdentity)) &&
        a->MeasuredLength == b->MeasuredLength && a->ParentCaseSensitive == b->ParentCaseSensitive &&
        a->DestinationLeafBytes == b->DestinationLeafBytes && a->TemporaryLeafBytes == b->TemporaryLeafBytes &&
        BpEqual(a->DestinationLeaf, b->DestinationLeaf, sizeof(a->DestinationLeaf)) &&
        BpEqual(a->TemporaryLeaf, b->TemporaryLeaf, sizeof(a->TemporaryLeaf)) && BpEqual(a->InspectedDigest, b->InspectedDigest, 32);
}
/* BpLock, no name-buffer reads or Unicode-table lookups at DISPATCH_LEVEL.
 * Store the full immutable destination key, conservatively exclude the whole
 * instance until shared-head integration can narrow contention safely. */
static BOOLEAN BpOtherReservation(_In_opt_ PBP_RECORD Owner, _In_ PFLT_INSTANCE Instance)
{
    PLIST_ENTRY link;
    for (link = BpRecords.Flink; link != &BpRecords; link = link->Flink) {
        PBP_RECORD r = CONTAINING_RECORD(link, BP_RECORD, Link);
        if (r != Owner && r->NameReserved && r->Source.Instance == Instance) return TRUE;
    }
    return FALSE;
}
static BOOLEAN BpNonceUsed(const GUID *Nonce)
{
    PLIST_ENTRY link;
    for (link = BpRecords.Flink; link != &BpRecords; link = link->Flink) {
        PBP_RECORD r = CONTAINING_RECORD(link, BP_RECORD, Link);
        if (BpEqual(Nonce, &r->Facts.Create.CreateNonce, sizeof(GUID)) ||
            BpEqual(Nonce, &r->Facts.Create.OperationId, sizeof(GUID)) ||
            BpEqual(Nonce, &r->Facts.Rename.PermitNonce, sizeof(GUID)) ||
            BpEqual(Nonce, &r->Facts.Rename.OperationId, sizeof(GUID)) ||
            BpEqual(Nonce, &r->Facts.CleanupNonce, sizeof(GUID)) ||
            BpEqual(Nonce, &r->Facts.CleanupOperationId, sizeof(GUID))) return TRUE;
    }
    return FALSE;
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS BpQuery(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT Object,
    _Out_writes_bytes_(Bytes) PVOID Buffer, _In_ ULONG Bytes, _In_ FILE_INFORMATION_CLASS Kind)
{
    ULONG returned = 0;
    NTSTATUS status;
    PAGED_CODE();
    RtlZeroMemory(Buffer, Bytes);
    status = FltQueryInformationFile(Instance, Object, Buffer, Bytes, Kind, &returned);
    return status == STATUS_SUCCESS && returned == Bytes ? STATUS_SUCCESS :
        (NT_SUCCESS(status) ? STATUS_INFO_LENGTH_MISMATCH : status);
}
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS BpIdentity(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT Object,
    _In_ BOOLEAN Directory, _Out_ PSAFEUPLOAD_STAGE_IDENTITY_V19 Id, _Out_opt_ PNTSTATUS QueryStatus)
{
    FILE_ATTRIBUTE_TAG_INFORMATION tag = {0};
    FILE_ID_INFORMATION id = {0};
    NTSTATUS status;
    ULONG returned = 0;
    PAGED_CODE();
    RtlZeroMemory(Id, sizeof(*Id));
    if (QueryStatus != NULL) *QueryStatus = 0;
    status = FltQueryInformationFile(Instance, Object, &tag, sizeof(tag), FileAttributeTagInformation, &returned);
    if (QueryStatus != NULL) *QueryStatus = status;
    if (status != STATUS_SUCCESS) return status;
    if (returned != sizeof(tag)) return STATUS_INFO_LENGTH_MISMATCH;
    if (BooleanFlagOn(tag.FileAttributes, FILE_ATTRIBUTE_DIRECTORY) != Directory ||
        FlagOn(tag.FileAttributes, FILE_ATTRIBUTE_REPARSE_POINT)) return STATUS_FILE_INVALID;
    returned = 0;
    status = FltQueryInformationFile(Instance, Object, &id, sizeof(id), FileIdInformation, &returned);
    if (QueryStatus != NULL) *QueryStatus = status;
    if (status == STATUS_SUCCESS && returned != sizeof(id)) return STATUS_INFO_LENGTH_MISMATCH;
    if (status == STATUS_SUCCESS && !BpZero(&id.FileId, sizeof(id.FileId))) {
        Id->VolumeSerialNumber = id.VolumeSerialNumber; Id->FileId = id.FileId;
    } else if (status == STATUS_SUCCESS) status = STATUS_FILE_INVALID;
    return status;
}
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS BpAnchors(_In_ PBP_RECORD r, _In_opt_ PFILE_OBJECT ActualParent)
{
    SAFEUPLOAD_STAGE_IDENTITY_V19 id;
    FILE_CASE_SENSITIVE_INFORMATION mode = {0};
    ULONG expectedCaseFlags = r->Facts.Create.ParentCaseSensitive ? FILE_CS_FLAG_CASE_SENSITIVE_DIR : 0UL;
    GUID mount;
    NTSTATUS status;
    PAGED_CODE();
    if (r->Source.Instance == NULL || r->Source.Root == NULL || r->Source.Parent == NULL ||
        SafeUploadStageAttachInstanceRetiring(r->Source.Instance) ||
        !SafeUploadInstanceAdmissionGateSatisfied(r->Source.Instance)) return STATUS_DEVICE_NOT_READY;
    status = SafeUploadStagePublicReadMountGuid(r->Source.Instance, &mount);
    if (status != STATUS_SUCCESS || !BpEqual(&mount, &r->Facts.Create.MountManagerVolumeId, sizeof(GUID))) return STATUS_FILE_INVALID;
    status = BpIdentity(r->Source.Instance, r->Source.Root, TRUE, &id, NULL);
    if (status != STATUS_SUCCESS || !BpEqual(&id, &r->Facts.Create.VolumeRootIdentity, sizeof(id))) return STATUS_FILE_INVALID;
    status = BpIdentity(r->Source.Instance, r->Source.Parent, TRUE, &id, NULL);
    if (status != STATUS_SUCCESS || !BpEqual(&id, &r->Facts.Create.ParentIdentity, sizeof(id))) return STATUS_FILE_INVALID;
    if (ActualParent != NULL) {
        status = BpIdentity(r->Source.Instance, ActualParent, TRUE, &id, NULL);
        if (status != STATUS_SUCCESS || !BpEqual(&id, &r->Facts.Create.ParentIdentity, sizeof(id))) return STATUS_FILE_INVALID;
    }
    status = BpQuery(r->Source.Instance, r->Source.Parent, &mode, sizeof(mode), FileCaseSensitiveInformation);
    if (status != STATUS_SUCCESS || mode.Flags != expectedCaseFlags)
        return STATUS_FILE_INVALID;
    return STATUS_SUCCESS;
}
/* Canonicalize self-relative/absolute inputs without dropping ANY control bit
 * or changing ACL order. Bounded copies, never AccessState pointer retention. */
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS BpCaptureSecurity(_In_ PSECURITY_DESCRIPTOR Input,
    _Outptr_result_nullonfailure_ PSECURITY_DESCRIPTOR *Copy, _Out_ PULONG Bytes)
{
    PSECURITY_DESCRIPTOR result = NULL;
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    ULONG bytes = 0;
    NTSTATUS status = STATUS_INVALID_SECURITY_DESCR;
    PAGED_CODE();
    *Copy = NULL; *Bytes = 0;
    try {
        if (Input == NULL || !RtlValidSecurityDescriptor(Input)) leave;
        control = ((SECURITY_DESCRIPTOR_RELATIVE *)Input)->Control;
        if (control & SE_SELF_RELATIVE) bytes = RtlLengthSecurityDescriptor(Input);
        else {
            status = RtlAbsoluteToSelfRelativeSD(Input, NULL, &bytes);
            if (status != STATUS_BUFFER_TOO_SMALL) { status = STATUS_INVALID_SECURITY_DESCR; leave; }
        }
        if (bytes < sizeof(SECURITY_DESCRIPTOR_RELATIVE) || bytes > SAFEUPLOAD_STAGE_CREATE_SECURITY_LIMIT) {
            status = STATUS_INVALID_BUFFER_SIZE; leave;
        }
        result = ExAllocatePool2(POOL_FLAG_NON_PAGED, bytes, BP_TAG);
        if (result == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; leave; }
        if (control & SE_SELF_RELATIVE) { RtlCopyMemory(result, Input, bytes); status = STATUS_SUCCESS; }
        else status = RtlAbsoluteToSelfRelativeSD(Input, result, &bytes);
        if (status == STATUS_SUCCESS && !RtlValidRelativeSecurityDescriptor(result, bytes,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION))
            status = STATUS_INVALID_SECURITY_DESCR;
    } except (EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
    /* Only an exact completed capture transfers ownership. Informational
     * native/exception statuses must not satisfy a nonnull success contract. */
    if (status != STATUS_SUCCESS && NT_SUCCESS(status)) status = STATUS_INVALID_SECURITY_DESCR;
    if (status == STATUS_SUCCESS && result == NULL) status = STATUS_INVALID_SECURITY_DESCR;
    if (status == STATUS_SUCCESS) { *Copy = result; *Bytes = bytes; result = NULL; }
    if (result != NULL) ExFreePoolWithTag(result, BP_TAG);
    return status;
}
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS BpStoredSecurity(_In_ PBP_RECORD r, _In_ PFILE_OBJECT Object)
{
    PSECURITY_DESCRIPTOR security;
    ULONG bytes = 0, returned = 0;
    NTSTATUS status;
    PAGED_CODE();
    status = FltQuerySecurityObject(r->Source.Instance, Object, BACKUP_SECURITY_INFORMATION, NULL, 0, &bytes);
    if ((status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) ||
        bytes == 0 || bytes > SAFEUPLOAD_STAGE_CREATE_SECURITY_LIMIT) return STATUS_INVALID_SECURITY_DESCR;
    security = ExAllocatePool2(POOL_FLAG_PAGED, bytes, BP_TAG);
    if (security == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    status = FltQuerySecurityObject(r->Source.Instance, Object, BACKUP_SECURITY_INFORMATION, security, bytes, &returned);
    if (status == STATUS_SUCCESS && (returned != r->Source.StoredBytes || returned > bytes ||
        !BpEqual(security, r->Source.Stored, returned))) status = STATUS_INVALID_SECURITY_DESCR;
    ExFreePoolWithTag(security, BP_TAG);
    if (status != STATUS_SUCCESS) SafeUploadStagePublicRecordWriterRefusal(StageWriterPublicationSecurityNotEquivalent);
    return status;
}
/* Complete anchored enumeration, no child open and no path/digest authority. */
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS BpObserve(_In_ PBP_RECORD r, _Out_ PSAFEUPLOAD_STAGE_IDENTITY_V19 Observed,
    _Out_ PNTSTATUS QueryStatus)
{
    PUCHAR buffer;
    ULONG page, returned, offset, header = FIELD_OFFSET(FILE_ID_EXTD_DIR_INFORMATION, FileName);
    BOOLEAN present = FALSE;
    NTSTATUS status = STATUS_BUFFER_TOO_SMALL;
    PAGED_CODE();
    RtlZeroMemory(Observed, sizeof(*Observed));
    *QueryStatus = 0;
    /* Share the lease's enumeration exclusion with ancestor revalidation.
     * RestartScan is FILE_OBJECT state, not private to this callback. */
    if (!SafeUploadStagePublicPublicationBeginObservation(r->Source.Writer)) return STATUS_DEVICE_BUSY;
    buffer = ExAllocatePool2(POOL_FLAG_PAGED, BP_DIRECTORY_BYTES, BP_TAG);
    if (buffer == NULL) {
        SafeUploadStagePublicPublicationEndObservation(r->Source.Writer);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    for (page = 0; page < BP_DIRECTORY_PAGES; ++page) {
        returned = 0;
        RtlZeroMemory(buffer, BP_DIRECTORY_BYTES);
        status = FltQueryDirectoryFile(r->Source.Instance, r->Source.Parent, buffer, BP_DIRECTORY_BYTES,
            FileIdExtdDirectoryInformation, FALSE, NULL, page == 0, &returned);
        *QueryStatus = status; /* Includes native STATUS_NO_MORE_FILES completion. */
        if (status == STATUS_NO_MORE_FILES && returned == 0) { status = STATUS_SUCCESS; goto Exit; }
        if (status != STATUS_SUCCESS) { if (NT_SUCCESS(status)) status = STATUS_RETRY; goto Exit; }
        if (returned < header || returned > BP_DIRECTORY_BYTES) { status = STATUS_DATA_ERROR; goto Exit; }
        offset = 0;
        for (;;) {
            PFILE_ID_EXTD_DIR_INFORMATION entry = (PFILE_ID_EXTD_DIR_INFORMATION)(buffer + offset);
            if (entry->FileNameLength == 0 || (entry->FileNameLength & 1) != 0 ||
                entry->FileNameLength > returned - offset - header || entry->FileNameLength > 510) {
                status = STATUS_DATA_ERROR; goto Exit;
            }
            if (BpLeafEqual(entry->FileName, (USHORT)entry->FileNameLength,
                r->Facts.Create.DestinationLeaf, r->Facts.Create.DestinationLeafBytes, r->Facts.Create.ParentCaseSensitive != 0)) {
                if (present || FlagOn(entry->FileAttributes, FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) ||
                    BpZero(&entry->FileId, sizeof(entry->FileId))) { status = STATUS_FILE_INVALID; goto Exit; }
                present = TRUE; Observed->VolumeSerialNumber = r->Facts.Create.ParentIdentity.VolumeSerialNumber;
                Observed->FileId = entry->FileId;
            }
            if (entry->NextEntryOffset == 0) break;
            if (entry->NextEntryOffset < header + entry->FileNameLength || (entry->NextEntryOffset & 7) != 0 ||
                entry->NextEntryOffset > returned - offset - header) { status = STATUS_DATA_ERROR; goto Exit; }
            offset += entry->NextEntryOffset;
        }
    }
    status = STATUS_BUFFER_TOO_SMALL;
Exit:
    if (status != STATUS_SUCCESS) RtlZeroMemory(Observed, sizeof(*Observed));
    ExFreePoolWithTag(buffer, BP_TAG);
    SafeUploadStagePublicPublicationEndObservation(r->Source.Writer);
    return status;
}

/* BpLock -> protocol state -> connection state. Reset drops protocol/connection
 * locks before revoking this map. No caller takes BpLock while holding a stage
 * resource. A cookie comparison never transfers original creator authority. */
static BOOLEAN BpChannelCurrent(PBP_RECORD r)
{
    PVOID cookie = NULL;
    UINT64 epoch = 0, authority = 0;
    return BpReplayUsable && BpAccepting && !BpNamespaceUnknown && !r->Revoked && !SafeUploadStageMandatoryTeardownActive() &&
        (r->Source.Instance == NULL || !SafeUploadStageAttachInstanceRetiring(r->Source.Instance)) &&
        SafeUploadStageProtocolMetadataIdentity(r->Cookie, &cookie, &epoch, &authority) &&
        cookie == r->Cookie && epoch == r->Facts.OriginalConnectionEpoch && authority == r->Authority;
}
_IRQL_requires_(PASSIVE_LEVEL)
static VOID BpPrepare(_In_ PBP_RECORD r)
{
    SAFEUPLOAD_PUBLICATION_SOURCE source;
    NTSTATUS status;
    ULONG alignment = 0;
    LONGLONG writeLimit = 0;
    UINT64 topology;
    KIRQL irql;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    RtlZeroMemory(&source, sizeof(source));
    BpAcquire(&irql);
    topology = BpTopologyRevision;
    BpRelease(irql);
    status = SafeUploadStagePublicationAcquireSource(&r->Facts.Create, &source);
    if (status == STATUS_SUCCESS && (!SafeUploadStageProtocolBoundAllocationReady() ||
        !SafeUploadStagePublicationSourceCurrent(&r->Facts.Create, &source))) status = STATUS_DEVICE_NOT_READY;
    if (status == STATUS_SUCCESS) {
        alignment = max((ULONG)PAGE_SIZE, source.SectorSize);
        if (source.SectorSize < 512 || alignment > 65536 || (alignment & (alignment - 1)) != 0 ||
            r->Facts.Create.MeasuredLength > MAXLONGLONG - (alignment - 1)) status = STATUS_INVALID_BUFFER_SIZE;
        else writeLimit = (r->Facts.Create.MeasuredLength + alignment - 1) & ~((LONGLONG)alignment - 1);
    }
    BpAcquire(&irql);
    if (status == STATUS_SUCCESS && topology == BpTopologyRevision && source.Instance != NULL &&
        !SafeUploadStageAttachInstanceRetiring(source.Instance) &&
        BpAccepting && BpChannelCurrent(r) && !(r->Facts.Flags & BP_CREATE_CONSUMED)) {
        r->Source = source; RtlZeroMemory(&source, sizeof(source));
        r->WriteLimit = writeLimit; r->CreateResult = BP_PREPARED;
    } else {
        /* Affirmative negative receipt; no fake NTFS status/information. */
        BpRevoke(r);
    }
    BpChangedLocked();
    BpRelease(irql);
    SafeUploadStagePublicationReleaseSource(&source);
}
_IRQL_requires_(PASSIVE_LEVEL)
static VOID BpDrainAndFlush(_In_ PBP_RECORD r, _In_ BOOLEAN Cleanup)
{
    PFILE_OBJECT object = NULL;
    SAFEUPLOAD_STAGE_IDENTITY_V19 id;
    FILE_STANDARD_INFORMATION standard = {0};
    GUID nonce = {0}, operation = {0};
    NTSTATUS status = STATUS_DEVICE_NOT_READY, flushStatus = STATUS_SUCCESS;
    KIRQL irql;
    BOOLEAN flushed = FALSE, eofKnown = FALSE;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    /* This dedicated local worker never calls the service. Wakeups, rather
     * than elapsed time, recheck actual admitted I/O counts. */
    for (;;) {
        BOOLEAN stop, drained;
        BpAcquire(&irql);
        KeClearEvent(&BpChanged);
        BpFence(r);
        drained = r->Facts.InFlightWrites == 0 && r->Facts.InFlightMutators == 0;
        stop = BpStopping || SafeUploadStageMandatoryTeardownActive() || (r->Facts.Flags & BP_COVERAGE_LOST) != 0;
        if (drained && !stop && r->Object != NULL && r->Exposed && !r->ClosePending &&
            !(r->Facts.Flags & BP_LAST_CLEANUP)) {
            object = r->Object;
            ObReferenceObject(object); /* Short I/O pin only, no retained handle. */
        }
        BpRelease(irql);
        if (drained || stop) break;
        (VOID)KeWaitForSingleObject(&BpChanged, Executive, KernelMode, FALSE, NULL);
    }
    if (object != NULL) {
        status = BpIdentity(r->Source.Instance, object, FALSE, &id, NULL);
        if (status == STATUS_SUCCESS && !BpEqual(&id, &r->Facts.TemporaryIdentity, sizeof(id))) status = STATUS_FILE_INVALID;
        if (status == STATUS_SUCCESS) status = BpQuery(r->Source.Instance, object, &standard, sizeof(standard), FileStandardInformation);
        if (status == STATUS_SUCCESS) eofKnown = TRUE;
        if (status == STATUS_SUCCESS && (standard.EndOfFile.QuadPart != r->Facts.Create.MeasuredLength ||
            standard.Directory || standard.DeletePending)) status = STATUS_FILE_INVALID;
        if (status == STATUS_SUCCESS) {
            /* Never flush under map/namespace/stream locks or on the port thread. */
            flushStatus = FltFlushBuffers(r->Source.Instance, object);
            status = flushStatus;
            flushed = flushStatus != STATUS_PENDING;
        }
    }
    if (!Cleanup && status == STATUS_SUCCESS &&
        (!SafeUploadPolicyPublicationQuiescent() || !SafeUploadStageNativePublicationIdle(r->Source.Instance) ||
         !SafeUploadStagePublicationSourceCurrent(&r->Facts.Create, &r->Source)))
        status = STATUS_DEVICE_NOT_READY;
    if (Cleanup) {
        /* IDs are reserved before forwarding, even for an empty temporary. */
        if (ExUuidCreate(&nonce) != STATUS_SUCCESS || ExUuidCreate(&operation) != STATUS_SUCCESS)
            RtlZeroMemory(&nonce, sizeof(nonce));
    }
    BpAcquire(&irql);
    if (eofKnown && standard.EndOfFile.QuadPart >= 0) r->Facts.ObservedEof = standard.EndOfFile.QuadPart;
    if (flushed) {
        r->Facts.FlushStatus = flushStatus; r->Facts.Flags |= BP_FLUSH_KNOWN;
        if (flushStatus == STATUS_SUCCESS) r->Facts.Flags |= BP_FLUSH_SUCCEEDED;
    }
    if (Cleanup) {
        if (r->Revoked && object != NULL && (r->Facts.Flags & BP_DRAINED) &&
            !(r->Facts.Flags & (BP_COVERAGE_LOST | BP_RENAME_ACCEPTED | BP_CLEANUP_ARMED)) &&
            (!(r->Facts.Flags & BP_RENAME_FORWARDED) ||
                ((r->Facts.Flags & BP_RENAME_KNOWN) && r->Facts.RenameStatus < 0)) &&
            !BpZero(&nonce, sizeof(nonce)) && !BpNonceUsed(&nonce) && !BpNonceUsed(&operation) &&
            !BpEqual(&nonce, &operation, sizeof(GUID))) {
            r->Facts.CleanupNonce = nonce; r->Facts.CleanupOperationId = operation;
            r->Facts.Flags |= BP_CLEANUP_ARMED;
        }
    } else if (status == STATUS_SUCCESS && flushed && BpAccepting && BpChannelCurrent(r) &&
        r->NameReserved && !(r->Facts.Flags & (BP_RENAME_CONSUMED | BP_COVERAGE_LOST))) {
        r->RenameResult = BP_PREPARED;
    } else {
        r->Facts.Flags |= BP_RENAME_CONSUMED | BP_RENAME_NOT_FORWARDED;
        r->RenameResult = BP_REJECTED;
    }
    BpChangedLocked();
    BpRelease(irql);
    if (object != NULL) ObDereferenceObject(object);
}
_Use_decl_annotations_
static VOID BpWorker(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    for (;;) {
        PBP_RECORD r = NULL;
        KIRQL irql;
        BOOLEAN stop;
        BpAcquire(&irql);
        stop = BpStopping;
        if (!IsListEmpty(&BpWork)) {
            r = CONTAINING_RECORD(RemoveHeadList(&BpWork), BP_RECORD, WorkLink);
            r->Queued = FALSE; r->Working = TRUE;
        }
        BpRelease(irql);
        if (r == NULL) {
            if (stop) break;
            (VOID)KeWaitForSingleObject(&BpWake, Executive, KernelMode, FALSE, NULL);
            continue;
        }
        if (!stop) {
            if (r->WorkKind == SAFEUPLOAD_BOUND_PUBLICATION_CREATE) BpPrepare(r);
            else BpDrainAndFlush(r, r->WorkKind == SAFEUPLOAD_BOUND_PUBLICATION_REVOKE);
        }
        BpAcquire(&irql);
        if (stop) BpRevoke(r);
        r->Working = FALSE; --r->Uses;
        if (r->Callbacks == 0) r->Facts.Flags &= ~BP_CALLBACK;
        BpChangedLocked();
        BpRelease(irql);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS BpMutation(_In_ const SAFEUPLOAD_BOUND_PUBLICATION_REQUEST *Request,
    _In_ PVOID Cookie, _In_ PEPROCESS Process, _In_ UINT64 Epoch, _In_ UINT64 Authority,
    _Out_ PSAFEUPLOAD_BOUND_PUBLICATION_REPLY Reply)
{
    PBP_RECORD fresh = NULL, r;
    PLIST_ENTRY link;
    KIRQL irql;
    ULONG result = BP_REJECTED;
    ULONG sessionId = 0;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN slot = FALSE;
    PSAFEUPLOAD_BOUND_PUBLICATION_REQUEST canonical = NULL;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    RtlZeroMemory(Reply, sizeof(*Reply));
    if (!BpValid(Request)) return STATUS_INVALID_PARAMETER;
    if (!BpEqual(&Request->DriverInstanceId, &BpDriver, sizeof(GUID))) return STATUS_REVISION_MISMATCH;
    if (Request->Phase == SAFEUPLOAD_BOUND_PUBLICATION_REVOKE) {
        canonical = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*canonical), BP_TAG);
        if (canonical == NULL) return STATUS_INSUFFICIENT_RESOURCES;
        *canonical = *Request;
        canonical->Phase = SAFEUPLOAD_BOUND_PUBLICATION_CREATE;
        RtlZeroMemory(&canonical->TemporaryIdentity, sizeof(canonical->TemporaryIdentity));
    }
    if (Request->Phase == SAFEUPLOAD_BOUND_PUBLICATION_CREATE) {
        BpAcquire(&irql);
        r = BpFind(&Request->CreateNonce);
        if (r == NULL && BpAccepting && BpReplayUsable && BpCount + BpFactories < SAFEUPLOAD_BOUND_PUBLICATION_MAX_RECORDS) {
            ++BpFactories; slot = TRUE;
        }
        BpRelease(irql);
        if (slot) {
            fresh = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*fresh), BP_TAG);
            if (fresh != NULL) {
                RtlZeroMemory(fresh, sizeof(*fresh));
                SafeUploadStageWritersOwnerAcquire();
                fresh->Facts.Create = *Request; /* Validated pack-4, all input bytes defined/zero-tailed. */
                fresh->Facts.OriginalProcessId = HandleToULong(PsGetProcessId(Process));
                fresh->Facts.OriginalProcessCreationTime = PsGetProcessCreateTimeQuadPart(Process);
                fresh->Facts.OriginalConnectionEpoch = Epoch; fresh->Facts.OsBootSequence = BpBoot;
                ObReferenceObject(Process); fresh->Creator = Process;
                fresh->Token = PsReferencePrimaryToken(Process);
                status = BpTokenSession(fresh->Token, &sessionId);
                if (status == STATUS_SUCCESS) fresh->Facts.OriginalSessionId = sessionId;
                fresh->Cookie = Cookie; fresh->Authority = Authority;
                fresh->Uses = 1; fresh->CreateResult = BP_NOT_READY;
            }
        }
    }
    BpAcquire(&irql);
    if (slot) { --BpFactories; BpChangedLocked(); }
    /* A failed session query is not a session-zero fact or a prepared record.
     * Release factory capacity and the private record outside BpLock. */
    if (status != STATUS_SUCCESS) goto Exit;
    r = BpFind(&Request->CreateNonce);
    if (!BpReplayUsable || !SafeUploadConnectionIsAuthenticatedIdentity(Cookie, (LONG64)Epoch)) {
        status = STATUS_ACCESS_DENIED; goto Exit;
    }
    if (Request->Phase == SAFEUPLOAD_BOUND_PUBLICATION_CREATE) {
        if (r != NULL) {
            if (BpEqual(Request, &r->Facts.Create, sizeof(*Request))) {
                result = r->CreateResult;
                if (result == BP_PREPARED && (r->Creator != Process || !BpChannelCurrent(r))) result = BP_NOT_READY;
            }
        } else if (fresh != NULL && BpAccepting && !BpNonceUsed(&Request->CreateNonce) && !BpNonceUsed(&Request->OperationId)) {
            r = fresh; fresh = NULL;
            InsertTailList(&BpRecords, &r->Link); ++BpCount;
            BpQueue(r, SAFEUPLOAD_BOUND_PUBLICATION_CREATE);
            result = BP_NOT_READY;
        } else if (!BpAccepting) result = BP_NOT_READY;
        else if (!slot || fresh == NULL) status = STATUS_QUOTA_EXCEEDED;
    } else if (r == NULL) result = BP_UNKNOWN;
    else if (Request->Phase == SAFEUPLOAD_BOUND_PUBLICATION_REVOKE) {
        if (canonical != NULL && BpEqual(canonical, &r->Facts.Create, sizeof(*canonical)) &&
            (BpZero(&Request->TemporaryIdentity, sizeof(Request->TemporaryIdentity)) ||
             BpEqual(&Request->TemporaryIdentity, &r->Facts.TemporaryIdentity, sizeof(Request->TemporaryIdentity)))) {
            BpRevoke(r); result = BP_REVOKED;
            /* Reconnect may revoke, but cannot inherit the creator's DELETE grant. */
            if (r->Cookie == Cookie && r->Creator == Process && r->Authority == Authority)
                BpQueue(r, SAFEUPLOAD_BOUND_PUBLICATION_REVOKE);
        }
    } else if (r->Facts.Flags & BP_RENAME_ARMED) {
        if (BpEqual(Request, &r->Facts.Rename, sizeof(*Request))) {
            result = r->RenameResult;
            if (result == BP_PREPARED && (r->Creator != Process || !BpChannelCurrent(r))) result = BP_NOT_READY;
        }
    } else if (r->Creator == Process && BpChannelCurrent(r) && BpSameSource(&r->Facts.Create, Request) &&
        BpEqual(&Request->TemporaryIdentity, &r->Facts.TemporaryIdentity, sizeof(Request->TemporaryIdentity)) &&
        (r->Facts.Flags & (BP_CREATE_ACCEPTED | BP_ID_KNOWN)) == (BP_CREATE_ACCEPTED | BP_ID_KNOWN) &&
        r->Exposed && r->Object != NULL && !r->Queued && !r->Working &&
        !(r->Facts.Flags & (BP_LAST_CLEANUP | BP_COVERAGE_LOST)) &&
        !BpNonceUsed(&Request->PermitNonce) && !BpNonceUsed(&Request->OperationId) &&
        Request->DestinationGeneration > Request->ExpectedCommittedDelete &&
        Request->DestinationGeneration >= Request->ExpectedLatestPublished) {
        BOOLEAN conflict = FALSE;
        for (link = BpRecords.Flink; link != &BpRecords; link = link->Flink) {
            PBP_RECORD other = CONTAINING_RECORD(link, BP_RECORD, Link);
            if (other != r && other->Source.Instance == r->Source.Instance &&
                (other->NameReserved || other->Object != NULL || other->Callbacks != 0)) {
                conflict = TRUE; break;
            }
        }
        if (!conflict && BpAccepting) {
            r->Facts.Rename = *Request; r->Facts.Flags |= BP_RENAME_ARMED;
            r->NameReserved = TRUE; r->RenameResult = BP_NOT_READY;
            BpFence(r); /* Irreversible even when preparation later fails. */
            BpQueue(r, SAFEUPLOAD_BOUND_PUBLICATION_RENAME); result = BP_NOT_READY;
        }
    }
Exit:
    BpReply(Request, Epoch, Authority, result, Reply);
    BpRelease(irql);
    if (fresh != NULL) { fresh->Uses = 0; BpDestroy(fresh); }
    if (canonical != NULL) ExFreePoolWithTag(canonical, BP_TAG);
    return status;
}

_Use_decl_annotations_
NTSTATUS SafeUploadBoundPublicationControl(PVOID Cookie, PVOID Input, ULONG InputLength,
    PVOID Output, ULONG OutputLength, PULONG Returned)
{
    PBP_CONTROL_WORK work = NULL;
    BP_INPUT *request;
    PSAFEUPLOAD_BOUND_PUBLICATION_FACTS_PAGE page = NULL;
    PSAFEUPLOAD_BOUND_PUBLICATION_REPLY reply;
    PBP_RECORD retired = NULL;
    PVOID cookie = NULL;
    PEPROCESS process = NULL;
    LONG64 epoch = 0;
    UINT64 authority;
    ULONG processId = 0, phase;
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    KIRQL irql;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    *Returned = 0;
    if (Input == NULL || Output == NULL ||
        (InputLength != sizeof(request->Mutation) && InputLength != sizeof(request->Facts))) return STATUS_INVALID_BUFFER_SIZE;
    work = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*work), BP_TAG);
    if (work == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(work, sizeof(*work));
    request = &work->Request;
    reply = &work->Reply;
    try {
        ProbeForRead(Input, InputLength, 4);
        RtlCopyMemory(request, Input, InputLength);
    } except (EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); goto FreeWork; }
    phase = request->Mutation.Phase;
    if (request->Mutation.Control.Version != SAFEUPLOAD_PROTOCOL_VERSION || request->Mutation.Control.StructSize != InputLength ||
        request->Mutation.Control.Command != SAFEUPLOAD_CONTROL_BOUND_PUBLICATION || request->Mutation.Control.Reserved != 0 ||
        request->Mutation.ExtensionVersion != SAFEUPLOAD_BOUND_PUBLICATION_VERSION || phase < 1 || phase > 5 ||
        InputLength != (phase <= 3 ? sizeof(request->Mutation) : sizeof(request->Facts)) ||
        OutputLength != (phase == SAFEUPLOAD_BOUND_PUBLICATION_FACTS ? sizeof(*page) : sizeof(*reply))) goto FreeWork;
    if (!BpEnter()) { status = STATUS_DEVICE_NOT_READY; goto FreeWork; }
    if (!SafeUploadConnectionGetAuthenticatedIdentity(Cookie, &cookie, &epoch, &processId) ||
        !SafeUploadConnectionPinAuthenticatedProcess(cookie, epoch, &process)) {
        ExReleaseRundownProtection(&BpCalls); status = STATUS_ACCESS_DENIED; goto FreeWork;
    }
    authority = SafeUploadStageProtocolNativeAuthority();
    if (process != PsGetCurrentProcess() || authority == 0) { status = STATUS_ACCESS_DENIED; goto Exit; }
    if (phase <= 3) {
        status = BpMutation(&request->Mutation, cookie, process, (UINT64)epoch, authority, reply);
    } else if (phase == SAFEUPLOAD_BOUND_PUBLICATION_FACTS) {
        const SAFEUPLOAD_BOUND_PUBLICATION_FACTS_REQUEST *q = &request->Facts;
        PLIST_ENTRY link;
        ULONG index = 0;
        if (q->Reserved != 0 || q->StartIndex > SAFEUPLOAD_BOUND_PUBLICATION_MAX_RECORDS ||
            (q->ExpectedRevision == 0 ? q->StartIndex != 0 || q->ExpectedConnectionEpoch != 0 ||
                !BpZero(&q->ExpectedDriverInstanceId, sizeof(GUID)) : q->ExpectedConnectionEpoch != (UINT64)epoch ||
                !BpEqual(&q->ExpectedDriverInstanceId, &BpDriver, sizeof(GUID)))) goto Exit;
        page = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*page), BP_TAG);
        if (page == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
        RtlZeroMemory(page, sizeof(*page));
        BpAcquire(&irql);
        status = !BpReplayUsable ? STATUS_INTEGER_OVERFLOW :
            (q->ExpectedRevision != 0 && q->ExpectedRevision != BpRevision ? STATUS_RETRY : STATUS_SUCCESS);
        if (status == STATUS_SUCCESS && q->StartIndex > BpCount) status = STATUS_INVALID_PARAMETER;
        if (status == STATUS_SUCCESS) {
            page->ExtensionVersion = SAFEUPLOAD_BOUND_PUBLICATION_VERSION; page->StructSize = sizeof(*page);
            page->DriverInstanceId = BpDriver; page->ConnectionEpoch = (UINT64)epoch;
            page->Revision = BpRevision; page->OsBootSequence = BpBoot; page->StartIndex = q->StartIndex;
            for (link = BpRecords.Flink; link != &BpRecords; link = link->Flink) {
                PBP_RECORD r = CONTAINING_RECORD(link, BP_RECORD, Link);
                if (index++ < q->StartIndex) continue;
                if (page->Count == SAFEUPLOAD_BOUND_PUBLICATION_PAGE_ROWS) break;
                page->Rows[page->Count++] = r->Facts;
            }
            page->Complete = q->StartIndex + page->Count == BpCount ? 1 : 0;
        }
        BpRelease(irql);
    } else {
        PBP_RECORD r;
        if (request->Ack.ExpectedRevision == 0 || BpZero(&request->Ack.CreateNonce, sizeof(GUID)) ||
            !BpEqual(&request->Ack.DriverInstanceId, &BpDriver, sizeof(GUID))) goto Exit;
        BpAcquire(&irql);
        r = BpFind(&request->Ack.CreateNonce);
        /* A missing row has no immutable echo. Return a failed transport;
         * lost ACK recovery uses the later complete replay and durable receipt. */
        if (r == NULL) status = STATUS_NOT_FOUND;
        else {
            ULONG result = BP_REJECTED;
            if (BpReplayUsable && request->Ack.ExpectedRevision == BpRevision && BpTerminal(r)) {
                RemoveEntryList(&r->Link); --BpCount; r->Uses = 0; retired = r;
                BpChangedLocked(); result = BP_ACKNOWLEDGED;
            }
            BpReply(&r->Facts.Create, (UINT64)epoch, authority, result, reply);
            reply->Phase = SAFEUPLOAD_BOUND_PUBLICATION_ACK; status = STATUS_SUCCESS;
        }
        BpRelease(irql);
    }
    if (status != STATUS_SUCCESS) goto Exit;
    if (!SafeUploadConnectionIsAuthenticatedIdentity(cookie, epoch)) { status = STATUS_ACCESS_DENIED; goto Exit; }
    /* Repeat the concrete size proof at each copy site: a Facts page is
     * 16,960 bytes, whereas mutation/ACK replies are only 128 bytes. Both
     * kernel source buffers were fully zeroed before any fields were filled. */
    if (page != NULL) {
        if (OutputLength != sizeof(*page)) { status = STATUS_INVALID_BUFFER_SIZE; goto Exit; }
        try {
            /* Probe only: same C6001 convention as StageNativeObservation.c. */
#pragma warning(suppress: 6001)
            ProbeForWrite(Output, sizeof(*page), 4);
            RtlCopyMemory(Output, page, sizeof(*page));
            *Returned = sizeof(*page);
        } except (EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
    } else {
        if (OutputLength != sizeof(*reply)) { status = STATUS_INVALID_BUFFER_SIZE; goto Exit; }
        try {
#pragma warning(suppress: 6001)
            ProbeForWrite(Output, sizeof(*reply), 4);
            RtlCopyMemory(Output, reply, sizeof(*reply));
            *Returned = sizeof(*reply);
        } except (EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
    }
Exit:
    if (page != NULL) ExFreePoolWithTag(page, BP_TAG);
    if (retired != NULL) BpDestroy(retired);
    SafeUploadConnectionReleaseAuthenticatedProcess(cookie, process);
    ExReleaseRundownProtection(&BpCalls);
FreeWork:
    ExFreePoolWithTag(work, BP_TAG);
    return status;
}

static FLT_PREOP_CALLBACK_STATUS BpDeny(PFLT_CALLBACK_DATA Data)
{
    if (FLT_IS_FASTIO_OPERATION(Data)) return FLT_PREOP_DISALLOW_FASTIO;
    if (Data->Iopb->MajorFunction == IRP_MJ_QUERY_OPEN) return FLT_PREOP_DISALLOW_FSFILTER_IO;
    Data->IoStatus.Status = STATUS_ACCESS_DENIED; Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}
static BOOLEAN BpActor(PBP_RECORD r, PFLT_CALLBACK_DATA Data)
{
    return Data->RequestorMode == UserMode && FltGetRequestorProcess(Data) == r->Creator &&
        PsGetCurrentProcess() == r->Creator && !SafeUploadStageMandatoryTeardownActive();
}
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS BpCheckCreate(_In_ PBP_RECORD r, _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _Outptr_result_nullonfailure_ PSECURITY_DESCRIPTOR *Security,
    _Out_ PULONG Bytes)
{
    PIO_SECURITY_CONTEXT sc = Data->Iopb->Parameters.Create.SecurityContext;
    PACCESS_STATE access;
    ULONG sessionId = 0;
    PSECURITY_DESCRIPTOR captured = NULL;
    ULONG capturedBytes = 0;
    NTSTATUS status;
    PAGED_CODE();
    *Security = NULL; *Bytes = 0;
    if (!BpActor(r, Data) || !FLT_IS_IRP_OPERATION(Data) || Objects->Transaction != NULL ||
        Objects->Instance != r->Source.Instance || Objects->FileObject->RelatedFileObject == NULL ||
        Data->Iopb->OperationFlags != 0 || sc == NULL || sc->AccessState == NULL ||
        sc->DesiredAccess != BP_ACCESS || Data->Iopb->Parameters.Create.Options != ((FILE_CREATE << 24) | BP_OPTIONS) ||
        Data->Iopb->Parameters.Create.ShareAccess != 0 ||
        Data->Iopb->Parameters.Create.FileAttributes != FILE_ATTRIBUTE_NORMAL ||
        Data->Iopb->Parameters.Create.EaLength != 0 || Data->Iopb->Parameters.Create.AllocationSize.QuadPart != 0)
        return STATUS_ACCESS_DENIED;
    access = sc->AccessState;
    if (access->OriginalDesiredAccess != BP_ACCESS ||
        (access->RemainingDesiredAccess | access->PreviouslyGrantedAccess) != BP_ACCESS ||
        access->SubjectSecurityContext.ClientToken != NULL || access->SubjectSecurityContext.PrimaryToken != r->Token)
        return STATUS_ACCESS_DENIED;
    status = BpTokenSession(r->Token, &sessionId);
    if (status != STATUS_SUCCESS) return NT_SUCCESS(status) ? STATUS_ACCESS_DENIED : status;
    if (sessionId != r->Facts.OriginalSessionId) return STATUS_ACCESS_DENIED;
    if (!BpLeafEqual(Objects->FileObject->FileName.Buffer, Objects->FileObject->FileName.Length,
        r->Facts.Create.TemporaryLeaf, r->Facts.Create.TemporaryLeafBytes, TRUE)) return STATUS_OBJECT_NAME_INVALID;
    status = BpAnchors(r, Objects->FileObject->RelatedFileObject);
    if (status != STATUS_SUCCESS) return NT_SUCCESS(status) ? STATUS_ACCESS_DENIED : status;
    if (!SafeUploadStagePublicationSourceCurrent(&r->Facts.Create, &r->Source)) return STATUS_DEVICE_NOT_READY;
    status = BpCaptureSecurity(access->SecurityDescriptor, &captured, &capturedBytes);
    if (status != STATUS_SUCCESS && NT_SUCCESS(status)) status = STATUS_INVALID_SECURITY_DESCR;
    if (status == STATUS_SUCCESS && (captured == NULL || capturedBytes != r->Source.ConstructionBytes ||
        !BpEqual(captured, r->Source.Construction, capturedBytes))) {
        SafeUploadStagePublicRecordWriterRefusal(StageWriterPublicationSecurityNotEquivalent);
        status = STATUS_INVALID_SECURITY_DESCR;
    }
    if (status == STATUS_SUCCESS) {
        *Security = captured; *Bytes = capturedBytes;
    } else if (captured != NULL) ExFreePoolWithTag(captured, BP_TAG);
    return status;
}
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS BpCheckRename(_In_ PBP_RECORD r, _In_ PFLT_CALLBACK_DATA Data,
    _Out_ PSAFEUPLOAD_STAGE_IDENTITY_V19 Observed, _Out_ PNTSTATUS QueryStatus,
    _Out_ PBOOLEAN ObservationComplete)
{
    PFILE_RENAME_INFORMATION rename = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    ULONG length = Data->Iopb->Parameters.SetFileInformation.Length;
    ULONG header = FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName);
    PFILE_OBJECT parent = NULL;
    SAFEUPLOAD_STAGE_IDENTITY_V19 source;
    NTSTATUS status = STATUS_ACCESS_DENIED;
    PAGED_CODE();
    RtlZeroMemory(Observed, sizeof(*Observed));
    *QueryStatus = 0; *ObservationComplete = FALSE;
    if (!BpActor(r, Data) || !FLT_IS_IRP_OPERATION(Data) || Data->Iopb->OperationFlags != 0 ||
        Data->Iopb->Parameters.SetFileInformation.FileInformationClass != FileRenameInformationEx ||
        rename == NULL || length < header || rename->FileNameLength != r->Facts.Create.DestinationLeafBytes ||
        rename->FileNameLength > length - header || rename->RootDirectory == NULL ||
        rename->Flags != (FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS) ||
        !BpEqual(rename->FileName, r->Facts.Create.DestinationLeaf, rename->FileNameLength)) return status;
    /* UserMode handle lookup validates the original service handle; this
     * metadata reference has no file-data, delete or access-state authority. */
    status = ObReferenceObjectByHandle(rename->RootDirectory, 0, *IoFileObjectType,
        UserMode, (PVOID *)&parent, NULL);
    if (status != STATUS_SUCCESS) return status;
    status = BpAnchors(r, parent);
    ObDereferenceObject(parent);
    if (status != STATUS_SUCCESS) return status;
    status = BpIdentity(r->Source.Instance, Data->Iopb->TargetFileObject, FALSE, &source, NULL);
    if (status != STATUS_SUCCESS || !BpEqual(&source, &r->Facts.TemporaryIdentity, sizeof(source))) return STATUS_FILE_INVALID;
    if (!SafeUploadStagePublicationSourceCurrent(&r->Facts.Create, &r->Source)) return STATUS_DEVICE_NOT_READY;
    status = BpObserve(r, Observed, QueryStatus);
    if (status != STATUS_SUCCESS) return status;
    *ObservationComplete = TRUE;
    return BpAnchors(r, NULL);
}
static BOOLEAN BpNamespaceMutation(PFLT_CALLBACK_DATA Data)
{
    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
        ACCESS_MASK access = Data->Iopb->Parameters.Create.SecurityContext != NULL ?
            Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess : MAXIMUM_ALLOWED;
        return (Data->Iopb->Parameters.Create.Options >> 24) != FILE_OPEN ||
            FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE) ||
            (access & (DELETE | FILE_DELETE_CHILD | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
                FILE_WRITE_ATTRIBUTES | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL | MAXIMUM_ALLOWED)) != 0;
    }
    if (Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION) {
        FILE_INFORMATION_CLASS c = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
        return c != FilePositionInformation;
    }
    return Data->Iopb->MajorFunction == IRP_MJ_SET_SECURITY ||
        Data->Iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL;
}

_Use_decl_annotations_
FLT_PREOP_CALLBACK_STATUS SafeUploadBoundPublicationPre(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, PVOID *Context, PBOOLEAN Handled)
{
    PBP_RECORD r = NULL;
    PLIST_ENTRY link;
    KIRQL irql;
    UCHAR major = Data->Iopb->MajorFunction;
    FLT_PREOP_CALLBACK_STATUS result = FLT_PREOP_SUCCESS_NO_CALLBACK;
    BOOLEAN validateCreate = FALSE, validateRename = FALSE;
    BOOLEAN sizeCaptured = FALSE, deleteCaptured = FALSE;
    BOOLEAN namespaceMutation = BpNamespaceMutation(Data);
    LARGE_INTEGER capturedSize = {0};
    WCHAR capturedLeaf[64] = {0};
    USHORT capturedLeafBytes = 0;
    /* Capture small buffered inputs before acquiring the spin lock. */
    if (major == IRP_MJ_CREATE && Objects->FileObject != NULL) {
        try {
            USHORT bytes = Objects->FileObject->FileName.Length;
            if (bytes != 0 && bytes < sizeof(capturedLeaf) && (bytes & 1) == 0 &&
                Objects->FileObject->FileName.Buffer != NULL) {
                RtlCopyMemory(capturedLeaf, Objects->FileObject->FileName.Buffer, bytes);
                capturedLeafBytes = bytes;
            }
        } except (EXCEPTION_EXECUTE_HANDLER) { capturedLeafBytes = 0; }
    }
    if (major == IRP_MJ_SET_INFORMATION) {
        FILE_INFORMATION_CLASS cls = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
        PVOID input = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        ULONG length = Data->Iopb->Parameters.SetFileInformation.Length;
        try {
            if (input != NULL && (cls == FileEndOfFileInformation || cls == FileAllocationInformation) && length == sizeof(capturedSize)) {
                RtlCopyMemory(&capturedSize, input, sizeof(capturedSize)); sizeCaptured = TRUE;
            } else if (input != NULL && cls == FileDispositionInformation && length == sizeof(FILE_DISPOSITION_INFORMATION))
                deleteCaptured = ((PFILE_DISPOSITION_INFORMATION)input)->DeleteFile == TRUE;
        } except (EXCEPTION_EXECUTE_HANDLER) { sizeCaptured = FALSE; deleteCaptured = FALSE; }
    }
    *Context = NULL; *Handled = FALSE;
    if (!BpEnter()) return result;
    BpAcquire(&irql);
    for (link = BpRecords.Flink; link != &BpRecords; link = link->Flink) {
        PBP_RECORD candidate = CONTAINING_RECORD(link, BP_RECORD, Link);
        if (Objects->FileObject != NULL && candidate->Object == Objects->FileObject &&
            candidate->Source.Instance == Objects->Instance) { r = candidate; break; }
        if (major == IRP_MJ_CREATE && Objects->FileObject != NULL && candidate->Creator == FltGetRequestorProcess(Data) &&
            (candidate->Source.Instance == NULL || candidate->Source.Instance == Objects->Instance) &&
            capturedLeafBytes != 0 && capturedLeafBytes == candidate->Facts.Create.TemporaryLeafBytes &&
            BpEqual(capturedLeaf, candidate->Facts.Create.TemporaryLeaf, capturedLeafBytes)) {
            r = candidate; break;
        }
    }
    /* Matched publication attempts are subject to OTHER reservations too.
     * Pending pre-CREATE validation is rechecked under this same lock. */
    if (namespaceMutation && BpOtherReservation(r, Objects->Instance)) {
        *Handled = TRUE; result = BpDeny(Data); goto Exit;
    }
    if (r == NULL) {
        goto Exit;
    }
    *Handled = TRUE;
    if (major == IRP_MJ_CLOSE) {
        /* Remove the non-owning key BEFORE lower CLOSE/address reuse. */
        r->CancelledClose = FlagOn(Objects->FileObject->Flags, FO_FILE_OPEN_CANCELLED) &&
            !FlagOn(Objects->FileObject->Flags, FO_HANDLE_CREATED);
        r->Object = NULL; r->ClosePending = TRUE;
        BpCallback(r, 1); *Context = r; result = FLT_PREOP_SUCCESS_WITH_CALLBACK; goto Exit;
    }
    if (major == IRP_MJ_CLEANUP) {
        BpFence(r); BpCallback(r, 1); *Context = r;
        result = FLT_PREOP_SUCCESS_WITH_CALLBACK; goto Exit;
    }
    if (major == IRP_MJ_CREATE) {
        if (irql != PASSIVE_LEVEL || r->CreateResult != BP_PREPARED ||
            (r->Facts.Flags & BP_CREATE_CONSUMED) || !BpChannelCurrent(r)) { result = BpDeny(Data); goto Exit; }
        /* At most one contender can leave the lock for security/anchor I/O. */
        r->Facts.Flags |= BP_CREATE_CONSUMED;
        r->CreateResult = BP_CONSUMED; BpCallback(r, 1); validateCreate = TRUE;
        goto Exit;
    }
    if (FLT_IS_FASTIO_OPERATION(Data) || !FLT_IS_IRP_OPERATION(Data) ||
        (major != IRP_MJ_QUERY_INFORMATION && major != IRP_MJ_QUERY_SECURITY &&
         major != IRP_MJ_QUERY_VOLUME_INFORMATION && major != IRP_MJ_READ && !BpActor(r, Data))) {
        result = BpDeny(Data); goto Exit;
    }
    if (major == IRP_MJ_QUERY_INFORMATION || major == IRP_MJ_QUERY_SECURITY || major == IRP_MJ_QUERY_VOLUME_INFORMATION) goto Exit;
    /* No reading of a service write-only temporary, MDL, mapping, paging,
     * security/EA/reparse/link/ioctl or other mutator escape hatch. */
    if (major == IRP_MJ_WRITE || major == IRP_MJ_FLUSH_BUFFERS || major == IRP_MJ_SET_INFORMATION) {
        FILE_INFORMATION_CLASS c = major == IRP_MJ_SET_INFORMATION ?
            Data->Iopb->Parameters.SetFileInformation.FileInformationClass : (FILE_INFORMATION_CLASS)0;
        if (major == IRP_MJ_SET_INFORMATION && c == FileRenameInformationEx) {
            if (r->RenameResult == BP_PREPARED && r->NameReserved && BpChannelCurrent(r) &&
                (r->Facts.Flags & (BP_FENCED | BP_DRAINED | BP_FLUSH_SUCCEEDED)) == (BP_FENCED | BP_DRAINED | BP_FLUSH_SUCCEEDED) &&
                !(r->Facts.Flags & (BP_RENAME_CONSUMED | BP_COVERAGE_LOST | BP_LAST_CLEANUP)) &&
                r->Facts.InFlightWrites == 0 && r->Facts.InFlightMutators == 0) {
                r->Facts.Flags |= BP_RENAME_CONSUMED; r->RenameResult = BP_CONSUMED;
                BpCallback(r, 1); validateRename = TRUE; goto Exit;
            }
        } else if (major == IRP_MJ_SET_INFORMATION && c == FileDispositionInformation) {
            PVOID cookie = NULL;
            LONG64 epoch = 0;
            ULONG pid = 0;
            if (r->Revoked && r->Exposed && deleteCaptured &&
                (r->Facts.Flags & (BP_CLEANUP_ARMED | BP_FENCED | BP_DRAINED)) == (BP_CLEANUP_ARMED | BP_FENCED | BP_DRAINED) &&
                !(r->Facts.Flags & (BP_CLEANUP_FORWARDED | BP_CLEANUP_NOT_FORWARDED | BP_RENAME_ACCEPTED | BP_COVERAGE_LOST | BP_LAST_CLEANUP)) &&
                (!(r->Facts.Flags & BP_RENAME_FORWARDED) ||
                ((r->Facts.Flags & BP_RENAME_KNOWN) && r->Facts.RenameStatus < 0)) &&
                SafeUploadConnectionGetAuthenticatedIdentity(r->Cookie, &cookie, &epoch, &pid) && cookie == r->Cookie &&
                (UINT64)epoch == r->Facts.OriginalConnectionEpoch) {
                r->Facts.Flags |= BP_CLEANUP_FORWARDED; BpCallback(r, 1);
                *Context = r; result = FLT_PREOP_SUCCESS_WITH_CALLBACK; goto Exit;
            }
        } else if (r->Exposed && !(r->Facts.Flags & (BP_LAST_CLEANUP | BP_COVERAGE_LOST)) &&
            (major == IRP_MJ_FLUSH_BUFFERS ||
             (!(r->Facts.Flags & BP_FENCED) && BpChannelCurrent(r) &&
              ((major == IRP_MJ_WRITE && FlagOn(Data->Iopb->IrpFlags, IRP_NOCACHE) &&
                !FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO) && Data->Iopb->MinorFunction == 0) ||
               (major == IRP_MJ_SET_INFORMATION && (c == FileEndOfFileInformation || c == FileAllocationInformation)))))) {
            BOOLEAN valid = TRUE;
            if (major == IRP_MJ_WRITE) {
                LONGLONG offset = Data->Iopb->Parameters.Write.ByteOffset.QuadPart;
                valid = offset >= 0 && offset <= r->WriteLimit && r->Source.SectorSize != 0 &&
                    ((UINT64)offset % r->Source.SectorSize) == 0 &&
                    (Data->Iopb->Parameters.Write.Length % r->Source.SectorSize) == 0 &&
                    Data->Iopb->Parameters.Write.Length <= (UINT64)(r->WriteLimit - offset);
            } else if (major == IRP_MJ_SET_INFORMATION) {
                valid = sizeCaptured && capturedSize.QuadPart ==
                    (c == FileEndOfFileInformation ? r->Facts.Create.MeasuredLength : r->WriteLimit);
            }
            if (valid && r->Facts.InFlightWrites < MAXULONG && r->Facts.InFlightMutators < MAXULONG) {
                if (major == IRP_MJ_WRITE) ++r->Facts.InFlightWrites;
                else if (major != IRP_MJ_FLUSH_BUFFERS) ++r->Facts.InFlightMutators;
                /* Flush after a completed fence cannot change bytes, but
                 * participates in rundown; do not claim DataDrained meanwhile. */
                if (major != IRP_MJ_FLUSH_BUFFERS) r->Facts.Flags &= ~BP_DRAINED;
                BpCallback(r, 1); *Context = r; result = FLT_PREOP_SUCCESS_WITH_CALLBACK; goto Exit;
            }
        }
    }
    result = BpDeny(Data);
Exit:
    BpRelease(irql);
    if (validateCreate || validateRename) {
        NTSTATUS status = STATUS_ACCESS_DENIED, queryStatus = 0;
        BOOLEAN observationComplete = FALSE;
        PSECURITY_DESCRIPTOR security = NULL;
        ULONG securityBytes = 0;
        SAFEUPLOAD_STAGE_IDENTITY_V19 observed;
        RtlZeroMemory(&observed, sizeof(observed));
        if (KeGetCurrentIrql() == PASSIVE_LEVEL && IoGetTopLevelIrp() == NULL) {
            try {
                if (validateCreate) status = BpCheckCreate(r, Data, Objects, &security, &securityBytes);
                else status = BpCheckRename(r, Data, &observed, &queryStatus, &observationComplete);
            } except (EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
        }
        BpAcquire(&irql);
        if (validateRename) r->Facts.TargetStatus = queryStatus;
        if (validateRename && observationComplete) {
            r->Facts.ObservedPublicIdentity = observed;
            r->Facts.Flags |= BP_TARGET_KNOWN;
            if (BpZero(&observed, sizeof(observed))) r->Facts.Flags |= BP_TARGET_ABSENT;
            if (!BpEqual(&observed, &r->Facts.Rename.ExpectedPublicIdentity, sizeof(observed))) status = STATUS_FILE_INVALID;
        }
        if (status == STATUS_SUCCESS && BpChannelCurrent(r) && !FltIsIoCanceled(Data) &&
            !BpOtherReservation(r, Objects->Instance) &&
            (validateCreate || (r->NameReserved && (r->Facts.Flags & BP_DRAINED) &&
                r->Facts.InFlightWrites == 0 && r->Facts.InFlightMutators == 0))) {
            if (validateCreate) {
                r->CallbackSecurity = security; security = NULL; r->CallbackSecurityBytes = securityBytes;
                r->Object = Objects->FileObject; r->Facts.Flags |= BP_CREATE_FORWARDED;
            } else r->Facts.Flags |= BP_RENAME_FORWARDED;
            *Context = r; result = FLT_PREOP_SUCCESS_WITH_CALLBACK;
        } else {
            r->Facts.Flags |= validateCreate ? BP_CREATE_NOT_FORWARDED : BP_RENAME_NOT_FORWARDED;
            BpRevoke(r); BpCallback(r, -1); result = BpDeny(Data);
        }
        BpChangedLocked();
        BpRelease(irql);
        if (security != NULL) ExFreePoolWithTag(security, BP_TAG);
    }
    ExReleaseRundownProtection(&BpCalls);
    return result;
}

_Use_decl_annotations_
BOOLEAN SafeUploadBoundPublicationPost(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS Objects,
    PVOID Context, FLT_POST_OPERATION_FLAGS Flags)
{
    PBP_RECORD r = NULL;
    PLIST_ENTRY link;
    KIRQL irql;
    UCHAR major = Data->Iopb->MajorFunction;
    BOOLEAN draining = FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) != 0;
    NTSTATUS nativeStatus = Data->IoStatus.Status, identityStatus = STATUS_DEVICE_NOT_READY, identityQueryStatus = 0;
    UINT64 information = (UINT64)Data->IoStatus.Information;
    SAFEUPLOAD_STAGE_IDENTITY_V19 id;
    BOOLEAN accepted = FALSE, expose = FALSE;
    if (Context == NULL || !BpEnter()) return FALSE;
    RtlZeroMemory(&id, sizeof(id));
    BpAcquire(&irql);
    for (link = BpRecords.Flink; link != &BpRecords; link = link->Flink) {
        PBP_RECORD candidate = CONTAINING_RECORD(link, BP_RECORD, Link);
        if (Context == candidate) { r = candidate; break; }
    }
    BpRelease(irql);
    if (r == NULL) { ExReleaseRundownProtection(&BpCalls); return FALSE; }
    if (major == IRP_MJ_CREATE && !draining && nativeStatus != STATUS_PENDING &&
        nativeStatus == STATUS_SUCCESS && information == FILE_CREATED) {
        accepted = TRUE;
        if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
            identityStatus = BpIdentity(Objects->Instance, Objects->FileObject, FALSE, &id, &identityQueryStatus);
            if (identityStatus == STATUS_SUCCESS && !BpId(&id, r->Facts.Create.VolumeRootIdentity.VolumeSerialNumber))
                identityStatus = STATUS_FILE_INVALID;
            if (identityStatus == STATUS_SUCCESS) {
                PIO_SECURITY_CONTEXT sc = Data->Iopb->Parameters.Create.SecurityContext;
                expose = BpStoredSecurity(r, Objects->FileObject) == STATUS_SUCCESS &&
                    sc != NULL && sc->AccessState != NULL && sc->DesiredAccess == BP_ACCESS &&
                    sc->AccessState->PreviouslyGrantedAccess == BP_ACCESS && sc->AccessState->RemainingDesiredAccess == 0 &&
                    Objects->FileObject->WriteAccess && Objects->FileObject->DeleteAccess && !Objects->FileObject->ReadAccess &&
                    FlagOn(Objects->FileObject->Flags, FO_NO_INTERMEDIATE_BUFFERING) &&
                    FlagOn(Objects->FileObject->Flags, FO_WRITE_THROUGH) &&
                    FlagOn(Objects->FileObject->Flags, FO_SYNCHRONOUS_IO);
            }
        }
    }
    BpAcquire(&irql);
    if (draining) { r->Facts.Flags |= BP_COVERAGE_LOST; BpRevoke(r); }
    if (major == IRP_MJ_CREATE) {
        if (!draining && nativeStatus != STATUS_PENDING) {
            r->Facts.CreateStatus = nativeStatus; r->Facts.CreateInformation = information;
            r->Facts.Flags |= BP_CREATE_KNOWN;
            if (accepted) r->Facts.Flags |= BP_CREATE_ACCEPTED;
            else if (nativeStatus < 0 && (information == 0 ||
                (nativeStatus == STATUS_OBJECT_NAME_COLLISION && information == FILE_EXISTS) ||
                ((nativeStatus == STATUS_OBJECT_NAME_NOT_FOUND || nativeStatus == STATUS_OBJECT_PATH_NOT_FOUND) && information == FILE_DOES_NOT_EXIST)))
                r->Object = NULL;
        }
        if (accepted) {
            r->Facts.IdentityStatus = identityQueryStatus;
            if (identityStatus == STATUS_SUCCESS) { r->Facts.TemporaryIdentity = id; r->Facts.Flags |= BP_ID_KNOWN; }
        }
        expose = expose && BpChannelCurrent(r) && !(r->Facts.Flags & (BP_FENCED | BP_COVERAGE_LOST));
        r->Exposed = expose;
        if (!expose) BpRevoke(r);
    } else if (major == IRP_MJ_CLOSE) {
        r->ClosePending = FALSE;
        /* Exact upper-filter cancellation, with no handle ever created, is
         * local lifetime evidence. Ordinary CLOSE alone is not. */
        if (r->CancelledClose && !draining && (r->Facts.Flags & BP_ID_KNOWN) && !(r->Facts.Flags & BP_COVERAGE_LOST))
            r->Facts.Flags |= BP_LAST_CLEANUP;
    } else if (major == IRP_MJ_CLEANUP) {
        if (!draining && (r->Facts.Flags & BP_ID_KNOWN) && !(r->Facts.Flags & BP_COVERAGE_LOST))
            r->Facts.Flags |= BP_LAST_CLEANUP;
        BpFence(r);
    } else if (major == IRP_MJ_SET_INFORMATION &&
        Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformationEx) {
        if (!draining && nativeStatus != STATUS_PENDING) {
            r->Facts.RenameStatus = nativeStatus; r->Facts.Flags |= BP_RENAME_KNOWN;
            if (nativeStatus == STATUS_SUCCESS) r->Facts.Flags |= BP_RENAME_ACCEPTED;
        }
    } else if (major == IRP_MJ_SET_INFORMATION &&
        Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformation) {
        if (!draining && nativeStatus != STATUS_PENDING) {
            r->Facts.CleanupStatus = nativeStatus; r->Facts.Flags |= BP_CLEANUP_KNOWN;
            if (nativeStatus == STATUS_SUCCESS) r->Facts.Flags |= BP_CLEANUP_ACCEPTED;
        }
    } else {
        if (major == IRP_MJ_WRITE) { NT_ASSERT(r->Facts.InFlightWrites != 0); --r->Facts.InFlightWrites; }
        else if (major != IRP_MJ_FLUSH_BUFFERS) { NT_ASSERT(r->Facts.InFlightMutators != 0); --r->Facts.InFlightMutators; }
        if ((r->Facts.Flags & BP_FENCED) && r->Facts.InFlightWrites == 0 && r->Facts.InFlightMutators == 0)
            r->Facts.Flags |= BP_DRAINED;
    }
    BpChangedLocked();
    BpRelease(irql);
    /* Preserve native facts above even if exposure is canceled. Cancel outside
     * the lock, with the callback reference retained through reentrant CLOSE. */
    if (major == IRP_MJ_CREATE && !draining && nativeStatus == STATUS_SUCCESS && !expose) {
        if (KeGetCurrentIrql() == PASSIVE_LEVEL) FltCancelFileOpen(Objects->Instance, Objects->FileObject);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED; Data->IoStatus.Information = 0;
    }
    BpAcquire(&irql);
    BpCallback(r, -1);
    BpRelease(irql);
    /* The service's metadata/private I/O is excluded from generic namespace
     * wakes. Its accepted bound rename is a real destination change. Publish
     * only an invalidation event, outside BpLock, before dropping callback
     * rundown; native reconciliation still needs its independent exact facts. */
    if (!draining && nativeStatus == STATUS_SUCCESS && major == IRP_MJ_SET_INFORMATION &&
        Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformationEx)
        SafeUploadStageNativeNameChanged(Objects->Instance);
    ExReleaseRundownProtection(&BpCalls);
    return TRUE;
}

_Use_decl_annotations_
NTSTATUS SafeUploadBoundPublicationInitialize(const GUID *Driver, ULONG Boot)
{
    OBJECT_ATTRIBUTES attributes;
    NTSTATUS status;
    PAGED_CODE();
    KeInitializeSpinLock(&BpLock);
    InitializeListHead(&BpRecords); InitializeListHead(&BpWork);
    KeInitializeEvent(&BpChanged, NotificationEvent, FALSE);
    KeInitializeEvent(&BpWake, SynchronizationEvent, FALSE);
    ExInitializeRundownProtection(&BpCalls);
    BpDriver = *Driver; BpBoot = Boot; BpCount = 0; BpFactories = 0;
    BpRevision = 1; BpReplayUsable = TRUE; BpAccepting = TRUE; BpStopping = FALSE; BpCallsDrained = FALSE;
    BpNamespaceUnknown = FALSE;
    BpTopologyRevision = 1;
    BpThread = NULL;
    InitializeObjectAttributes(&attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = PsCreateSystemThread(&BpThread, THREAD_ALL_ACCESS, &attributes, NULL, NULL, BpWorker, NULL);
    if (status != STATUS_SUCCESS) { BpAccepting = FALSE; return status; }
    InterlockedExchange(&BpInitialized, 1);
    return STATUS_SUCCESS;
}
_Use_decl_annotations_
VOID SafeUploadBoundPublicationNamespaceCoverageLost(VOID)
{
    PLIST_ENTRY link;
    KIRQL irql;
    if (!BpEnter()) return;
    BpAcquire(&irql);
    if (!BpNamespaceUnknown) {
        BpNamespaceUnknown = TRUE;
        for (link = BpRecords.Flink; link != &BpRecords; link = link->Flink)
            BpRevoke(CONTAINING_RECORD(link, BP_RECORD, Link));
        BpChangedLocked();
    }
    BpRelease(irql);
    ExReleaseRundownProtection(&BpCalls);
}
_Use_decl_annotations_
VOID SafeUploadBoundPublicationRevokeConnection(PVOID Cookie)
{
    PLIST_ENTRY link;
    KIRQL irql;
    if (!BpEnter()) return;
    BpAcquire(&irql);
    for (link = BpRecords.Flink; link != &BpRecords; link = link->Flink) {
        PBP_RECORD r = CONTAINING_RECORD(link, BP_RECORD, Link);
        if (r->Cookie == Cookie) BpRevoke(r);
    }
    BpRelease(irql);
    ExReleaseRundownProtection(&BpCalls);
}
_Use_decl_annotations_
VOID SafeUploadBoundPublicationInstanceTeardown(PFLT_INSTANCE Instance, FLT_INSTANCE_TEARDOWN_FLAGS Reason)
{
    PLIST_ENTRY link;
    KIRQL irql;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (!BpEnter()) return;
    BpAcquire(&irql);
    /* Covers a factory holding a local Source not yet installed in the map,
     * even if the attach tombstone disappears before that factory returns. */
    if (++BpTopologyRevision == 0) BpNamespaceUnknown = TRUE;
    for (link = BpRecords.Flink; link != &BpRecords; link = link->Flink) {
        PBP_RECORD r = CONTAINING_RECORD(link, BP_RECORD, Link);
        if (r->Source.Instance != Instance) continue;
        BpRevoke(r);
        if (r->Object != NULL || r->Callbacks != 0) {
            r->Facts.Flags |= BP_COVERAGE_LOST;
            r->Facts.Flags &= ~BP_LAST_CLEANUP;
            r->Facts.TeardownReason = Reason;
            /* Remove only the non-owning lookup key. Loss is NOT last-close
             * evidence and does not retire the version/receipt/namespace hold. */
            r->Object = NULL;
            BpChangedLocked();
        }
    }
    BpRelease(irql);
    ExReleaseRundownProtection(&BpCalls);
}
_Use_decl_annotations_
BOOLEAN SafeUploadBoundPublicationNamespaceAvailable(PFLT_INSTANCE Instance)
{
    PLIST_ENTRY link;
    KIRQL irql;
    BOOLEAN available = TRUE;
    if (!BpEnter()) return TRUE; /* No publication map before initialization. */
    BpAcquire(&irql);
    for (link = BpRecords.Flink; link != &BpRecords; link = link->Flink) {
        PBP_RECORD r = CONTAINING_RECORD(link, BP_RECORD, Link);
        if (r->NameReserved && r->Source.Instance == Instance) { available = FALSE; break; }
    }
    BpRelease(irql);
    ExReleaseRundownProtection(&BpCalls);
    return available;
}
BOOLEAN SafeUploadBoundPublicationTryCloseAdmission(VOID)
{
    KIRQL irql;
    BOOLEAN closed;
    BpAcquire(&irql);
    closed = BpCount == 0 && BpFactories == 0 && !BpNamespaceUnknown;
    if (closed) BpAccepting = FALSE;
    BpRelease(irql);
    return closed;
}
VOID SafeUploadBoundPublicationReopenAdmission(VOID)
{
    KIRQL irql;
    BpAcquire(&irql);
    if (!BpStopping && !SafeUploadStageMandatoryTeardownActive()) BpAccepting = TRUE;
    BpRelease(irql);
}
VOID SafeUploadBoundPublicationCloseAdmission(VOID)
{
    PLIST_ENTRY link;
    KIRQL irql;
    BpAcquire(&irql);
    BpAccepting = FALSE; BpStopping = TRUE;
    for (link = BpRecords.Flink; link != &BpRecords; link = link->Flink)
        BpRevoke(CONTAINING_RECORD(link, BP_RECORD, Link));
    KeSetEvent(&BpWake, IO_NO_INCREMENT, FALSE);
    KeSetEvent(&BpChanged, IO_NO_INCREMENT, FALSE);
    BpRelease(irql);
}
_Use_decl_annotations_
__declspec(noinline) VOID SafeUploadBoundPublicationDrainLocal(VOID)
{
    KIRQL irql;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    SafeUploadBoundPublicationCloseAdmission();
    if (BpThread != NULL) {
        (VOID)ZwWaitForSingleObject(BpThread, FALSE, NULL);
        ZwClose(BpThread); BpThread = NULL;
    }
    for (;;) {
        PLIST_ENTRY link, next;
        LIST_ENTRY retired;
        BOOLEAN empty;
        InitializeListHead(&retired);
        BpAcquire(&irql);
        KeClearEvent(&BpChanged);
        for (link = BpRecords.Flink; link != &BpRecords; link = next) {
            PBP_RECORD r = CONTAINING_RECORD(link, BP_RECORD, Link);
            next = link->Flink;
            if (!BpTerminal(r)) continue;
            /* Local terminal drain is NOT durable ACK. Service intent remains
             * for restart. Neither timeout, missing callback nor coverage loss
             * substitutes for lifetime proof. No owned file handle to close. */
            RemoveEntryList(link); --BpCount; r->Uses = 0;
            InsertTailList(&retired, link); BpChangedLocked();
        }
        empty = BpCount == 0 && BpFactories == 0;
        BpRelease(irql);
        while (!IsListEmpty(&retired))
            BpDestroy(CONTAINING_RECORD(RemoveHeadList(&retired), BP_RECORD, Link));
        if (empty) break;
        (VOID)KeWaitForSingleObject(&BpChanged, Executive, KernelMode, FALSE, NULL);
    }
    ExWaitForRundownProtectionRelease(&BpCalls);
    BpCallsDrained = TRUE;
}
_Use_decl_annotations_
VOID SafeUploadBoundPublicationUninitialize(VOID)
{
    PAGED_CODE();
    /* Voluntary preflight proves empty; startup failure can retain refused RPCs.
     * Mandatory teardown already joined/drained while callbacks were resident. */
    if (!BpCallsDrained) SafeUploadBoundPublicationDrainLocal();
    NT_ASSERT(BpCount == 0 && BpFactories == 0);
    InterlockedExchange(&BpInitialized, 0);
}

#endif
