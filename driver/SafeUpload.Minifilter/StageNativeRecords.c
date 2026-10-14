/* T5 original-NTFS-object fallback records. The CREATE producer and service
 * exporter are connected separately. A FILE_OBJECT reference would prevent
 * CLOSE after an upper filter cancels CREATE before any handle exists. Use
 * a non-owning key, removed at CLEANUP/CLOSE or callback-coverage loss. No NTFS section
 * pointer is borrowed, no service call runs under this lock, and no receipt
 * here certifies physical deletion. Normal builds omit this module. */
#include "StageNativeRecords.h"
#include "StageNativeWire.h"
#include "Stage.h"
#include "StageBoundPublicationInternal.h"
#include "StageSecurity.h"

#if SAFEUPLOAD_STAGING_PROTOTYPE
#define NATIVE_RECORD_TAG 'nUpS'
#define NATIVE_RECORD_LIMIT ((LONG)SAFEUPLOAD_NATIVE_REPLAY_MAX_RECORDS) /* simultaneous unacked, never per boot */
#define NATIVE_PAGE_LIMIT SAFEUPLOAD_NATIVE_REPLAY_PAGE_ROWS

struct _SAFEUPLOAD_STAGE_NATIVE_RECORD {
    LIST_ENTRY Link;
    LONG References; /* NativeLock; map + producer/short callback use */
    PFLT_INSTANCE Instance;
    PFILE_OBJECT FileObject; /* non-owning exact lookup key */
    PFILE_OBJECT CreateFileObject; /* compare only while CREATE context owns its lifetime */
    BOOLEAN CreateCallbackOwned;
    BOOLEAN CloseCallbackOwned;
    BOOLEAN CloseWasCancelledBeforeHandle;
    BOOLEAN DispositionCallbackOwned;
    BOOLEAN DispositionNoNameEffect;
    PFILE_OBJECT DispositionFileObject; /* callback-owned lifetime, compare only */
    PSAFEUPLOAD_STAGE_PUBLIC_BACKEND Backend; /* combined writer owner, closed before lifetime evidence */
    PFILE_OBJECT BackendAppObject; /* local owner-release key only; never forwarding authority */
    BOOLEAN BackendOperation; /* operation rundown transferred to original disposition post */
    PSAFEUPLOAD_ADMISSION_EPOCH_TOKEN DispositionEpoch; /* acquired after queue wait; post releases */
    ULONG TombstoneCount;
    struct { ULONG Pid; LONG64 Creation; BOOLEAN Scheduled; } Tombstones[16]; /* bounded before forwarding */
    WCHAR FoldedLeaf[256]; /* computed at PASSIVE; no Unicode-table access under NativeLock */
    KSEMAPHORE DispositionGate; /* no NativeLock held while waiting */
    UINT64 NextDispositionSequence;
    SAFEUPLOAD_STAGE_NATIVE_SNAPSHOT Snapshot;
};

static KSPIN_LOCK NativeLock;
static EX_RUNDOWN_REF NativeCalls;
static LIST_ENTRY NativeRecords;
static GUID NativeDriverInstance;
static ULONG NativeBootSequence;
static PKEVENT NativeWakeEvent;
static volatile LONG NativeInitialized;
static volatile LONG NativeRecordCount;
static LONG NativeFactories; /* NativeLock: includes capture before map insertion. */
static BOOLEAN NativeAccepting;
static BOOLEAN NativeReplayUsable;
static UINT64 NativeRevision;
static KEVENT NativeLocalChanged;
static BOOLEAN NativeCallsDrained;

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS NativeReserve(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT FileObject,
    _In_ const SAFEUPLOAD_STAGE_NATIVE_BINDING *Binding, _In_opt_ PSAFEUPLOAD_STAGE_PUBLIC_BACKEND Backend,
    _Outptr_result_nullonfailure_ PSAFEUPLOAD_STAGE_NATIVE_RECORD *Record);

_IRQL_requires_(PASSIVE_LEVEL)
static VOID NativeDispositionFlush(_In_ PSAFEUPLOAD_STAGE_NATIVE_RECORD Record);
_IRQL_requires_(PASSIVE_LEVEL)
static VOID NativeDestroy(_In_ PSAFEUPLOAD_STAGE_NATIVE_RECORD Record);
_IRQL_requires_(PASSIVE_LEVEL)
static FLT_PREOP_CALLBACK_STATUS NativeDispositionPrepare(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PSAFEUPLOAD_STAGE_NATIVE_RECORD Record, _Outptr_result_maybenull_ PVOID *CompletionContext);
/* Routines that own NativeLock/BpLock across statements stay resident.
 * Entry remains PASSIVE where required for I/O; no PAGE instruction may
 * execute after the spin-lock wrapper raises IRQL. */
#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, NativeDestroy)
#pragma alloc_text(PAGE, SafeUploadStageNativeReserve)
#pragma alloc_text(PAGE, NativeDispositionFlush)
#endif

_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_raises_(DISPATCH_LEVEL)
__declspec(noinline) static VOID NativeAcquire(_Out_ _At_(*Irql, _IRQL_saves_) PKIRQL Irql)
{ KeAcquireSpinLock(&NativeLock, Irql); }

_IRQL_requires_(DISPATCH_LEVEL)
__declspec(noinline) static VOID NativeRelease(_In_ _IRQL_restores_ KIRQL Irql)
{ KeReleaseSpinLock(&NativeLock, Irql); }

static BOOLEAN NativeEnter(VOID)
{
    if (InterlockedCompareExchange(&NativeInitialized, 0, 0) == 0) return FALSE;
    return ExAcquireRundownProtection(&NativeCalls);
}

/* NativeLock. Stop replay on wrap rather than reusing an absence revision. */
static VOID NativeChanged(VOID)
{
    NativeRevision += 1;
    if (NativeRevision == 0) NativeReplayUsable = FALSE;
    KeSetEvent(&NativeLocalChanged, IO_NO_INCREMENT, FALSE);
}

static VOID NativeWake(VOID)
{ KeSetEvent(NativeWakeEvent, IO_NO_INCREMENT, FALSE); }

static BOOLEAN NativeScheduled(const SAFEUPLOAD_STAGE_NATIVE_BINDING *Binding)
{ return FlagOn(Binding->CreateOptions, FILE_DELETE_ON_CLOSE) != 0; }

/* No native data lifetime is owned by this ordinary-read record. In-flight
 * binding/callbacks and future disposition/cleanup obligations still veto. */
static BOOLEAN NativeOrdinaryIdle(PSAFEUPLOAD_STAGE_NATIVE_RECORD Record)
{
    return !NativeScheduled(&Record->Snapshot.Binding) && Record->Snapshot.PublicOpenConfirmed &&
        Record->References == 1 && Record->Backend == NULL && !Record->CreateCallbackOwned && !Record->CloseCallbackOwned &&
        !Record->DispositionCallbackOwned && !Record->Snapshot.PublicCleanupOutstanding &&
        Record->Snapshot.PublicOperation.Sequence == 0;
}

static BOOLEAN NativeGuidEqual(const GUID *Left, const GUID *Right)
{ return RtlEqualMemory(Left, Right, sizeof(*Left)); }

/* The binding is immutable. Compare defined fields, not C padding or unused
 * SID/name tail bytes. Generation and observed grant are separate facts. */
static BOOLEAN NativeBindingEqual(const SAFEUPLOAD_STAGE_NATIVE_BINDING *Left,
    const SAFEUPLOAD_STAGE_NATIVE_BINDING *Right)
{
    const SAFEUPLOAD_STAGE_PUBLIC_BINDING *a = &Left->Public, *b = &Right->Public;
    return NativeGuidEqual(&Left->DriverInstanceId, &Right->DriverInstanceId) &&
        NativeGuidEqual(&Left->TransferId, &Right->TransferId) &&
        NativeGuidEqual(&Left->RequestNonce, &Right->RequestNonce) &&
        NativeGuidEqual(&Left->OperationId, &Right->OperationId) &&
        Left->ConnectionEpoch == Right->ConnectionEpoch && Left->OsBootSequence == Right->OsBootSequence &&
        Left->CreateOptions == Right->CreateOptions &&
        a->OriginalDesiredAccess == b->OriginalDesiredAccess && a->OriginalShareAccess == b->OriginalShareAccess &&
        a->CallerProcessId == b->CallerProcessId && a->CallerProcessCreationTime == b->CallerProcessCreationTime &&
        a->CallerSessionId == b->CallerSessionId && a->CallerSidBytes == b->CallerSidBytes &&
        a->ParentCaseSensitive == b->ParentCaseSensitive && a->CanonicalLeafBytes == b->CanonicalLeafBytes &&
        RtlEqualMemory(&a->VolumeRootIdentity, &b->VolumeRootIdentity, sizeof(FILE_ID_INFORMATION)) &&
        NativeGuidEqual(&a->MountManagerVolumeId, &b->MountManagerVolumeId) &&
        RtlEqualMemory(&a->ParentIdentity, &b->ParentIdentity, sizeof(FILE_ID_INFORMATION)) &&
        RtlEqualMemory(&a->PublicIdentity, &b->PublicIdentity, sizeof(FILE_ID_INFORMATION)) &&
        RtlEqualMemory(a->CallerSid, b->CallerSid, a->CallerSidBytes) &&
        RtlEqualMemory(a->CanonicalLeaf, b->CanonicalLeaf, a->CanonicalLeafBytes);
}

static BOOLEAN NativeBindingValid(const SAFEUPLOAD_STAGE_NATIVE_BINDING *Binding)
{
    static const GUID zero = {0};
    static const FILE_ID_128 zeroId = {0};
    const SAFEUPLOAD_STAGE_PUBLIC_BINDING *p = &Binding->Public;
    ULONG i;
    if (!NativeGuidEqual(&Binding->DriverInstanceId, &NativeDriverInstance) ||
        NativeGuidEqual(&Binding->TransferId, &zero) || NativeGuidEqual(&Binding->RequestNonce, &zero) ||
        NativeGuidEqual(&Binding->OperationId, &zero) || Binding->ConnectionEpoch == 0 ||
        Binding->OsBootSequence != NativeBootSequence || (Binding->CreateOptions >> 24) != FILE_OPEN ||
        FlagOn(Binding->CreateOptions, FILE_DIRECTORY_FILE | FILE_OPEN_BY_FILE_ID | FILE_OPEN_REPARSE_POINT) ||
        (NativeScheduled(Binding) && FlagOn(p->OriginalDesiredAccess, FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
            FILE_DELETE_CHILD | GENERIC_WRITE | GENERIC_ALL | MAXIMUM_ALLOWED)) ||
        (NativeScheduled(Binding) && FlagOn(p->OriginalDesiredAccess, FILE_WRITE_ATTRIBUTES)) ||
        !FlagOn(p->OriginalDesiredAccess, DELETE | GENERIC_ALL | MAXIMUM_ALLOWED) || p->GrantedAccess != 0 ||
        FlagOn(p->OriginalShareAccess, ~(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)) ||
        p->CallerProcessId == 0 || p->CallerProcessCreationTime <= 0 ||
        p->CallerSidBytes == 0 || p->CallerSidBytes > sizeof(p->CallerSid) ||
        !RtlValidSid((PSID)p->CallerSid) || RtlLengthSid((PSID)p->CallerSid) != p->CallerSidBytes ||
        p->CanonicalLeafBytes == 0 || (p->CanonicalLeafBytes & 1) != 0 ||
        p->CanonicalLeafBytes >= sizeof(p->CanonicalLeaf) ||
        NativeGuidEqual(&p->MountManagerVolumeId, &zero) ||
        RtlEqualMemory(&p->VolumeRootIdentity.FileId, &zeroId, sizeof(zeroId)) ||
        RtlEqualMemory(&p->ParentIdentity.FileId, &zeroId, sizeof(zeroId)) ||
        RtlEqualMemory(&p->PublicIdentity.FileId, &zeroId, sizeof(zeroId)) ||
        p->VolumeRootIdentity.VolumeSerialNumber != p->ParentIdentity.VolumeSerialNumber ||
        p->ParentIdentity.VolumeSerialNumber != p->PublicIdentity.VolumeSerialNumber) return FALSE;
    for (i = 0; i < p->CanonicalLeafBytes / sizeof(WCHAR); ++i)
        if (p->CanonicalLeaf[i] == 0 || p->CanonicalLeaf[i] == L'\\' ||
            p->CanonicalLeaf[i] == L'/' || p->CanonicalLeaf[i] == L':') return FALSE;
    return !((p->CanonicalLeafBytes == sizeof(WCHAR) && p->CanonicalLeaf[0] == L'.') ||
        (p->CanonicalLeafBytes == 2 * sizeof(WCHAR) && p->CanonicalLeaf[0] == L'.' && p->CanonicalLeaf[1] == L'.'));
}

/* The caller's unused stack bytes never enter replayable metadata. */
static VOID NativeCopyBinding(PSAFEUPLOAD_STAGE_NATIVE_BINDING Destination,
    const SAFEUPLOAD_STAGE_NATIVE_BINDING *Source)
{
    PSAFEUPLOAD_STAGE_PUBLIC_BINDING d = &Destination->Public;
    const SAFEUPLOAD_STAGE_PUBLIC_BINDING *s = &Source->Public;
    RtlZeroMemory(Destination, sizeof(*Destination));
    Destination->DriverInstanceId = Source->DriverInstanceId;
    Destination->TransferId = Source->TransferId;
    Destination->RequestNonce = Source->RequestNonce;
    Destination->OperationId = Source->OperationId;
    Destination->ConnectionEpoch = Source->ConnectionEpoch;
    Destination->OsBootSequence = Source->OsBootSequence;
    Destination->CreateOptions = Source->CreateOptions;
    d->OriginalDesiredAccess = s->OriginalDesiredAccess;
    d->OriginalShareAccess = s->OriginalShareAccess;
    d->MountManagerVolumeId = s->MountManagerVolumeId;
    d->CallerProcessId = s->CallerProcessId;
    d->CallerProcessCreationTime = s->CallerProcessCreationTime;
    d->CallerSessionId = s->CallerSessionId;
    d->CallerSidBytes = s->CallerSidBytes;
    d->ParentCaseSensitive = s->ParentCaseSensitive;
    d->VolumeRootIdentity = s->VolumeRootIdentity;
    d->ParentIdentity = s->ParentIdentity;
    d->PublicIdentity = s->PublicIdentity;
    d->CanonicalLeafBytes = s->CanonicalLeafBytes;
    RtlCopyMemory(d->CallerSid, s->CallerSid, s->CallerSidBytes);
    RtlCopyMemory(d->CanonicalLeaf, s->CanonicalLeaf, s->CanonicalLeafBytes);
}

/* NativeLock. Ordinary retirement requires an exact ACK; mandatory local
 * retirement instead requires proved terminal lifetime. Callbacks never own
 * the final reference or free objects at elevated IRQL. */
static PSAFEUPLOAD_STAGE_NATIVE_RECORD NativeFindObject(PFLT_INSTANCE Instance, PFILE_OBJECT FileObject)
{
    PLIST_ENTRY link;
    if (Instance == NULL || FileObject == NULL) return NULL;
    for (link = NativeRecords.Flink; link != &NativeRecords; link = link->Flink) {
        PSAFEUPLOAD_STAGE_NATIVE_RECORD record = CONTAINING_RECORD(link, SAFEUPLOAD_STAGE_NATIVE_RECORD, Link);
        if (record->Instance == Instance && record->FileObject == FileObject) return record;
    }
    return NULL;
}

/* Never dereference an arbitrary legacy completion context. Membership and
 * the outstanding callback reference identify a native context under lock. */
static PSAFEUPLOAD_STAGE_NATIVE_RECORD NativeFindContext(PVOID Context, BOOLEAN Create)
{
    PLIST_ENTRY link;
    if (Context == NULL) return NULL;
    for (link = NativeRecords.Flink; link != &NativeRecords; link = link->Flink) {
        PSAFEUPLOAD_STAGE_NATIVE_RECORD record = CONTAINING_RECORD(link, SAFEUPLOAD_STAGE_NATIVE_RECORD, Link);
        if ((PVOID)record == Context && (Create ? record->CreateCallbackOwned : record->CloseCallbackOwned))
            return record;
    }
    return NULL;
}

_Use_decl_annotations_
static VOID NativeDestroy(PSAFEUPLOAD_STAGE_NATIVE_RECORD Record)
{
    PAGED_CODE();
    NT_ASSERT(Record->References == 0);
    NT_ASSERT(Record->FileObject == NULL);
    NT_ASSERT(Record->Backend == NULL && !Record->BackendOperation);
    NT_ASSERT(Record->DispositionEpoch == NULL);
    FltObjectDereference(Record->Instance);
    ExFreePoolWithTag(Record, NATIVE_RECORD_TAG);
    InterlockedDecrement(&NativeRecordCount);
    SafeUploadStageWritersOwnerRelease();
}

_Use_decl_annotations_
VOID SafeUploadStageNativeInitialize(const GUID *DriverInstanceId, ULONG OsBootSequence, PKEVENT WakeEvent)
{
    KeInitializeSpinLock(&NativeLock);
    ExInitializeRundownProtection(&NativeCalls);
    InitializeListHead(&NativeRecords);
    KeInitializeEvent(&NativeLocalChanged, NotificationEvent, FALSE);
    NativeCallsDrained = FALSE;
    NativeDriverInstance = *DriverInstanceId;
    NativeBootSequence = OsBootSequence;
    NativeWakeEvent = WakeEvent;
    InterlockedExchange(&NativeRecordCount, 0);
    NativeFactories = 0;
    NativeRevision = 1;
    NativeReplayUsable = TRUE;
    NativeAccepting = TRUE;
    InterlockedExchange(&NativeInitialized, 1);
}

_Use_decl_annotations_
__declspec(noinline) static NTSTATUS NativeReserve(PFLT_INSTANCE Instance, PFILE_OBJECT FileObject,
    const SAFEUPLOAD_STAGE_NATIVE_BINDING *Binding, PSAFEUPLOAD_STAGE_PUBLIC_BACKEND Backend,
    PSAFEUPLOAD_STAGE_NATIVE_RECORD *Record)
{
    PSAFEUPLOAD_STAGE_NATIVE_RECORD item = NULL;
    PLIST_ENTRY link;
    KIRQL irql;
    NTSTATUS status = STATUS_DEVICE_NOT_READY;
    ULONG index = 0;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    *Record = NULL;
    if (!NativeEnter()) return STATUS_DEVICE_NOT_READY;
    NativeAcquire(&irql);
    if (!NativeAccepting || SafeUploadStageMandatoryTeardownActive()) {
        NativeRelease(irql);
        ExReleaseRundownProtection(&NativeCalls);
        return STATUS_FLT_DELETING_OBJECT;
    }
    if (NativeFactories + InterlockedCompareExchange(&NativeRecordCount, 0, 0) >= NATIVE_RECORD_LIMIT) {
        NativeRelease(irql);
        ExReleaseRundownProtection(&NativeCalls);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ++NativeFactories;
    NativeRelease(irql);
    if (Instance == NULL || FileObject == NULL || !NativeBindingValid(Binding) ||
        !SafeUploadInstanceAdmissionGateSatisfied(Instance)) { status = STATUS_ACCESS_DENIED; goto Exit; }
    {
        GUID actualVolumeId;
        status = SafeUploadStagePublicReadMountGuid(Instance, &actualVolumeId);
        if (!NT_SUCCESS(status) || !NativeGuidEqual(&actualVolumeId, &Binding->Public.MountManagerVolumeId)) {
            status = STATUS_FILE_INVALID;
            goto Exit;
        }
    }
    item = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*item), NATIVE_RECORD_TAG);
    if (item == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    RtlZeroMemory(item, sizeof(*item));
    SafeUploadStageWritersOwnerAcquire();
    KeInitializeSemaphore(&item->DispositionGate, 1, 1);
    status = FltObjectReference(Instance);
    if (!NT_SUCCESS(status)) goto Fail;
    item->Instance = Instance;
    item->FileObject = FileObject;
    item->CreateFileObject = FileObject;
    NativeCopyBinding(&item->Snapshot.Binding, Binding);
    for (index = 0; index < (ULONG)(Binding->Public.CanonicalLeafBytes / sizeof(WCHAR)); ++index)
        item->FoldedLeaf[index] = RtlUpcaseUnicodeChar(Binding->Public.CanonicalLeaf[index]);
    item->Snapshot.CreateStatus = STATUS_PENDING;
    item->Snapshot.IdentityStatus = STATUS_PENDING;
    item->References = 2; /* map + producer */
    NativeAcquire(&irql);
    /* Lock order NativeLock -> StageAttachLock. Teardown publishes the attach
     * tombstone before taking NativeLock, and never holds both in reverse. */
    if (!NativeAccepting || !NativeReplayUsable ||
        InterlockedCompareExchange(&NativeRecordCount, 0, 0) >= NATIVE_RECORD_LIMIT ||
        SafeUploadStageAttachInstanceRetiring(Instance)) { status = STATUS_DEVICE_BUSY; goto UnlockFail; }
    for (link = NativeRecords.Flink; link != &NativeRecords; link = link->Flink) {
        PSAFEUPLOAD_STAGE_NATIVE_RECORD current = CONTAINING_RECORD(link, SAFEUPLOAD_STAGE_NATIVE_RECORD, Link);
        const SAFEUPLOAD_STAGE_NATIVE_BINDING *existing = &current->Snapshot.Binding;
        if (current->FileObject == FileObject || NativeGuidEqual(&existing->OperationId, &Binding->OperationId) ||
            NativeGuidEqual(&existing->TransferId, &Binding->TransferId) ||
            NativeGuidEqual(&existing->RequestNonce, &Binding->RequestNonce)) {
            status = STATUS_OBJECT_NAME_COLLISION; goto UnlockFail;
        }
    }
    InsertTailList(&NativeRecords, &item->Link);
    if (Backend != NULL) {
        SafeUploadStagePublicReferenceBackend(Backend);
        item->Backend = Backend;
        item->BackendAppObject = FileObject;
        item->Snapshot.CombinedBackend = TRUE;
    }
    InterlockedIncrement(&NativeRecordCount);
    NativeChanged();
    NativeRelease(irql);
    *Record = item;
    NativeWake();
    status = STATUS_SUCCESS;
    goto Exit;
UnlockFail:
    NativeRelease(irql);
Fail:
    if (item->Instance != NULL) FltObjectDereference(item->Instance);
    ExFreePoolWithTag(item, NATIVE_RECORD_TAG);
    SafeUploadStageWritersOwnerRelease();
Exit:
    NativeAcquire(&irql);
    NT_ASSERT(NativeFactories > 0);
    --NativeFactories;
    NativeChanged();
    NativeRelease(irql);
    ExReleaseRundownProtection(&NativeCalls);
    return status;
}

_Use_decl_annotations_
NTSTATUS SafeUploadStageNativeReserve(PFLT_INSTANCE Instance, PFILE_OBJECT FileObject,
    const SAFEUPLOAD_STAGE_NATIVE_BINDING *Binding, PSAFEUPLOAD_STAGE_NATIVE_RECORD *Record)
{
    PAGED_CODE();
    *Record = NULL;
    if (FlagOn(Binding->Public.OriginalDesiredAccess, FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
        FILE_DELETE_CHILD | GENERIC_WRITE | GENERIC_ALL | MAXIMUM_ALLOWED)) return STATUS_ACCESS_DENIED;
    return NativeReserve(Instance, FileObject, Binding, NULL, Record);
}

_Use_decl_annotations_
NTSTATUS SafeUploadStageNativeBindWriter(PFLT_INSTANCE Instance, PFILE_OBJECT AppObject,
    PSAFEUPLOAD_STAGE_WRITER_LEASE Writer)
{
    PSAFEUPLOAD_STAGE_NATIVE_BINDING binding = NULL;
    PSAFEUPLOAD_STAGE_NATIVE_RECORD record = NULL;
    PSAFEUPLOAD_STAGE_PUBLIC_BACKEND backend = NULL;
    PSAFEUPLOAD_STAGE_NATIVE_SNAPSHOT snapshot = NULL;
    SAFEUPLOAD_PUBLIC_RELAY_REPLY reply = {0};
    PFLT_INSTANCE actualInstance = NULL;
    PFILE_OBJECT object = NULL;
    PVOID cookie = NULL;
    LONG64 epoch = 0;
    ULONG pid = 0;
    UINT64 revision = 0, authority = 0;
    NTSTATUS status = STATUS_DEVICE_NOT_READY;
    KIRQL irql;
    BOOLEAN operation = FALSE;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    status = SafeUploadStagePublicReferenceWriterDelete(Writer, &backend);
    if (status != STATUS_SUCCESS) return status;
    operation = SafeUploadStagePublicAcquireOperation(backend, &actualInstance, &object);
    if (!operation || actualInstance != Instance || object == NULL || !object->DeleteAccess ||
        !SafeUploadConnectionGetAuthenticatedIdentity(NULL, &cookie, &epoch, &pid)) {
        status = STATUS_DEVICE_NOT_READY; goto Exit;
    }
    snapshot = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*snapshot), NATIVE_RECORD_TAG);
    if (snapshot == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    RtlZeroMemory(snapshot, sizeof(*snapshot));
    binding = &snapshot->Binding;
    status = SafeUploadStageNativeReadIdentity(&binding->DriverInstanceId, &binding->OsBootSequence);
    if (status != STATUS_SUCCESS) goto Exit;
    binding->ConnectionEpoch = (UINT64)epoch;
    /* This is the actual retained FILE_OPEN, never the mutating app CREATE. */
    binding->CreateOptions = ((ULONG)FILE_OPEN << 24);
    SafeUploadStagePublicGetBinding(backend, &binding->Public);
    binding->Public.GrantedAccess = 0;
    status = ExUuidCreate(&binding->TransferId); if (!NT_SUCCESS(status)) goto Exit;
    status = ExUuidCreate(&binding->RequestNonce); if (!NT_SUCCESS(status)) goto Exit;
    status = ExUuidCreate(&binding->OperationId); if (!NT_SUCCESS(status)) goto Exit;
    status = NativeReserve(Instance, AppObject, binding, backend, &record);
    if (status != STATUS_SUCCESS) goto Exit;
    status = SafeUploadStageNativeSnapshot(record, snapshot, &revision);
    if (status == STATUS_SUCCESS)
        status = SafeUploadStagePublicOpenExchange(snapshot, revision, SAFEUPLOAD_PUBLIC_OPEN_PREPARE, &reply, &authority);
    if (status == STATUS_SUCCESS)
        status = SafeUploadStageNativeMarkForwarded(record, 0, revision, authority, &reply);
    NativeAcquire(&irql);
    /* The factory already observed this exact nonmutating open's successful
     * grant. Failure of this binding never repeats or changes that open. */
    record->CreateCallbackOwned = FALSE;
    record->CreateFileObject = NULL;
    record->Snapshot.CreateOutcomeKnown = TRUE;
    record->Snapshot.CreateAccepted = TRUE;
    record->Snapshot.CreateStatus = STATUS_SUCCESS;
    record->Snapshot.IdentityStatus = status;
    record->Snapshot.IdentityAndDeleteGrantChecked = status == STATUS_SUCCESS;
    if (status == STATUS_SUCCESS) {
        SafeUploadStagePublicGetBinding(backend, &snapshot->Binding.Public);
        record->Snapshot.GrantedAccess = snapshot->Binding.Public.GrantedAccess;
    }
    NativeChanged();
    NativeRelease(irql);
    SafeUploadStageNativeReleaseRecord(record);
    NativeWake();
Exit:
    if (snapshot != NULL) ExFreePoolWithTag(snapshot, NATIVE_RECORD_TAG);
    if (operation) SafeUploadStagePublicReleaseOperation(backend);
    if (status != STATUS_SUCCESS && record != NULL) SafeUploadStageNativeCloseWriter(Instance, AppObject);
    SafeUploadStagePublicDereferenceBackend(backend);
    return status;
}

_Use_decl_annotations_
VOID SafeUploadStageNativeCloseWriter(PFLT_INSTANCE Instance, PFILE_OBJECT AppObject)
{
    PSAFEUPLOAD_STAGE_NATIVE_RECORD record = NULL;
    PSAFEUPLOAD_STAGE_PUBLIC_BACKEND backend = NULL;
    KIRQL irql;
    PLIST_ENTRY link;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (!NativeEnter()) return;
    NativeAcquire(&irql);
    for (link = NativeRecords.Flink; link != &NativeRecords; link = link->Flink) {
        PSAFEUPLOAD_STAGE_NATIVE_RECORD candidate = CONTAINING_RECORD(link, SAFEUPLOAD_STAGE_NATIVE_RECORD, Link);
        if (candidate->Instance == Instance && candidate->BackendAppObject == AppObject) { record = candidate; break; }
    }
    if (record != NULL && record->Backend != NULL) {
        record->References += 1;
        backend = record->Backend;
        record->BackendAppObject = NULL;
        record->FileObject = NULL; /* remove the app lookup before CLOSE/address reuse */
        NativeChanged();
    }
    NativeRelease(irql);
    if (backend != NULL) {
        /* No NativeLock/namespace lock across local I/O rundown or handle close.
         * Keep Backend installed until post callbacks have released their use. */
        SafeUploadStagePublicCloseBackend(backend);
        NativeAcquire(&irql);
        record->Backend = NULL;
        record->Snapshot.LastHandleCleanedUp = TRUE;
        NativeChanged();
        NativeRelease(irql);
        SafeUploadStagePublicDereferenceBackend(backend);
        SafeUploadStageNativeReleaseRecord(record);
        NativeWake();
    }
    ExReleaseRundownProtection(&NativeCalls);
}

_Use_decl_annotations_
NTSTATUS SafeUploadStageNativeOwnerNameStatus(PFLT_INSTANCE Instance, PUNICODE_STRING Name, PEPROCESS Owner)
{
    FILE_ID_INFORMATION identity = {0};
    FILE_ID_INFORMATION parentIdentity = {0};
    UNICODE_STRING parent = {0}, leaf = {0};
    struct { WCHAR Exact[256], Folded[256]; } *leafCopy = NULL;
    PLIST_ENTRY link;
    KIRQL irql;
    ULONG index = 0, pid = HandleToULong(PsGetProcessId(Owner));
    LONG64 creation = PsGetProcessCreateTimeQuadPart(Owner);
    BOOLEAN candidate = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (!NativeEnter()) return STATUS_SUCCESS;
    parent = *Name;
    for (index = (ULONG)(Name->Length / sizeof(WCHAR)); index != 0; --index)
        if (Name->Buffer[index - 1] == L'\\') break;
    if (index == 0 || Name->Length - index * sizeof(WCHAR) >= sizeof(leafCopy->Exact)) goto Exit;
    leaf.Buffer = Name->Buffer + index;
    leaf.Length = (USHORT)(Name->Length - index * sizeof(WCHAR));
    leaf.MaximumLength = leaf.Length;
    parent.Length = (USHORT)((index - 1) * sizeof(WCHAR));
    parent.MaximumLength = parent.Length;
    /* The normalized name can be paged. Capture both case modes before
     * NativeLock raises IRQL; all three locked passes read only this copy. */
    leafCopy = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*leafCopy), NATIVE_RECORD_TAG);
    if (leafCopy == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    RtlZeroMemory(leafCopy, sizeof(*leafCopy));
    RtlCopyMemory(leafCopy->Exact, leaf.Buffer, leaf.Length);
    for (index = 0; index < (ULONG)(leaf.Length / sizeof(WCHAR)); ++index)
        leafCopy->Folded[index] = RtlUpcaseUnicodeChar(leafCopy->Exact[index]);
    NativeAcquire(&irql);
    for (link = NativeRecords.Flink; link != &NativeRecords; link = link->Flink) {
        PSAFEUPLOAD_STAGE_NATIVE_RECORD r = CONTAINING_RECORD(link, SAFEUPLOAD_STAGE_NATIVE_RECORD, Link);
        if (r->Instance != Instance || r->Snapshot.Binding.Public.CanonicalLeafBytes != leaf.Length ||
            !RtlEqualMemory(r->Snapshot.Binding.Public.ParentCaseSensitive ? r->Snapshot.Binding.Public.CanonicalLeaf : r->FoldedLeaf,
                r->Snapshot.Binding.Public.ParentCaseSensitive ? leafCopy->Exact : leafCopy->Folded, leaf.Length)) continue;
        for (index = 0; index < r->TombstoneCount; ++index)
            if (r->Tombstones[index].Pid == pid && r->Tombstones[index].Creation == creation) candidate = TRUE;
    }
    NativeRelease(irql);
    if (!candidate) goto Exit;
    status = SafeUploadStageQueryIdentity(Instance, &parent, TRUE, &parentIdentity);
    if (!NT_SUCCESS(status)) goto Exit;
    candidate = FALSE;
    NativeAcquire(&irql);
    for (link = NativeRecords.Flink; link != &NativeRecords; link = link->Flink) {
        PSAFEUPLOAD_STAGE_NATIVE_RECORD r = CONTAINING_RECORD(link, SAFEUPLOAD_STAGE_NATIVE_RECORD, Link);
        if (r->Instance != Instance || r->Snapshot.Binding.Public.CanonicalLeafBytes != leaf.Length ||
            !RtlEqualMemory(&r->Snapshot.Binding.Public.ParentIdentity, &parentIdentity, sizeof(parentIdentity)) ||
            !RtlEqualMemory(r->Snapshot.Binding.Public.ParentCaseSensitive ? r->Snapshot.Binding.Public.CanonicalLeaf : r->FoldedLeaf,
                r->Snapshot.Binding.Public.ParentCaseSensitive ? leafCopy->Exact : leafCopy->Folded, leaf.Length)) continue;
        for (index = 0; index < r->TombstoneCount; ++index)
            if (r->Tombstones[index].Pid == pid && r->Tombstones[index].Creation == creation) candidate = TRUE;
    }
    NativeRelease(irql);
    if (!candidate) goto Exit;
    /* A locator only finds the object to compare. It cannot delete anything or
     * hide a replacement with another full identity. No native lock spans I/O. */
    status = SafeUploadStageQueryIdentity(Instance, Name, FALSE, &identity);
    if (!NT_SUCCESS(status)) goto Exit;
    NativeAcquire(&irql);
    for (link = NativeRecords.Flink; link != &NativeRecords; link = link->Flink) {
        PSAFEUPLOAD_STAGE_NATIVE_RECORD r = CONTAINING_RECORD(link, SAFEUPLOAD_STAGE_NATIVE_RECORD, Link);
        if (r->Instance != Instance || r->Snapshot.Binding.Public.CanonicalLeafBytes != leaf.Length ||
            !RtlEqualMemory(&r->Snapshot.Binding.Public.ParentIdentity, &parentIdentity, sizeof(parentIdentity)) ||
            !RtlEqualMemory(r->Snapshot.Binding.Public.ParentCaseSensitive ? r->Snapshot.Binding.Public.CanonicalLeaf : r->FoldedLeaf,
                r->Snapshot.Binding.Public.ParentCaseSensitive ? leafCopy->Exact : leafCopy->Folded, leaf.Length) ||
            !RtlEqualMemory(&r->Snapshot.Binding.Public.PublicIdentity, &identity, sizeof(identity))) continue;
        for (index = 0; index < r->TombstoneCount; ++index)
            if (r->Tombstones[index].Pid == pid && r->Tombstones[index].Creation == creation)
                status = STATUS_DELETE_PENDING;
    }
    NativeRelease(irql);
Exit:
    if (leafCopy != NULL) ExFreePoolWithTag(leafCopy, NATIVE_RECORD_TAG);
    ExReleaseRundownProtection(&NativeCalls);
    return status;
}

_Use_decl_annotations_
NTSTATUS SafeUploadStageNativeSnapshot(PSAFEUPLOAD_STAGE_NATIVE_RECORD Record,
    PSAFEUPLOAD_STAGE_NATIVE_SNAPSHOT Snapshot, PUINT64 Revision)
{
    KIRQL irql;
    NTSTATUS status = STATUS_SUCCESS;
    RtlZeroMemory(Snapshot, sizeof(*Snapshot));
    *Revision = 0;
    NativeAcquire(&irql);
    if (!NativeAccepting || !NativeReplayUsable || Record->References < 2) status = STATUS_DEVICE_NOT_READY;
    else { *Snapshot = Record->Snapshot; *Revision = NativeRevision; }
    NativeRelease(irql);
    return status;
}

_Use_decl_annotations_
NTSTATUS SafeUploadStageNativeMarkForwarded(PSAFEUPLOAD_STAGE_NATIVE_RECORD Record,
    UINT64 DurableGeneration, UINT64 ExpectedRevision, UINT64 AuthorityRevision,
    const SAFEUPLOAD_PUBLIC_RELAY_REPLY *PublicOpenReceipt)
{
    static const FILE_ID_128 zero = {0};
    KIRQL irql;
    NTSTATUS status = STATUS_SUCCESS;
    if (!NativeScheduled(&Record->Snapshot.Binding)) {
        if (PublicOpenReceipt == NULL || PublicOpenReceipt->Request.Phase != SAFEUPLOAD_PUBLIC_OPEN_PREPARE ||
            PublicOpenReceipt->Request.NativeMapRevision != ExpectedRevision ||
            !NativeGuidEqual(&PublicOpenReceipt->Request.OpenNonce, &Record->Snapshot.Binding.RequestNonce) ||
            !NativeGuidEqual(&PublicOpenReceipt->Request.OperationId, &Record->Snapshot.Binding.OperationId) ||
            PublicOpenReceipt->PublishedGeneration > (UINT64)MAXLONGLONG ||
            (PublicOpenReceipt->PublishedGeneration == 0 ?
                (PublicOpenReceipt->PublishedIdentity.VolumeSerialNumber != 0 ||
                 !RtlEqualMemory(&PublicOpenReceipt->PublishedIdentity.FileId, &zero, sizeof(zero))) :
                (PublicOpenReceipt->PublishedIdentity.VolumeSerialNumber != Record->Snapshot.Binding.Public.PublicIdentity.VolumeSerialNumber ||
                 RtlEqualMemory(&PublicOpenReceipt->PublishedIdentity.FileId, &zero, sizeof(zero)))))
            return STATUS_INVALID_PARAMETER;
    }
    NativeAcquire(&irql);
    if (!SafeUploadBoundPublicationNamespaceAvailable(Record->Instance)) status = STATUS_DEVICE_BUSY;
    else if (ExpectedRevision != 0 && ExpectedRevision != NativeRevision) status = STATUS_RETRY;
    else if (!NativeAccepting || !NativeReplayUsable || ExpectedRevision == 0 ||
        AuthorityRevision == 0 ||
        !SafeUploadStageProtocolNativeForwardAllowed(Record->Snapshot.Binding.ConnectionEpoch, AuthorityRevision) ||
        (NativeScheduled(&Record->Snapshot.Binding) ? DurableGeneration == 0 :
            DurableGeneration != 0) || Record->Snapshot.Forwarded ||
        Record->Snapshot.CreateOutcomeKnown || Record->Snapshot.CleanupCoverageLost ||
        SafeUploadStageAttachInstanceRetiring(Record->Instance)) status = STATUS_INVALID_DEVICE_STATE;
    else {
        Record->Snapshot.JournalGeneration = DurableGeneration;
        if (PublicOpenReceipt != NULL) {
            Record->Snapshot.PublicOpenPrepared = TRUE;
            Record->Snapshot.PublishedGeneration = PublicOpenReceipt->PublishedGeneration;
            Record->Snapshot.PublishedIdentity = PublicOpenReceipt->PublishedIdentity;
        }
        Record->Snapshot.Forwarded = TRUE;
        Record->CreateCallbackOwned = TRUE; /* producer reference transfers to post-CREATE */
        NativeChanged();
    }
    NativeRelease(irql);
    if (NT_SUCCESS(status)) NativeWake();
    return status;
}

_Use_decl_annotations_
NTSTATUS SafeUploadStageNativeMarkNotForwarded(PSAFEUPLOAD_STAGE_NATIVE_RECORD Record)
{
    KIRQL irql;
    NTSTATUS status = STATUS_SUCCESS;
    NativeAcquire(&irql);
    if (Record->Snapshot.Forwarded || Record->Snapshot.CreateOutcomeKnown) status = STATUS_INVALID_DEVICE_STATE;
    else {
        Record->Snapshot.CreateOutcomeKnown = TRUE;
        Record->Snapshot.CreateAccepted = FALSE;
        Record->Snapshot.CreateStatus = STATUS_CANCELLED; /* preparation ended before NTFS forwarding */
        Record->FileObject = NULL;
        Record->CreateFileObject = NULL;
        NativeChanged();
    }
    NativeRelease(irql);
    if (NT_SUCCESS(status)) NativeWake();
    return status;
}

_Use_decl_annotations_
VOID SafeUploadStageNativeReleaseRecord(PSAFEUPLOAD_STAGE_NATIVE_RECORD Record)
{
    KIRQL irql;
    NativeAcquire(&irql);
    /* A rejected concurrent request can release its short lookup reference
     * while another original callback is still owned. It cannot consume that
     * callback's reference (or the map's reference) on its behalf. */
    NT_ASSERT(Record->References > 1 + (LONG)Record->CreateCallbackOwned +
        (LONG)Record->DispositionCallbackOwned + (LONG)Record->CloseCallbackOwned);
    Record->References -= 1;
    if (Record->References == 1) NativeChanged(); /* ACK eligibility changed, even without new CREATE facts. */
    NativeRelease(irql);
    NativeWake(); /* an ACK previously refused for an active producer may now proceed */
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS NativeDispositionActor(PFLT_CALLBACK_DATA Data, PSAFEUPLOAD_STAGE_PUBLIC_MUTATION Operation)
{
    SECURITY_SUBJECT_CONTEXT subject;
    PACCESS_TOKEN token;
    PEPROCESS process = FltGetRequestorProcess(Data);
    PTOKEN_USER user = NULL;
    PULONG session = NULL;
    NTSTATUS status;
    if (Data->Thread == NULL || process == NULL) return STATUS_ACCESS_DENIED;
    Operation->ActorProcessId = FltGetRequestorProcessId(Data);
    Operation->ActorProcessCreationTime = PsGetProcessCreateTimeQuadPart(process);
    if (Operation->ActorProcessId == 0 || Operation->ActorProcessId > MAXLONG ||
        Operation->ActorProcessId != HandleToULong(PsGetProcessId(process)) ||
        Operation->ActorProcessCreationTime <= 0) return STATUS_ACCESS_DENIED;
    /* Audit/owner delivery only. The existing NTFS handle's DELETE grant,
     * not this SID or a service token, authorizes the original operation.
     * Capture the original requestor's thread, never the executing worker. */
    SeCaptureSubjectContextEx(Data->Thread, process, &subject);
    SeLockSubjectContext(&subject);
    token = SeQuerySubjectContextToken(&subject);
    status = token != NULL ? SeQueryInformationToken(token, TokenUser, (PVOID *)&user) : STATUS_ACCESS_DENIED;
    if (!NT_SUCCESS(status)) goto Exit;
    if (user == NULL || user->User.Sid == NULL || !RtlValidSid(user->User.Sid) ||
        RtlLengthSid(user->User.Sid) > sizeof(Operation->ActorSid)) { status = STATUS_INVALID_SID; goto Exit; }
    Operation->ActorSidBytes = RtlLengthSid(user->User.Sid);
    status = RtlCopySid(sizeof(Operation->ActorSid), Operation->ActorSid, user->User.Sid);
    if (!NT_SUCCESS(status)) goto Exit;
    status = SeQueryInformationToken(token, TokenSessionId, (PVOID *)&session);
    if (!NT_SUCCESS(status)) goto Exit;
    if (session == NULL) { status = STATUS_INVALID_BUFFER_SIZE; goto Exit; }
    Operation->ActorSessionId = *session;
Exit:
    if (session != NULL) ExFreePool(session);
    if (user != NULL) ExFreePool(user);
    SeUnlockSubjectContext(&subject);
    SeReleaseSubjectContext(&subject);
    return status;
}

static NTSTATUS NativeDispositionFlags(PFLT_CALLBACK_DATA Data, PULONG Flags)
{
    PVOID buffer = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    ULONG length = Data->Iopb->Parameters.SetFileInformation.Length;
    if (buffer == NULL) return STATUS_INVALID_PARAMETER;
    __try {
        if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformation) {
            if (length < sizeof(FILE_DISPOSITION_INFORMATION)) return STATUS_INFO_LENGTH_MISMATCH;
            *Flags = ((PFILE_DISPOSITION_INFORMATION)buffer)->DeleteFile ? 1u : 0u;
        } else {
            if (length < sizeof(FILE_DISPOSITION_INFORMATION_EX)) return STATUS_INFO_LENGTH_MISMATCH;
            *Flags = ((PFILE_DISPOSITION_INFORMATION_EX)buffer)->Flags;
            if (FlagOn(*Flags, ~0x1fu)) return STATUS_INVALID_PARAMETER;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS SafeUploadStagePublicDispositionConfirm(const SAFEUPLOAD_STAGE_NATIVE_SNAPSHOT *Snapshot,
    const SAFEUPLOAD_PUBLIC_RELAY_REPLY *Reply, UINT64 AuthorityRevision)
{
    PLIST_ENTRY link;
    NTSTATUS status = STATUS_NOT_FOUND;
    KIRQL irql;
    if (Reply->Result != SAFEUPLOAD_PUBLIC_RELAY_RECORDED || Snapshot->PublicOperation.Sequence == 0 ||
        Reply->Request.Phase != SAFEUPLOAD_PUBLIC_DISPOSITION_FACTS ||
        !NativeGuidEqual(&Reply->Request.OpenNonce, &Snapshot->Binding.RequestNonce) ||
        !NativeGuidEqual(&Reply->Request.OperationId, &Snapshot->PublicOperation.OperationId) ||
        !NativeGuidEqual(&Reply->Request.MutationNonce, &Snapshot->PublicOperation.Nonce) ||
        Reply->Request.OperationSequence != Snapshot->PublicOperation.Sequence ||
        (Snapshot->PublicOperation.Generation != 0 && Reply->MutationGeneration != Snapshot->PublicOperation.Generation))
        return STATUS_INVALID_PARAMETER;
    if (!NativeEnter()) return STATUS_DEVICE_NOT_READY;
    NativeAcquire(&irql);
    if (AuthorityRevision == 0 || !SafeUploadStageProtocolNativeForwardAllowed(0, AuthorityRevision))
        status = STATUS_DEVICE_NOT_READY;
    else for (link = NativeRecords.Flink; link != &NativeRecords; link = link->Flink) {
        PSAFEUPLOAD_STAGE_NATIVE_RECORD record = CONTAINING_RECORD(link, SAFEUPLOAD_STAGE_NATIVE_RECORD, Link);
        const SAFEUPLOAD_STAGE_PUBLIC_MUTATION *operation = &record->Snapshot.PublicOperation;
        if (!NativeBindingEqual(&record->Snapshot.Binding, &Snapshot->Binding)) continue;
        if (record->DispositionCallbackOwned || operation->Sequence != Snapshot->PublicOperation.Sequence ||
            !NativeGuidEqual(&operation->OperationId, &Snapshot->PublicOperation.OperationId) ||
            operation->Facts != Snapshot->PublicOperation.Facts || operation->Status != Snapshot->PublicOperation.Status ||
            !FlagOn(operation->Facts, SAFEUPLOAD_PUBLIC_OPERATION_RESULT_KNOWN | SAFEUPLOAD_PUBLIC_OPERATION_NOT_FORWARDED)) {
            status = STATUS_DEVICE_BUSY; break;
        }
        /* The service durably armed the pre-ACK revision. Clearing this exact
         * slot advances replay; accepted cleanup remains independently pinned. */
        RtlZeroMemory(&record->Snapshot.PublicOperation, sizeof(record->Snapshot.PublicOperation));
        record->DispositionNoNameEffect = FALSE;
        NativeChanged(); status = STATUS_SUCCESS; break;
    }
    NativeRelease(irql);
    if (NT_SUCCESS(status)) NativeWake();
    ExReleaseRundownProtection(&NativeCalls);
    return status;
}

_Use_decl_annotations_
static VOID NativeDispositionFlush(PSAFEUPLOAD_STAGE_NATIVE_RECORD Record)
{
    PSAFEUPLOAD_STAGE_NATIVE_SNAPSHOT snapshot;
    SAFEUPLOAD_PUBLIC_RELAY_REPLY reply;
    UINT64 revision, authority;
    NTSTATUS status;
    PAGED_CODE();
    if (SafeUploadStageMandatoryTeardownActive()) return;
    snapshot = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*snapshot), NATIVE_RECORD_TAG);
    if (snapshot == NULL) return; /* local facts remain replayable */
    status = SafeUploadStageNativeSnapshot(Record, snapshot, &revision);
    if (NT_SUCCESS(status) && snapshot->PublicOperation.Sequence != 0 &&
        FlagOn(snapshot->PublicOperation.Facts, SAFEUPLOAD_PUBLIC_OPERATION_RESULT_KNOWN | SAFEUPLOAD_PUBLIC_OPERATION_NOT_FORWARDED)) {
        status = SafeUploadStagePublicOpenExchange(snapshot, revision, SAFEUPLOAD_PUBLIC_DISPOSITION_FACTS, &reply, &authority);
        if (status == STATUS_SUCCESS) (VOID)SafeUploadStagePublicDispositionConfirm(snapshot, &reply, authority);
    }
    ExFreePoolWithTag(snapshot, NATIVE_RECORD_TAG);
}

_Use_decl_annotations_
static FLT_PREOP_CALLBACK_STATUS NativeDispositionPrepare(PFLT_CALLBACK_DATA Data,
    PSAFEUPLOAD_STAGE_NATIVE_RECORD Record, PVOID *CompletionContext)
{
    SAFEUPLOAD_STAGE_PUBLIC_MUTATION operation;
    PSAFEUPLOAD_STAGE_NATIVE_SNAPSHOT snapshot = NULL;
    SAFEUPLOAD_PUBLIC_RELAY_REPLY reply;
    UINT64 revision = 0, authority = 0;
    KIRQL irql;
    ULONG actualFlags = 0;
    ULONG tombstoneIndex = 0;
    BOOLEAN captured = FALSE;
    BOOLEAN backendOperation = FALSE;
    PSAFEUPLOAD_ADMISSION_EPOCH_TOKEN epoch = NULL;
    PFLT_INSTANCE backendInstance = NULL;
    PFILE_OBJECT backendObject = NULL;
    NTSTATUS status = STATUS_DEVICE_NOT_READY;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    *CompletionContext = NULL;
    RtlZeroMemory(&operation, sizeof(operation));
    status = NativeDispositionFlags(Data, &operation.DispositionFlags);
    if (!NT_SUCCESS(status)) goto Exit;
    /* ON_CLOSE belongs to the actual native app handle. It must never be
     * emulated or retargeted onto a driver's combined backend handle. */
    if (Record->Snapshot.CombinedBackend && FlagOn(operation.DispositionFlags, FILE_DISPOSITION_ON_CLOSE)) {
        status = STATUS_NOT_SUPPORTED; goto Exit;
    }
    operation.InformationClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    operation.RequestorMode = Data->RequestorMode;
    operation.Facts = SAFEUPLOAD_PUBLIC_OPERATION_CAPTURED;
    operation.Status = STATUS_PENDING;
    status = NativeDispositionActor(Data, &operation);
    if (!NT_SUCCESS(status)) goto Exit;
    status = ExUuidCreate(&operation.TransferId); if (!NT_SUCCESS(status)) goto Exit;
    status = ExUuidCreate(&operation.Nonce); if (!NT_SUCCESS(status)) goto Exit;
    status = ExUuidCreate(&operation.OperationId); if (!NT_SUCCESS(status)) goto Exit;
    snapshot = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*snapshot), NATIVE_RECORD_TAG);
    if (snapshot == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    /* Serialize original I/O outside all global/namespace locks. Post releases
     * this local gate even if durable bookkeeping is lost. A retained slot then
     * refuses new mutation until its exact result is reconciled, never replayed. */
    (VOID)KeWaitForSingleObject(&Record->DispositionGate, Executive, KernelMode, FALSE, NULL);
    NativeAcquire(&irql);
    for (tombstoneIndex = 0; tombstoneIndex < Record->TombstoneCount; ++tombstoneIndex)
        if (Record->Tombstones[tombstoneIndex].Pid == operation.ActorProcessId &&
            Record->Tombstones[tombstoneIndex].Creation == operation.ActorProcessCreationTime &&
            Record->Tombstones[tombstoneIndex].Scheduled == BooleanFlagOn(operation.DispositionFlags, FILE_DISPOSITION_ON_CLOSE)) break;
    if (!NativeAccepting || !NativeReplayUsable || Record->Snapshot.CleanupCoverageLost ||
        !Record->Snapshot.IdentityAndDeleteGrantChecked || Record->FileObject != Data->Iopb->TargetFileObject ||
        Record->Snapshot.PublicOperation.Sequence != 0 || SafeUploadStageAttachInstanceRetiring(Record->Instance))
        status = STATUS_DEVICE_NOT_READY;
    else if (Record->NextDispositionSequence == MAXULONGLONG) status = STATUS_INTEGER_OVERFLOW;
    else if (FlagOn(operation.DispositionFlags, FILE_DISPOSITION_DELETE) &&
        tombstoneIndex == (ULONG)RTL_NUMBER_OF(Record->Tombstones)) status = STATUS_INSUFFICIENT_RESOURCES;
    else {
        operation.Sequence = ++Record->NextDispositionSequence;
        Record->Snapshot.PublicOperation = operation;
        NativeChanged(); captured = TRUE;
    }
    NativeRelease(irql);
    if (!captured) goto ReleaseGate;
    if (Record->Snapshot.CombinedBackend) {
        /* Backend cannot be detached until this local gate/use has drained. */
        NativeAcquire(&irql);
        if (Record->Backend != NULL)
            backendOperation = SafeUploadStagePublicAcquireOperation(Record->Backend, &backendInstance, &backendObject);
        NativeRelease(irql);
        if (!backendOperation || backendInstance != Record->Instance || backendObject == NULL || !backendObject->DeleteAccess) {
            status = STATUS_FILE_CLOSED; goto NotForwarded;
        }
    }
    NativeWake();
    for (;;) {
        status = SafeUploadStageNativeSnapshot(Record, snapshot, &revision);
        if (!NT_SUCCESS(status)) break;
        if (FltIsIoCanceled(Data)) { status = STATUS_CANCELLED; break; }
        status = SafeUploadStagePublicOpenExchange(snapshot, revision, SAFEUPLOAD_PUBLIC_DISPOSITION_PREPARE, &reply, &authority);
        if (status != STATUS_SUCCESS) break;
        status = NativeDispositionFlags(Data, &actualFlags);
        if (!NT_SUCCESS(status) || actualFlags != operation.DispositionFlags ||
            (ULONG)Data->Iopb->Parameters.SetFileInformation.FileInformationClass != operation.InformationClass ||
            (ULONG)Data->RequestorMode != operation.RequestorMode) { status = STATUS_INVALID_PARAMETER; break; }
        if (FltIsIoCanceled(Data)) { status = STATUS_CANCELLED; break; }
        status = SafeUploadPolicyAdmissionAcquire(&epoch);
        if (!NT_SUCCESS(status)) break;
        if (SafeUploadPolicyAdmissionMustRetry()) { status = STATUS_RETRY; break; }
        NativeAcquire(&irql);
        if (NativeRevision != revision) status = STATUS_RETRY;
        else if (!NativeAccepting || !NativeReplayUsable || Record->Snapshot.CleanupCoverageLost ||
            SafeUploadStageAttachInstanceRetiring(Record->Instance) ||
            !SafeUploadBoundPublicationNamespaceAvailable(Record->Instance) ||
            !SafeUploadStageProtocolNativeForwardAllowed(0, authority) || Record->FileObject != Data->Iopb->TargetFileObject ||
            Record->Snapshot.PublicOperation.Facts != SAFEUPLOAD_PUBLIC_OPERATION_CAPTURED)
            status = STATUS_DEVICE_NOT_READY;
        else {
            Record->Snapshot.PublicOperation.Generation = reply.MutationGeneration;
            Record->Snapshot.PublicOperation.Facts |= SAFEUPLOAD_PUBLIC_OPERATION_FORWARDED;
            Record->DispositionNoNameEffect = reply.Result == SAFEUPLOAD_PUBLIC_RELAY_PREPARED_NO_NAME_EFFECT;
            Record->DispositionFileObject = backendOperation ? backendObject : Data->Iopb->TargetFileObject;
            Record->DispositionCallbackOwned = TRUE;
            Record->BackendOperation = backendOperation;
            Record->DispositionEpoch = epoch;
            NativeChanged(); status = STATUS_SUCCESS;
        }
        NativeRelease(irql);
        if (status == STATUS_RETRY) {
            SafeUploadPolicyAdmissionRelease(epoch); epoch = NULL;
            continue; /* only a changed replay revision; no epoch across the next RPC */
        }
        if (status == STATUS_SUCCESS) {
            ExFreePoolWithTag(snapshot, NATIVE_RECORD_TAG);
            *CompletionContext = Record; /* reference + local gate transfer to post */
            if (backendOperation) {
                Data->Iopb->TargetFileObject = backendObject;
                FltSetCallbackDataDirty(Data);
            }
            return FLT_PREOP_SYNCHRONIZE; /* unchanged outer operation/thread/mode */
        }
        break;
    }
NotForwarded:
    if (NT_SUCCESS(status)) status = STATUS_DEVICE_NOT_READY; /* no positive timeout completes as a successful delete */
    NativeAcquire(&irql);
    Record->Snapshot.PublicOperation.Facts |= SAFEUPLOAD_PUBLIC_OPERATION_NOT_FORWARDED;
    Record->Snapshot.PublicOperation.Status = status;
    NativeChanged();
    NativeRelease(irql);
    NativeWake(); NativeDispositionFlush(Record);
ReleaseGate:
    SafeUploadPolicyAdmissionRelease(epoch);
    if (backendOperation) SafeUploadStagePublicReleaseCallbackOperation(Record->Backend);
    KeReleaseSemaphore(&Record->DispositionGate, IO_NO_INCREMENT, 1, FALSE);
Exit:
    if (snapshot != NULL) ExFreePoolWithTag(snapshot, NATIVE_RECORD_TAG);
    SafeUploadStageNativeReleaseRecord(Record);
    Data->IoStatus.Status = status; Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

_Use_decl_annotations_
FLT_PREOP_CALLBACK_STATUS SafeUploadStagePublicDispositionPre(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, PVOID *CompletionContext, PBOOLEAN Handled)
{
    PSAFEUPLOAD_STAGE_NATIVE_RECORD record;
    KIRQL irql;
    FILE_INFORMATION_CLASS information = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    *Handled = FALSE; *CompletionContext = NULL;
    if (information != FileDispositionInformation && information != FileDispositionInformationEx) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!NativeEnter()) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    NativeAcquire(&irql);
    record = NativeFindObject(Objects->Instance, Objects->FileObject);
    if (record != NULL && NativeScheduled(&record->Snapshot.Binding)) record = NULL;
    if (record != NULL) record->References += 1;
    NativeRelease(irql);
    ExReleaseRundownProtection(&NativeCalls);
    if (record == NULL) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    *Handled = TRUE;
    if (FLT_IS_FASTIO_OPERATION(Data)) {
        SafeUploadStageNativeReleaseRecord(record); return FLT_PREOP_DISALLOW_FASTIO;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || !FLT_IS_IRP_OPERATION(Data)) {
        SafeUploadStageNativeReleaseRecord(record);
        Data->IoStatus.Status = STATUS_DEVICE_NOT_READY; Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    return NativeDispositionPrepare(Data, record, CompletionContext);
}

_Use_decl_annotations_
BOOLEAN SafeUploadStagePublicDispositionPost(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
    PLIST_ENTRY link;
    PSAFEUPLOAD_STAGE_NATIVE_RECORD record = NULL;
    KIRQL irql;
    PSAFEUPLOAD_STAGE_PUBLIC_BACKEND backend = NULL;
    PSAFEUPLOAD_ADMISSION_EPOCH_TOKEN epoch = NULL;
    if (CompletionContext == NULL || !NativeEnter()) return FALSE;
    NativeAcquire(&irql);
    for (link = NativeRecords.Flink; link != &NativeRecords; link = link->Flink) {
        PSAFEUPLOAD_STAGE_NATIVE_RECORD candidate = CONTAINING_RECORD(link, SAFEUPLOAD_STAGE_NATIVE_RECORD, Link);
        if ((PVOID)candidate == CompletionContext && candidate->DispositionCallbackOwned) { record = candidate; break; }
    }
    if (record != NULL) {
        record->DispositionCallbackOwned = FALSE;
        if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) || record->Instance != Objects->Instance ||
            record->DispositionFileObject != Data->Iopb->TargetFileObject || Data->IoStatus.Status == STATUS_PENDING)
            record->Snapshot.PublicOperation.Facts |= SAFEUPLOAD_PUBLIC_OPERATION_COVERAGE_LOST;
        else {
            record->Snapshot.PublicOperation.Status = Data->IoStatus.Status;
            record->Snapshot.PublicOperation.Facts |= SAFEUPLOAD_PUBLIC_OPERATION_RESULT_KNOWN;
            if (NT_SUCCESS(Data->IoStatus.Status) && !record->DispositionNoNameEffect) {
                if (FlagOn(record->Snapshot.PublicOperation.DispositionFlags, FILE_DISPOSITION_DELETE)) {
                    ULONG index;
                    for (index = 0; index < record->TombstoneCount; ++index)
                        if (record->Tombstones[index].Pid == record->Snapshot.PublicOperation.ActorProcessId &&
                            record->Tombstones[index].Creation == record->Snapshot.PublicOperation.ActorProcessCreationTime &&
                            record->Tombstones[index].Scheduled ==
                                BooleanFlagOn(record->Snapshot.PublicOperation.DispositionFlags, FILE_DISPOSITION_ON_CLOSE)) break;
                    NT_ASSERT(index < (ULONG)RTL_NUMBER_OF(record->Tombstones));
                    if (index < (ULONG)RTL_NUMBER_OF(record->Tombstones)) {
                        record->Tombstones[index].Pid = record->Snapshot.PublicOperation.ActorProcessId;
                        record->Tombstones[index].Creation = record->Snapshot.PublicOperation.ActorProcessCreationTime;
                        record->Tombstones[index].Scheduled =
                            BooleanFlagOn(record->Snapshot.PublicOperation.DispositionFlags, FILE_DISPOSITION_ON_CLOSE);
                        if (index == record->TombstoneCount) record->TombstoneCount++;
                    }
                    record->Snapshot.PublicCleanupOutstanding = TRUE;
                } else {
                    /* Exact ordinary FALSE is stream-wide across owners. It
                     * cannot cancel native CREATE's scheduled per-handle state. */
                    PLIST_ENTRY other;
                    for (other = NativeRecords.Flink; other != &NativeRecords; other = other->Flink) {
                        PSAFEUPLOAD_STAGE_NATIVE_RECORD r = CONTAINING_RECORD(other, SAFEUPLOAD_STAGE_NATIVE_RECORD, Link);
                        if (!NativeScheduled(&r->Snapshot.Binding) && r->Instance == record->Instance &&
                            RtlEqualMemory(&r->Snapshot.Binding.Public.PublicIdentity,
                                &record->Snapshot.Binding.Public.PublicIdentity, sizeof(FILE_ID_INFORMATION))) {
                            ULONG index, retained = 0;
                            BOOLEAN scheduledClear = BooleanFlagOn(record->Snapshot.PublicOperation.DispositionFlags,
                                FILE_DISPOSITION_ON_CLOSE);
                            for (index = 0; index < r->TombstoneCount; ++index) {
                                BOOLEAN clear = scheduledClear ? r == record && r->Tombstones[index].Scheduled :
                                    !r->Tombstones[index].Scheduled;
                                if (!clear) r->Tombstones[retained++] = r->Tombstones[index];
                            }
                            r->TombstoneCount = retained;
                            /* Cleanup obligations remain until their durable
                             * canceled receipts are reconciled by the service. */
                        }
                    }
                }
            }
        }
        record->DispositionFileObject = NULL;
        epoch = record->DispositionEpoch;
        record->DispositionEpoch = NULL;
        if (record->BackendOperation) {
            backend = record->Backend;
            record->BackendOperation = FALSE;
        }
        NativeChanged();
    }
    NativeRelease(irql);
    if (backend != NULL) SafeUploadStagePublicReleaseCallbackOperation(backend);
    SafeUploadPolicyAdmissionRelease(epoch);
    if (record != NULL) {
        NativeWake();
        if (KeGetCurrentIrql() == PASSIVE_LEVEL) NativeDispositionFlush(record);
        KeReleaseSemaphore(&record->DispositionGate, IO_NO_INCREMENT, 1, FALSE);
        SafeUploadStageNativeReleaseRecord(record);
    }
    ExReleaseRundownProtection(&NativeCalls);
    return record != NULL; /* never rewrite the original lower result */
}

_Use_decl_annotations_
BOOLEAN SafeUploadStageNativePostCreate(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
    PSAFEUPLOAD_STAGE_NATIVE_RECORD record;
    FILE_ID_INFORMATION identity;
    NTSTATUS identityStatus = STATUS_UNSUCCESSFUL;
    ULONG returned = 0;
    ACCESS_MASK granted = 0;
    BOOLEAN accepted, checked = FALSE, cancelledBeforeHandle = FALSE, exactObject;
    KIRQL irql;
    if (!NativeEnter()) return FALSE;
    NativeAcquire(&irql);
    record = NativeFindContext(CompletionContext, TRUE);
    if (record != NULL) record->CreateCallbackOwned = FALSE; /* consume producer reference below */
    NativeRelease(irql);
    if (record == NULL) { ExReleaseRundownProtection(&NativeCalls); return FALSE; }
    exactObject = record->Instance == Objects->Instance && record->CreateFileObject == Objects->FileObject &&
        Objects->FileObject != NULL;
    if (exactObject && !FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING))
        cancelledBeforeHandle = !NT_SUCCESS(Data->IoStatus.Status) &&
            FlagOn(Objects->FileObject->Flags, FO_FILE_OPEN_CANCELLED) &&
            !FlagOn(Objects->FileObject->Flags, FO_HANDLE_CREATED);
    accepted = NT_SUCCESS(Data->IoStatus.Status) && Data->IoStatus.Status != STATUS_REPARSE &&
        !cancelledBeforeHandle;
    if (exactObject && !FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) && accepted &&
        KeGetCurrentIrql() == PASSIVE_LEVEL) {
        identityStatus = FltQueryInformationFile(Objects->Instance, Objects->FileObject,
            &identity, sizeof(identity), FileIdInformation, &returned);
        checked = NT_SUCCESS(identityStatus) && returned == sizeof(identity) &&
            RtlEqualMemory(&identity, &record->Snapshot.Binding.Public.PublicIdentity, sizeof(identity)) &&
            Objects->FileObject->DeleteAccess && !Objects->FileObject->WriteAccess;
        if (checked) {
            granted = record->Snapshot.Binding.Public.OriginalDesiredAccess;
            RtlMapGenericMask(&granted, IoGetFileObjectGenericMapping());
        }
    }
    NativeAcquire(&irql);
    record->Snapshot.CreateStatus = Data->IoStatus.Status;
    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) || !exactObject) {
        record->Snapshot.CleanupCoverageLost = TRUE;
        record->FileObject = NULL;
    }
    else if (cancelledBeforeHandle) {
        /* Lower-filter cancellation can hide both acceptance and its CLOSE.
         * It cannot create/reissue an app handle. This is terminal lifetime
         * evidence, not a no-effect result or physical-delete ACK. The exact
         * parent observer must still reconcile original identity/absence. */
        record->Snapshot.CancelledBeforeHandle = TRUE;
        record->Snapshot.IdentityStatus = Data->IoStatus.Status;
        record->FileObject = NULL;
    }
    else {
        record->Snapshot.CreateOutcomeKnown = TRUE;
        record->Snapshot.CreateAccepted = accepted;
        record->Snapshot.IdentityAndDeleteGrantChecked = checked;
        record->Snapshot.IdentityStatus = identityStatus;
        if (checked) record->Snapshot.GrantedAccess = granted;
        if (accepted && NativeScheduled(&record->Snapshot.Binding)) {
            record->TombstoneCount = 1;
            record->Tombstones[0].Pid = record->Snapshot.Binding.Public.CallerProcessId;
            record->Tombstones[0].Creation = record->Snapshot.Binding.Public.CallerProcessCreationTime;
            record->Tombstones[0].Scheduled = TRUE;
        }
        if (!accepted) record->FileObject = NULL;
    }
    record->CreateFileObject = NULL;
    NativeChanged();
    NT_ASSERT(record->References > 1);
    record->References -= 1;
    NativeRelease(irql);
    NativeWake();
    ExReleaseRundownProtection(&NativeCalls);
    /* Preserve NTFS's result, including an accepted scheduled delete whose
     * identity query failed. No cancel-open or optional context dependency. */
    return TRUE;
}

_Use_decl_annotations_
VOID SafeUploadStageNativeNameChanged(PFLT_INSTANCE Instance)
{
    PLIST_ENTRY link = NULL;
    KIRQL irql = PASSIVE_LEVEL;
    BOOLEAN changed = FALSE;
    if (!NativeEnter()) return;
    NativeAcquire(&irql);
    for (link = NativeRecords.Flink; link != &NativeRecords; link = link->Flink) {
        PSAFEUPLOAD_STAGE_NATIVE_RECORD record = CONTAINING_RECORD(link, SAFEUPLOAD_STAGE_NATIVE_RECORD, Link);
        /* The original object may already be gone while another reader keeps
         * its link delete-pending. Retain the same record and re-enumerate on
         * the next event; neither this event nor absence is a cleanup receipt. */
        if (record->Instance == Instance && !record->Snapshot.CleanupCoverageLost &&
            (record->Snapshot.LastHandleCleanedUp || record->Snapshot.CancelledBeforeHandle ||
             record->Snapshot.CancelledCloseObserved || record->Snapshot.PublicCleanupOutstanding)) {
            changed = TRUE;
            break;
        }
    }
    if (changed) NativeChanged();
    NativeRelease(irql);
    if (changed) NativeWake();
    ExReleaseRundownProtection(&NativeCalls);
}

_Use_decl_annotations_
VOID SafeUploadStageNativePostCleanup(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, FLT_POST_OPERATION_FLAGS Flags)
{
    PSAFEUPLOAD_STAGE_NATIVE_RECORD record;
    KIRQL irql;
    UNREFERENCED_PARAMETER(Data);
    if (!NativeEnter()) return;
    NativeAcquire(&irql);
    record = NativeFindObject(Objects->Instance, Objects->FileObject);
    if (record != NULL) {
        if (!FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
            /* Actual CLEANUP itself establishes zero app handles even if
             * filesystem cleanup returns an error. It proves no deletion. */
            record->Snapshot.LastHandleCleanedUp = TRUE;
            record->FileObject = NULL; /* no pointer reuse can match this closed open */
        } else {
            record->Snapshot.CleanupCoverageLost = TRUE;
            record->FileObject = NULL;
        }
        NativeChanged();
    }
    NativeRelease(irql);
    if (record != NULL) NativeWake();
    ExReleaseRundownProtection(&NativeCalls);
}

_Use_decl_annotations_
BOOLEAN SafeUploadStageNativePreClose(PCFLT_RELATED_OBJECTS Objects, PVOID *CompletionContext)
{
    PSAFEUPLOAD_STAGE_NATIVE_RECORD record;
    KIRQL irql;
    *CompletionContext = NULL;
    if (!NativeEnter()) return FALSE;
    NativeAcquire(&irql);
    record = NativeFindObject(Objects->Instance, Objects->FileObject);
    if (record != NULL) {
        NT_ASSERT(!record->CloseCallbackOwned);
        record->References += 1;
        record->CloseCallbackOwned = TRUE;
        record->CloseWasCancelledBeforeHandle =
            FlagOn(Objects->FileObject->Flags, FO_FILE_OPEN_CANCELLED) &&
            !FlagOn(Objects->FileObject->Flags, FO_HANDLE_CREATED);
        record->FileObject = NULL; /* CLOSE may release the allocation after our callback */
        NativeChanged();
        *CompletionContext = record;
    }
    NativeRelease(irql);
    if (record != NULL) NativeWake();
    ExReleaseRundownProtection(&NativeCalls);
    return record != NULL;
}

_Use_decl_annotations_
BOOLEAN SafeUploadStageNativePostClose(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
    PSAFEUPLOAD_STAGE_NATIVE_RECORD record;
    KIRQL irql;
    if (!NativeEnter()) return FALSE;
    NativeAcquire(&irql);
    record = NativeFindContext(CompletionContext, FALSE);
    if (record != NULL) {
        record->CloseCallbackOwned = FALSE;
        if (Objects->Instance == record->Instance && record->CloseWasCancelledBeforeHandle &&
            !FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) && NT_SUCCESS(Data->IoStatus.Status))
            record->Snapshot.CancelledCloseObserved = TRUE;
        else if (!record->Snapshot.LastHandleCleanedUp) record->Snapshot.CleanupCoverageLost = TRUE;
        NT_ASSERT(record->References > 1);
        record->References -= 1;
        NativeChanged();
    }
    NativeRelease(irql);
    if (record != NULL) NativeWake();
    ExReleaseRundownProtection(&NativeCalls);
    return record != NULL;
}

_Use_decl_annotations_
VOID SafeUploadStageNativeInstanceTeardownStart(PFLT_INSTANCE Instance, FLT_INSTANCE_TEARDOWN_FLAGS Reason)
{
    PLIST_ENTRY link;
    BOOLEAN changed = FALSE;
    KIRQL irql;
    if (!NativeEnter()) return;
    NativeAcquire(&irql);
    for (link = NativeRecords.Flink; link != &NativeRecords; link = link->Flink) {
        PSAFEUPLOAD_STAGE_NATIVE_RECORD record = CONTAINING_RECORD(link, SAFEUPLOAD_STAGE_NATIVE_RECORD, Link);
        if (record->Instance == Instance && !record->Snapshot.LastHandleCleanedUp) {
            record->Snapshot.CleanupCoverageLost = TRUE;
            record->Snapshot.TeardownReason = Reason;
            record->FileObject = NULL; /* no CLOSE may arrive; never keep a stale pointer lookup */
            changed = TRUE;
        }
    }
    if (changed) NativeChanged();
    NativeRelease(irql);
    if (changed) NativeWake();
    ExReleaseRundownProtection(&NativeCalls);
}

_Use_decl_annotations_
NTSTATUS SafeUploadStageNativeReadIdentity(GUID *DriverInstanceId, PULONG OsBootSequence)
{
    KIRQL irql;
    RtlZeroMemory(DriverInstanceId, sizeof(*DriverInstanceId));
    *OsBootSequence = 0;
    if (!NativeEnter()) return STATUS_DEVICE_NOT_READY;
    NativeAcquire(&irql);
    *DriverInstanceId = NativeDriverInstance;
    *OsBootSequence = NativeBootSequence;
    NativeRelease(irql);
    ExReleaseRundownProtection(&NativeCalls);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS SafeUploadStageNativeReadRevision(PUINT64 Revision)
{
    KIRQL irql;
    NTSTATUS status;
    *Revision = 0;
    if (!NativeEnter()) return STATUS_DEVICE_NOT_READY;
    NativeAcquire(&irql);
    status = NativeReplayUsable ? STATUS_SUCCESS : STATUS_INTEGER_OVERFLOW;
    if (NT_SUCCESS(status)) *Revision = NativeRevision;
    NativeRelease(irql);
    ExReleaseRundownProtection(&NativeCalls);
    return status;
}

static NTSTATUS NativeReadPage(UINT64 ExpectedRevision, ULONG Offset,
    PSAFEUPLOAD_STAGE_NATIVE_SNAPSHOT Rows, ULONG Capacity, PULONG Count, PUINT64 Revision, PBOOLEAN Complete,
    BOOLEAN Ordinary)
{
    PLIST_ENTRY link;
    PSAFEUPLOAD_STAGE_NATIVE_SNAPSHOT page;
    ULONG index = 0, count = 0;
    UINT64 revision = 0;
    BOOLEAN complete = FALSE;
    KIRQL irql;
    NTSTATUS status = STATUS_SUCCESS;
    *Count = 0; *Revision = 0; *Complete = FALSE;
    if (Capacity == 0 || Capacity > NATIVE_PAGE_LIMIT || (ExpectedRevision == 0 && Offset != 0))
        return STATUS_INVALID_PARAMETER;
    /* Callers' rows may be paged. Fill one bounded nonpaged page under
     * NativeLock and copy it to the caller only after the lock is released. */
    page = ExAllocatePool2(POOL_FLAG_NON_PAGED, (SIZE_T)Capacity * sizeof(*page), NATIVE_RECORD_TAG);
    if (page == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    if (!NativeEnter()) { ExFreePoolWithTag(page, NATIVE_RECORD_TAG); return STATUS_DEVICE_NOT_READY; }
    NativeAcquire(&irql);
    revision = NativeRevision;
    if (!NativeReplayUsable) { status = STATUS_INTEGER_OVERFLOW; goto Exit; }
    if (ExpectedRevision != 0 && ExpectedRevision != NativeRevision) { status = STATUS_RETRY; goto Exit; }
    for (link = NativeRecords.Flink; link != &NativeRecords; link = link->Flink) {
        PSAFEUPLOAD_STAGE_NATIVE_RECORD record = CONTAINING_RECORD(link, SAFEUPLOAD_STAGE_NATIVE_RECORD, Link);
        if (NativeScheduled(&record->Snapshot.Binding) == Ordinary) continue;
        if (index++ < Offset) continue;
        if (count == Capacity) break;
        page[count++] = record->Snapshot;
    }
    if (index < Offset) status = STATUS_INVALID_PARAMETER;
    else complete = link == &NativeRecords;
Exit:
    NativeRelease(irql);
    ExReleaseRundownProtection(&NativeCalls);
    if (count != 0) RtlCopyMemory(Rows, page, (SIZE_T)count * sizeof(*page));
    *Count = count; *Revision = revision; *Complete = complete;
    ExFreePoolWithTag(page, NATIVE_RECORD_TAG);
    return status;
}

_Use_decl_annotations_
NTSTATUS SafeUploadStageNativeReadPage(UINT64 ExpectedRevision, ULONG Offset,
    PSAFEUPLOAD_STAGE_NATIVE_SNAPSHOT Rows, ULONG Capacity, PULONG Count, PUINT64 Revision, PBOOLEAN Complete)
{ return NativeReadPage(ExpectedRevision, Offset, Rows, Capacity, Count, Revision, Complete, FALSE); }

_Use_decl_annotations_
NTSTATUS SafeUploadStagePublicOpenReadPage(UINT64 ExpectedRevision, ULONG Offset,
    PSAFEUPLOAD_STAGE_NATIVE_SNAPSHOT Rows, ULONG Capacity, PULONG Count, PUINT64 Revision, PBOOLEAN Complete)
{ return NativeReadPage(ExpectedRevision, Offset, Rows, Capacity, Count, Revision, Complete, TRUE); }

_Use_decl_annotations_
NTSTATUS SafeUploadStageNativeAcknowledge(const SAFEUPLOAD_STAGE_NATIVE_BINDING *Binding)
{
    PLIST_ENTRY link;
    PSAFEUPLOAD_STAGE_NATIVE_RECORD retired = NULL;
    KIRQL irql;
    NTSTATUS status = STATUS_NOT_FOUND;
    if (!NativeEnter()) return STATUS_DEVICE_NOT_READY;
    /* Bound lengths before comparing a service ACK with immutable metadata. */
    if (!NativeBindingValid(Binding)) { ExReleaseRundownProtection(&NativeCalls); return STATUS_INVALID_PARAMETER; }
    NativeAcquire(&irql);
    for (link = NativeRecords.Flink; link != &NativeRecords; link = link->Flink) {
        PSAFEUPLOAD_STAGE_NATIVE_RECORD record = CONTAINING_RECORD(link, SAFEUPLOAD_STAGE_NATIVE_RECORD, Link);
        if (!NativeBindingEqual(&record->Snapshot.Binding, Binding)) continue;
        if (record->References != 1 || record->FileObject != NULL || record->Backend != NULL ||
            !(record->Snapshot.LastHandleCleanedUp || record->Snapshot.CancelledBeforeHandle ||
              record->Snapshot.CancelledCloseObserved ||
              (record->Snapshot.CreateOutcomeKnown && !record->Snapshot.CreateAccepted))) {
            status = STATUS_DEVICE_BUSY;
        } else {
            RemoveEntryList(&record->Link);
            record->References = 0;
            retired = record;
            NativeChanged();
            status = STATUS_SUCCESS;
        }
        break;
    }
    NativeRelease(irql);
    if (retired != NULL) NativeDestroy(retired);
    if (NT_SUCCESS(status)) NativeWake();
    ExReleaseRundownProtection(&NativeCalls);
    return status;
}

_Use_decl_annotations_
NTSTATUS SafeUploadStagePublicOpenConfirm(const SAFEUPLOAD_STAGE_NATIVE_BINDING *Binding,
    UINT64 ExpectedRevision, UINT64 AuthorityRevision)
{
    PLIST_ENTRY link;
    PSAFEUPLOAD_STAGE_NATIVE_RECORD retired = NULL;
    KIRQL irql;
    NTSTATUS status = STATUS_NOT_FOUND;
    if (!NativeEnter()) return STATUS_DEVICE_NOT_READY;
    if (!NativeBindingValid(Binding) || NativeScheduled(Binding)) {
        ExReleaseRundownProtection(&NativeCalls); return STATUS_INVALID_PARAMETER;
    }
    NativeAcquire(&irql);
    if (ExpectedRevision == 0 || ExpectedRevision != NativeRevision) status = STATUS_RETRY;
    else if (AuthorityRevision == 0 || !SafeUploadStageProtocolNativeForwardAllowed(0, AuthorityRevision))
        status = STATUS_DEVICE_NOT_READY;
    else for (link = NativeRecords.Flink; link != &NativeRecords; link = link->Flink) {
        PSAFEUPLOAD_STAGE_NATIVE_RECORD record = CONTAINING_RECORD(link, SAFEUPLOAD_STAGE_NATIVE_RECORD, Link);
        if (!NativeBindingEqual(&record->Snapshot.Binding, Binding)) continue;
        if (!record->Snapshot.CreateOutcomeKnown && !record->Snapshot.CancelledBeforeHandle &&
            !record->Snapshot.CancelledCloseObserved && !record->Snapshot.CleanupCoverageLost) {
            status = STATUS_DEVICE_BUSY; break;
        }
        if (!record->Snapshot.PublicOpenConfirmed) {
            record->Snapshot.PublicOpenConfirmed = TRUE;
            NativeChanged();
        }
        if (record->Snapshot.PublicOperation.Sequence == 0 && record->Snapshot.PublicCleanupOutstanding) {
            record->Snapshot.PublicCleanupOutstanding = FALSE; /* exact service cleanup/cancellation receipt */
            NativeChanged();
        }
        if (NativeOrdinaryIdle(record) && record->FileObject == NULL) {
            RemoveEntryList(&record->Link); record->References = 0; retired = record;
            NativeChanged();
        }
        status = STATUS_SUCCESS;
        break;
    }
    NativeRelease(irql);
    if (retired != NULL) NativeDestroy(retired);
    if (NT_SUCCESS(status)) NativeWake();
    ExReleaseRundownProtection(&NativeCalls);
    return status;
}

_Use_decl_annotations_
BOOLEAN SafeUploadStageNativeTryCloseAdmission(VOID)
{
    KIRQL irql;
    BOOLEAN closed;
    NativeAcquire(&irql);
    /* A live ordinary open is still a future disposition capability. Veto
     * without erasing it; a later failed preflight must preserve its lookup.
     * A factory has ownership even before its record enters this list. */
    closed = NativeFactories == 0 && IsListEmpty(&NativeRecords) &&
        InterlockedCompareExchange(&NativeRecordCount, 0, 0) == 0;
    if (closed) NativeAccepting = FALSE;
    NativeRelease(irql);
    return closed;
}

VOID SafeUploadStageNativeReopenAdmission(VOID)
{
    KIRQL irql;
    NativeAcquire(&irql);
    if (!SafeUploadStageMandatoryTeardownActive()) NativeAccepting = TRUE;
    NativeRelease(irql);
}

VOID SafeUploadStageNativeCloseAdmission(VOID)
{
    KIRQL irql;
    NativeAcquire(&irql);
    NativeAccepting = FALSE;
    NativeRelease(irql);
}

_Use_decl_annotations_
VOID SafeUploadStageNativeDrainLocal(VOID)
{
    KIRQL irql;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    for (;;) {
        PLIST_ENTRY link, next;
        LIST_ENTRY retired;
        BOOLEAN empty;
        InitializeListHead(&retired);
        NativeAcquire(&irql);
        KeClearEvent(&NativeLocalChanged);
        for (link = NativeRecords.Flink; link != &NativeRecords; link = next) {
            PSAFEUPLOAD_STAGE_NATIVE_RECORD record = CONTAINING_RECORD(link, SAFEUPLOAD_STAGE_NATIVE_RECORD, Link);
            next = link->Flink;
            /* Local retirement is not an ACK. The durable intent/result is
             * left for restart reconciliation. Coverage loss alone is never
             * terminal evidence, even after app/service close or a new GUID. */
            if (record->References != 1 || record->FileObject != NULL || record->Backend != NULL ||
                record->CreateCallbackOwned || record->CloseCallbackOwned || record->DispositionCallbackOwned ||
                !(record->Snapshot.LastHandleCleanedUp || record->Snapshot.CancelledBeforeHandle ||
                  record->Snapshot.CancelledCloseObserved ||
                  (record->Snapshot.CreateOutcomeKnown && !record->Snapshot.CreateAccepted))) continue;
            RemoveEntryList(link);
            record->References = 0;
            InsertTailList(&retired, link);
        }
        empty = IsListEmpty(&NativeRecords) && NativeFactories == 0;
        NativeRelease(irql);
        while (!IsListEmpty(&retired)) {
            PSAFEUPLOAD_STAGE_NATIVE_RECORD record = CONTAINING_RECORD(RemoveHeadList(&retired), SAFEUPLOAD_STAGE_NATIVE_RECORD, Link);
            NativeDestroy(record); /* instance pin drops outside NativeLock */
        }
        if (empty) {
            /* No record still needs a cleanup callback. Close API body
             * admission only now; callback source/code stays until unregister. */
            ExWaitForRundownProtectionRelease(&NativeCalls);
            NativeCallsDrained = TRUE;
            return;
        }
        (VOID)KeWaitForSingleObject(&NativeLocalChanged, Executive, KernelMode, FALSE, NULL);
    }
}

_Use_decl_annotations_
VOID SafeUploadStageNativeUninitialize(VOID)
{
    KIRQL irql;
    NativeAcquire(&irql);
    NativeAccepting = FALSE;
    NT_ASSERT(InterlockedCompareExchange(&NativeRecordCount, 0, 0) == 0);
    NativeRelease(irql);
    InterlockedExchange(&NativeInitialized, 0);
    if (!NativeCallsDrained) ExWaitForRundownProtectionRelease(&NativeCalls);
    NT_ASSERT(IsListEmpty(&NativeRecords));
}
/* Called after publication has installed its reservation. MarkForwarded and
 * disposition consume consult that reservation under NativeLock. A queued
 * request is harmless; a released callback or unresolved result vetoes.
 * Idle checked handles remain tied to their original object across rename. */
_Use_decl_annotations_
BOOLEAN SafeUploadStageNativePublicationIdle(PFLT_INSTANCE Instance)
{
    KIRQL irql;
    PLIST_ENTRY link;
    BOOLEAN idle = TRUE;
    if (!NativeEnter()) return FALSE;
    NativeAcquire(&irql);
    for (link = NativeRecords.Flink; link != &NativeRecords; link = link->Flink) {
        PSAFEUPLOAD_STAGE_NATIVE_RECORD record = CONTAINING_RECORD(link, SAFEUPLOAD_STAGE_NATIVE_RECORD, Link);
        if (record->Instance != Instance) continue;
        if (!record->Snapshot.Forwarded && !record->Snapshot.CreateOutcomeKnown &&
            !record->Snapshot.CleanupCoverageLost) continue; /* queued binding, no native operation released */
        /* A captured request waiting for the service turn has not mutated.
         * Its final consume rechecks BpLock under NativeLock. Native scheduled
         * cleanup still acts only on its original NTFS link; a checked live
         * scheduled open does not serialize every newer save for its lifetime. */
        if (record->Snapshot.CleanupCoverageLost || record->CreateCallbackOwned || record->CloseCallbackOwned ||
            !record->Snapshot.CreateOutcomeKnown || !record->Snapshot.IdentityAndDeleteGrantChecked ||
            record->DispositionCallbackOwned || record->Snapshot.PublicCleanupOutstanding ||
            (record->Snapshot.PublicOperation.Sequence != 0 &&
             record->Snapshot.PublicOperation.Facts != SAFEUPLOAD_PUBLIC_OPERATION_CAPTURED) ||
            (!NativeScheduled(&record->Snapshot.Binding) && !record->Snapshot.PublicOpenConfirmed)) {
            idle = FALSE; break;
        }
    }
    NativeRelease(irql);
    ExReleaseRundownProtection(&NativeCalls);
    return idle;
}
#endif
