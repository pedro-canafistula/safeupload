/* T5 original-NTFS-object fallback records. The CREATE producer and service
 * exporter are connected separately. A FILE_OBJECT reference would prevent
 * CLOSE after an upper filter cancels CREATE before any handle exists. Use
 * a non-owning key, removed at CLEANUP/CLOSE or callback-coverage loss. No NTFS section
 * pointer is borrowed, no service call runs under this lock, and no receipt
 * here certifies physical deletion. Normal builds omit this module. */
#include "StageNativeRecords.h"
#include "StageNativeWire.h"
#include "Stage.h"

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
static BOOLEAN NativeAccepting;
static BOOLEAN NativeReplayUsable;
static UINT64 NativeRevision;

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
}

static VOID NativeWake(VOID)
{ KeSetEvent(NativeWakeEvent, IO_NO_INCREMENT, FALSE); }

/* NativeLock. Another native reader may retain a delete-pending link after
 * the scheduled creator's cleanup. Its CLEANUP/CLOSE is a resolving event
 * even when that reader has no record of its own. It triggers exact anchored
 * observation only; it supplies no lifetime, unlink or cleanup-ACK proof. */
static BOOLEAN NativeNameMayResolveLocked(PFLT_INSTANCE Instance)
{
    PLIST_ENTRY link;
    for (link = NativeRecords.Flink; link != &NativeRecords; link = link->Flink) {
        PSAFEUPLOAD_STAGE_NATIVE_RECORD record = CONTAINING_RECORD(link, SAFEUPLOAD_STAGE_NATIVE_RECORD, Link);
        if (record->Instance == Instance && !record->Snapshot.CleanupCoverageLost &&
            record->Snapshot.Forwarded &&
            ((record->Snapshot.CreateOutcomeKnown && record->Snapshot.CreateAccepted &&
              record->Snapshot.LastHandleCleanedUp) ||
             (record->Snapshot.CancelledBeforeHandle && record->Snapshot.CancelledCloseObserved)))
            return TRUE;
    }
    return FALSE;
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
        FlagOn(p->OriginalDesiredAccess, FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
            FILE_WRITE_ATTRIBUTES | FILE_DELETE_CHILD | GENERIC_WRITE | GENERIC_ALL | MAXIMUM_ALLOWED) ||
        !FlagOn(p->OriginalDesiredAccess, DELETE) || p->GrantedAccess != 0 ||
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

/* NativeLock. The map reference prevents destruction until an exact ACK;
 * callbacks never own the final reference or free objects at elevated IRQL. */
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

_IRQL_requires_(PASSIVE_LEVEL)
static VOID NativeDestroy(PSAFEUPLOAD_STAGE_NATIVE_RECORD Record)
{
    NT_ASSERT(Record->References == 0);
    NT_ASSERT(Record->FileObject == NULL);
    FltObjectDereference(Record->Instance);
    ExFreePoolWithTag(Record, NATIVE_RECORD_TAG);
    InterlockedDecrement(&NativeRecordCount);
}

_Use_decl_annotations_
VOID SafeUploadStageNativeInitialize(const GUID *DriverInstanceId, ULONG OsBootSequence, PKEVENT WakeEvent)
{
    KeInitializeSpinLock(&NativeLock);
    ExInitializeRundownProtection(&NativeCalls);
    InitializeListHead(&NativeRecords);
    NativeDriverInstance = *DriverInstanceId;
    NativeBootSequence = OsBootSequence;
    NativeWakeEvent = WakeEvent;
    InterlockedExchange(&NativeRecordCount, 0);
    NativeRevision = 1;
    NativeReplayUsable = TRUE;
    NativeAccepting = TRUE;
    InterlockedExchange(&NativeInitialized, 1);
}

_Use_decl_annotations_
NTSTATUS SafeUploadStageNativeReserve(PFLT_INSTANCE Instance, PFILE_OBJECT FileObject,
    const SAFEUPLOAD_STAGE_NATIVE_BINDING *Binding, PSAFEUPLOAD_STAGE_NATIVE_RECORD *Record)
{
    PSAFEUPLOAD_STAGE_NATIVE_RECORD item = NULL;
    PLIST_ENTRY link;
    KIRQL irql;
    NTSTATUS status;
    *Record = NULL;
    if (!NativeEnter()) return STATUS_DEVICE_NOT_READY;
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
    status = FltObjectReference(Instance);
    if (!NT_SUCCESS(status)) goto Fail;
    item->Instance = Instance;
    item->FileObject = FileObject;
    item->CreateFileObject = FileObject;
    NativeCopyBinding(&item->Snapshot.Binding, Binding);
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
Exit:
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
    UINT64 DurableGeneration, UINT64 ExpectedRevision, UINT64 AuthorityRevision)
{
    KIRQL irql;
    NTSTATUS status = STATUS_SUCCESS;
    NativeAcquire(&irql);
    if (ExpectedRevision != 0 && ExpectedRevision != NativeRevision) status = STATUS_RETRY;
    else if (!NativeAccepting || !NativeReplayUsable || ExpectedRevision == 0 ||
        AuthorityRevision == 0 ||
        !SafeUploadStageProtocolNativeForwardAllowed(Record->Snapshot.Binding.ConnectionEpoch, AuthorityRevision) ||
        DurableGeneration == 0 || Record->Snapshot.Forwarded ||
        Record->Snapshot.CreateOutcomeKnown || Record->Snapshot.CleanupCoverageLost ||
        SafeUploadStageAttachInstanceRetiring(Record->Instance)) status = STATUS_INVALID_DEVICE_STATE;
    else {
        Record->Snapshot.JournalGeneration = DurableGeneration;
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
    NT_ASSERT(Record->References > 1); /* the map is retired only with no other users */
    NT_ASSERT(!Record->CreateCallbackOwned);
    Record->References -= 1;
    if (Record->References == 1) NativeChanged(); /* ACK eligibility changed, even without new CREATE facts. */
    NativeRelease(irql);
    NativeWake(); /* an ACK previously refused for an active producer may now proceed */
}

_Use_decl_annotations_
BOOLEAN SafeUploadStageNativePostCreate(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
    PSAFEUPLOAD_STAGE_NATIVE_RECORD record;
    FILE_ID_INFORMATION identity;
    NTSTATUS identityStatus = STATUS_UNSUCCESSFUL;
    ULONG returned = 0;
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
VOID SafeUploadStageNativePostCleanup(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, FLT_POST_OPERATION_FLAGS Flags)
{
    PSAFEUPLOAD_STAGE_NATIVE_RECORD record;
    KIRQL irql;
    BOOLEAN changed = FALSE;
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
        changed = TRUE;
    } else if (!FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) && NativeNameMayResolveLocked(Objects->Instance)) {
        NativeChanged();
        changed = TRUE;
    }
    NativeRelease(irql);
    if (changed) NativeWake();
    ExReleaseRundownProtection(&NativeCalls);
}

_Use_decl_annotations_
BOOLEAN SafeUploadStageNativePreClose(PCFLT_RELATED_OBJECTS Objects, PVOID *CompletionContext)
{
    PSAFEUPLOAD_STAGE_NATIVE_RECORD record;
    KIRQL irql;
    BOOLEAN observeClose;
    *CompletionContext = NULL;
    if (!NativeEnter()) return FALSE;
    NativeAcquire(&irql);
    record = NativeFindObject(Objects->Instance, Objects->FileObject);
    observeClose = record == NULL && NativeNameMayResolveLocked(Objects->Instance);
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
    /* A null context owns no record reference. Filter Manager preserves the
     * instance/callback lifetime for this observe-only synchronized post. */
    return record != NULL || observeClose;
}

_Use_decl_annotations_
BOOLEAN SafeUploadStageNativePostClose(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
    PSAFEUPLOAD_STAGE_NATIVE_RECORD record;
    KIRQL irql;
    BOOLEAN changed = FALSE;
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
        changed = TRUE;
    } else if (!FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) && NativeNameMayResolveLocked(Objects->Instance)) {
        NativeChanged();
        changed = TRUE;
    }
    NativeRelease(irql);
    if (changed) NativeWake();
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
NTSTATUS SafeUploadStageNativeReadPage(UINT64 ExpectedRevision, ULONG Offset,
    PSAFEUPLOAD_STAGE_NATIVE_SNAPSHOT Rows, ULONG Capacity, PULONG Count, PUINT64 Revision, PBOOLEAN Complete)
{
    PLIST_ENTRY link;
    ULONG index = 0;
    KIRQL irql;
    NTSTATUS status = STATUS_SUCCESS;
    *Count = 0; *Revision = 0; *Complete = FALSE;
    if (Capacity == 0 || Capacity > NATIVE_PAGE_LIMIT || (ExpectedRevision == 0 && Offset != 0))
        return STATUS_INVALID_PARAMETER;
    if (!NativeEnter()) return STATUS_DEVICE_NOT_READY;
    NativeAcquire(&irql);
    *Revision = NativeRevision;
    if (!NativeReplayUsable) { status = STATUS_INTEGER_OVERFLOW; goto Exit; }
    if (ExpectedRevision != 0 && ExpectedRevision != NativeRevision) { status = STATUS_RETRY; goto Exit; }
    for (link = NativeRecords.Flink; link != &NativeRecords; link = link->Flink) {
        PSAFEUPLOAD_STAGE_NATIVE_RECORD record = CONTAINING_RECORD(link, SAFEUPLOAD_STAGE_NATIVE_RECORD, Link);
        if (index++ < Offset) continue;
        if (*Count == Capacity) break;
        Rows[*Count] = record->Snapshot;
        *Count += 1;
    }
    if (index < Offset) status = STATUS_INVALID_PARAMETER;
    else *Complete = link == &NativeRecords;
Exit:
    NativeRelease(irql);
    ExReleaseRundownProtection(&NativeCalls);
    return status;
}

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
        if (record->References != 1 || record->FileObject != NULL ||
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

BOOLEAN SafeUploadStageNativeTryCloseAdmission(VOID)
{
    KIRQL irql;
    BOOLEAN closed;
    NativeAcquire(&irql);
    closed = InterlockedCompareExchange(&NativeRecordCount, 0, 0) == 0;
    if (closed) NativeAccepting = FALSE;
    NativeRelease(irql);
    return closed;
}

VOID SafeUploadStageNativeReopenAdmission(VOID)
{
    KIRQL irql;
    NativeAcquire(&irql);
    NativeAccepting = TRUE;
    NativeRelease(irql);
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
    ExWaitForRundownProtectionRelease(&NativeCalls);
    NT_ASSERT(IsListEmpty(&NativeRecords));
}
#endif
