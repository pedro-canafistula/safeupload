#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define _Inout_
#define TRUE 1
#define FALSE 0
#define VOID void
#define PAGED_CODE() assert(held == 0)
#define NT_ASSERT assert
#define PASSIVE_LEVEL 0
#define NT_SUCCESS(s) ((s) >= 0)
#define STATUS_SUCCESS 0
#define STATUS_IO_TIMEOUT (-1)
#define STATUS_PORT_DISCONNECTED (-2)
#define STATUS_INVALID_DEVICE_STATE (-3)
#define STATUS_INVALID_BUFFER_SIZE (-4)
#define STATUS_DELETE_PENDING (-5)
#define STATUS_CANCELLED (-6)
#define STATUS_VOLUME_DISMOUNTED (-7)
#define STATUS_ACCESS_DENIED (-8)
#define STAGE_WAIT_NONE 0
#define STAGE_WAIT_EXCHANGE 1
#define STAGE_WAIT_SERVICE 2
#define SAFEUPLOAD_OPERATION_STAGE_ATTACH_PREPARE 12
#define SAFEUPLOAD_OPERATION_STAGE_ATTACH_COMMIT 13
#define SAFEUPLOAD_OPERATION_STAGE_ATTACH_ABORT 14
#define SAFEUPLOAD_OPERATION_STAGE_ATTACH_COMPLETION_PERMITTED 15
#define SAFEUPLOAD_STAGE_RESULT_ATTACH_PREPARED 6
#define SAFEUPLOAD_STAGE_RESULT_ATTACH_COMMITTED 7
#define SAFEUPLOAD_STAGE_RESULT_ATTACH_ABORTED 8
#define SAFEUPLOAD_STAGE_RESULT_ATTACH_COMMIT_DENIED 9
#define SAFEUPLOAD_STAGE_RESULT_ATTACH_ALREADY_COMMITTED 10
#define SAFEUPLOAD_STAGE_RESULT_COMPLETION_PERMITTED 16
#define SAFEUPLOAD_STAGE_DISCARD_KIND_PRIVATE_VERSION 4
#define SAFEUPLOAD_STAGE_DISCARD_KIND_UNATTACHED_ALLOCATION 5
#define SAFEUPLOAD_STAGE_REPLY_DISCARD_ACKNOWLEDGED 3
typedef int NTSTATUS, BOOLEAN, LONG;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef struct { int value; } GUID, IDENTITY;
typedef struct { struct LIST *Flink, *Blink; } UNUSED_LIST;
typedef struct LIST { struct LIST *Flink, *Blink; } LIST_ENTRY, *PLIST_ENTRY;
typedef struct { UINT64 RequestId; } REQUEST;
typedef struct VIEW { int Detached; void *Current; } VIEW;
typedef struct STREAM {
    LIST_ENTRY RpcLink;
    VIEW *View;
    int Name, StageName, OriginalInstance, RpcProcessIdSnapshot;
    GUID TransferId, DriverInstanceId, DeleteReservationId, RpcReservationSnapshot, RpcTransferIdSnapshot;
    IDENTITY StageIdentity, RpcIdentitySnapshot, AllocationParentDirectoryIdentity;
    UINT64 DestinationGeneration, RpcGenerationSnapshot;
    REQUEST AttachPrepareRequest, AttachCommitRequest, AttachAbortRequest, AttachCompletionRequest;
    REQUEST AllocationIntent, AllocationRequest;
    BOOLEAN HasTransferId, StageIdentityValid, AttachLifecycleInFlight;
    BOOLEAN AttachPrepareMayExist, AttachPrepareKnown, AttachCommitMayExist, AttachCommitKnown;
    UINT32 AttachCommitResult;
    BOOLEAN AttachCompletionMayExist, AttachCompletionKnown, AttachCompletionPending, AttachTerminalPending;
    BOOLEAN AllocationReceiptPending, AllocationTupleKnown, AllocationRecoveryPending, AllocationRecoveryInFlight;
    BOOLEAN DiscardRpcPending, DiscardRpcInFlight, Discarded, Sealed, Retired, ReservationLinked, PrivateDeleteReserved;
    int Wait, DrainStatus, RpcReferences, AllocationReceiptReferences;
    UINT32 DiscardRpcKind, RpcKindSnapshot;
    struct STREAM *AllocationReceiptParent;
} STAGE_STREAM, *PSTAGE_STREAM;
typedef struct {
    PSTAGE_STREAM Stream;
    LONG CancelRequested, TeardownRequested;
    int CallbackData, UnexposedRetirementAllowed, CompletionKnown;
} STAGE_ATTACH_TRANSACTION, *PSTAGE_ATTACH_TRANSACTION;
static int held, StageNamespaceResource, abortCalls, discardCalls, clearCalls, queueCalls;
static int mandatory, ready = TRUE, abortStatus, discardStatus, changeChannel, changeIdentity;
static UINT32 abortResult = SAFEUPLOAD_STAGE_RESULT_ATTACH_ABORTED, discardResult;
static int prepareMayExist = TRUE;
static LONG StageServiceGeneration = 1, StageReconcileNeeded;
static int StageServiceAvailable = TRUE;
static struct { int WakeInline; } StageCounters;
static void StageAcquire(int *r) { (void)r; assert(held++ == 0); }
static void StageRelease(int *r) { (void)r; assert(--held == 0); }
static LONG InterlockedCompareExchange(LONG *v, LONG set, LONG expected) { LONG old = *v; if (old == expected) *v = set; return old; }
static LONG InterlockedExchange(LONG *v, LONG set) { LONG old = *v; *v = set; return old; }
static LONG InterlockedDecrement(LONG *v) { return --*v; }
static int KeGetCurrentIrql(void) { return PASSIVE_LEVEL; }
static int SafeUploadStageMandatoryTeardownActive(void) { return mandatory; }
static int SafeUploadStageProtocolIsReady(void) { return ready; }
static int FltIsIoCanceled(int data) { (void)data; return FALSE; }
static int StageVolumeKind(int instance) { (void)instance; return 1; }
static int StageV19IdentityEqual(const IDENTITY *a, const IDENTITY *b) { return a->value == b->value; }
#define RtlEqualMemory(a,b,n) (memcmp(a,b,n) == 0)
#define RtlZeroMemory(a,n) memset(a,0,n)
#define CONTAINING_RECORD(p,t,f) ((t *)((char *)(p) - offsetof(t,f)))
static void InitializeListHead(PLIST_ENTRY h) { h->Flink = h->Blink = h; }
static int IsListEmpty(PLIST_ENTRY h) { return h->Flink == h; }
static PLIST_ENTRY RemoveHeadList(PLIST_ENTRY h) { PLIST_ENTRY e = h->Flink; h->Flink = e->Flink; e->Flink->Blink = h; return e; }
static void insert(PLIST_ENTRY h, PLIST_ENTRY e) { e->Flink = h; e->Blink = h->Blink; h->Blink->Flink = e; h->Blink = e; }
static void StageQueueStream(PSTAGE_STREAM s, int *counter) { (void)s; (void)counter; assert(held); ++queueCalls; }
static void StageUpdateRetryTimer(void) { assert(held); }
static void StageRemoveAllocationNameReservation(PSTAGE_STREAM s) { assert(held); s->ReservationLinked = FALSE; }
static void StageClearPrivateDelete(PSTAGE_STREAM s) {
    assert(held && !s->AllocationReceiptPending && !s->DiscardRpcInFlight);
    s->PrivateDeleteReserved = FALSE; ++clearCalls;
}
static NTSTATUS StageAttachValidateCurrent(PSTAGE_ATTACH_TRANSACTION t, PSTAGE_STREAM s) { (void)t; (void)s; return STATUS_SUCCESS; }
static NTSTATUS StageAttachExchangeRetry(PSTAGE_ATTACH_TRANSACTION t, UINT32 op, REQUEST *r, UINT32 *result) {
    assert(held == 0); (void)r; *result = 0;
    assert(op == SAFEUPLOAD_OPERATION_STAGE_ATTACH_PREPARE);
    t->Stream->AttachPrepareMayExist = prepareMayExist;
    return STATUS_IO_TIMEOUT;
}
static NTSTATUS SafeUploadStageAttachmentExchangeV20(int pid, int *name, int kind, UINT32 op,
    const GUID *id, UINT64 generation, const IDENTITY *identity, const GUID *driver,
    const IDENTITY *parent, REQUEST *request, UINT32 *result, BOOLEAN *mayExist) {
    assert(held == 0 && op == SAFEUPLOAD_OPERATION_STAGE_ATTACH_ABORT);
    assert(pid == 42 && *name == 7 && kind == 1 && id->value == 11 && generation == 9);
    assert(identity->value == 13 && driver->value == 17 && parent->value == 19);
    if (request->RequestId == 0) request->RequestId = 101;
    assert(request->RequestId == 101); ++abortCalls; *result = abortResult; *mayExist = TRUE;
    return abortStatus;
}
static PSTAGE_STREAM active;
static NTSTATUS SafeUploadStageDiscardVersionV19(int pid, int *name, const GUID *reservation,
    const IDENTITY *identity, UINT64 generation, UINT32 kind, UINT32 *result) {
    assert(held == 0 && pid == 42 && *name == 23 && reservation->value == 11);
    assert(identity->value == 13 && generation == 9 && kind == 5);
    ++discardCalls; *result = discardResult;
    if (changeChannel) ++StageServiceGeneration;
    if (changeIdentity) ++active->StageIdentity.value;
    return discardStatus;
}
/* PRODUCTION */
static void setup(PSTAGE_STREAM s, VIEW *v) {
    memset(s, 0, sizeof(*s)); memset(v, 0, sizeof(*v)); s->View = v; v->Current = s;
    s->Name = 7; s->StageName = 23; s->HasTransferId = s->StageIdentityValid = TRUE;
    s->TransferId.value = s->RpcTransferIdSnapshot.value = s->RpcReservationSnapshot.value = 11;
    s->DriverInstanceId.value = 17; s->AllocationParentDirectoryIdentity.value = 19;
    s->StageIdentity.value = s->RpcIdentitySnapshot.value = 13;
    s->DestinationGeneration = s->RpcGenerationSnapshot = 9; s->RpcProcessIdSnapshot = 42;
    s->AllocationReceiptPending = s->AllocationTupleKnown = s->PrivateDeleteReserved = s->ReservationLinked = TRUE;
    s->AttachCompletionPending = s->AttachLifecycleInFlight = TRUE;
    s->DiscardRpcKind = s->RpcKindSnapshot = 5;
    abortCalls = discardCalls = clearCalls = queueCalls = changeChannel = changeIdentity = 0;
    abortStatus = discardStatus = STATUS_SUCCESS; abortResult = SAFEUPLOAD_STAGE_RESULT_ATTACH_ABORTED;
    discardResult = SAFEUPLOAD_STAGE_REPLY_DISCARD_ACKNOWLEDGED; mandatory = FALSE; active = s;
}
static void attempt(PSTAGE_STREAM s) {
    LIST_ENTRY work; InitializeListHead(&work); InitializeListHead(&s->RpcLink); insert(&work, &s->RpcLink);
    s->DiscardRpcInFlight = TRUE; s->DiscardRpcPending = FALSE; s->RpcReferences = 1;
    StagePerformDiscardRpcs(&work);
    assert(held == 0 && s->RpcReferences == 0 && IsListEmpty(&work));
}
int main(void) {
    STAGE_STREAM s, parent; VIEW v;
    for (prepareMayExist = FALSE; prepareMayExist <= TRUE; ++prepareMayExist) {
        setup(&s, &v); STAGE_ATTACH_TRANSACTION t = { .Stream = &s };
        assert(StageAttachRunLifecycle(&t, &s) == STATUS_IO_TIMEOUT);
        assert(s.AttachTerminalPending && s.AllocationReceiptPending && !s.AttachCompletionPending);
        assert(!s.AttachCommitMayExist && !s.AttachCompletionMayExist && !clearCalls);
        s.AttachLifecycleInFlight = FALSE; /* actual worker rolls back binding before collection */
        attempt(&s);
        assert(abortCalls == prepareMayExist && discardCalls == 1 && clearCalls == 1);
        assert(s.Retired && s.Discarded && s.Sealed && v.Detached && !s.AllocationReceiptPending);
    }
    prepareMayExist = TRUE;
    setup(&s, &v); s.AttachPrepareMayExist = TRUE;
    abortStatus = STATUS_IO_TIMEOUT; attempt(&s);
    assert(abortCalls == 1 && !discardCalls && !clearCalls && s.DiscardRpcPending && !s.Retired);
    abortStatus = STATUS_SUCCESS; discardResult = 1; attempt(&s);
    assert(abortCalls == 2 && discardCalls == 1 && !clearCalls && s.DiscardRpcPending);
    memset(&parent, 0, sizeof(parent)); parent.AllocationReceiptReferences = 1; s.AllocationReceiptParent = &parent;
    discardResult = SAFEUPLOAD_STAGE_REPLY_DISCARD_ACKNOWLEDGED; attempt(&s);
    assert(clearCalls == 1 && !s.AllocationReceiptParent && !parent.AllocationReceiptReferences && v.Detached);
    setup(&s, &v); s.AttachPrepareMayExist = TRUE; abortResult = SAFEUPLOAD_STAGE_RESULT_ATTACH_ALREADY_COMMITTED;
    attempt(&s); assert(!discardCalls && !clearCalls && !s.Retired);
    for (int permission = 0; permission < 4; ++permission) {
        setup(&s, &v); s.AttachPrepareMayExist = TRUE;
        if (permission == 0) s.AttachCommitMayExist = TRUE;
        if (permission == 1) s.AttachCommitKnown = TRUE;
        if (permission == 2) s.AttachCompletionMayExist = TRUE;
        if (permission == 3) s.AttachCompletionKnown = TRUE;
        attempt(&s); assert(!abortCalls && !discardCalls && !clearCalls);
    }
    setup(&s, &v); s.AttachPrepareMayExist = s.AttachPrepareKnown = TRUE;
    attempt(&s); assert(!abortCalls && discardCalls == 1 && clearCalls == 1); /* existing confirmed Abort path */
    setup(&s, &v); mandatory = TRUE; attempt(&s); assert(!abortCalls && !discardCalls && !clearCalls);
    setup(&s, &v); changeChannel = TRUE; attempt(&s); assert(!clearCalls && s.AllocationReceiptPending && !v.Detached);
    changeChannel = FALSE; attempt(&s); assert(clearCalls == 1 && v.Detached);
    setup(&s, &v); changeIdentity = TRUE; attempt(&s); assert(!clearCalls && s.AllocationReceiptPending);
    puts("allocation reply production controls PASS (timeout, late/retried abort, pending/ACK, tuple/channel/permission/teardown gates)");
    return 0;
}
