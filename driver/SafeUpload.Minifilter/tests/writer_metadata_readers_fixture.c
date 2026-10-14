/* Injectable OS boundaries for production C bodies, inserted by the runner.
 * Four real threads hold reader operations; teardown runs on a fifth thread.
 * No driver build, service connection or Windows authorization is modelled. */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <setjmp.h>
typedef void VOID, *PVOID, *PFLT_INSTANCE, *PFILE_OBJECT;
typedef int32_t LONG, NTSTATUS;
typedef uint32_t ULONG, UINT32, *PULONG;
typedef uint64_t UINT64;
typedef unsigned char UCHAR, BOOLEAN;
typedef struct { UCHAR Bytes[16]; } GUID;
typedef struct { UINT32 Version, StructSize, Command, Reserved; } SAFEUPLOAD_CONTROL;
typedef struct _LIST_ENTRY { struct _LIST_ENTRY *Flink, *Blink; } LIST_ENTRY, *PLIST_ENTRY;
typedef struct { pthread_mutex_t Lock; pthread_cond_t Changed; int Signalled; } KEVENT;
#define EVENT_INITIALIZER { PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 1 }
#define TRUE 1
#define FALSE 0
#define PASSIVE_LEVEL 0
#define IO_NO_INCREMENT 0
#define Executive 0
#define KernelMode 0
#define STATUS_SUCCESS 0
#define STATUS_INVALID_BUFFER_SIZE -1
#define STATUS_INVALID_PARAMETER -2
#define STATUS_ACCESS_DENIED -3
#define STATUS_NOT_FOUND -4
#define STATUS_FLT_DELETING_OBJECT -5
#define STATUS_REVISION_MISMATCH -6
#define STATUS_INSUFFICIENT_RESOURCES -7
#define STATUS_ACCESS_VIOLATION -8
#define STAGE_PUBLIC_TAG 0
#define POOL_FLAG_PAGED 0
#define _Use_decl_annotations_
#define PAGED_CODE() assert(KeGetCurrentIrql() == PASSIVE_LEVEL)
#define NT_ASSERT assert
#define __alignof _Alignof
#define CONTAINING_RECORD(p, t, f) ((t *)((char *)(p) - offsetof(t, f)))
#define RtlEqualMemory(a, b, n) (memcmp((a), (b), (n)) == 0)
#define RtlCopyMemory memcpy
#define min(a, b) ((a) < (b) ? (a) : (b))
/* Model the two probe-exception exits, not Windows SEH itself. */
static _Thread_local jmp_buf Exception;
#define try if (setjmp(Exception) == 0)
#define except(x) else
#define GetExceptionCode() STATUS_ACCESS_VIOLATION
/* PRODUCTION_WIRE */
typedef struct _BACKEND {
    BOOLEAN WriterLease, Closing, TeardownSelected;
    LIST_ENTRY Link;
} SAFEUPLOAD_STAGE_PUBLIC_BACKEND, *PSAFEUPLOAD_STAGE_PUBLIC_BACKEND;
typedef struct {
    SAFEUPLOAD_STAGE_PUBLIC_BACKEND Lifetime;
    BOOLEAN MetadataPublished;
    PVOID MetadataCookie, ProcessHandle;
    SAFEUPLOAD_WRITER_METADATA_HEADER MetadataHeader;
    UCHAR *Metadata;
} SAFEUPLOAD_STAGE_WRITER_LEASE, *PSAFEUPLOAD_STAGE_WRITER_LEASE;
enum { StageWriterMetadataResourceLimit, StageWriterMetadataStale };
static pthread_mutex_t StagePublicListLock = PTHREAD_MUTEX_INITIALIZER;
static LIST_ENTRY StagePublicBackends;
static LONG StagePublicFactories, StagePublicBackendCount, StageWriterMetadataReaders;
static BOOLEAN StagePublicAdmissionClosed, StagePublicOpensDrained;
static KEVENT StageWriterMetadataReadersDrained = EVENT_INITIALIZER;
static int StagePublicOpens;
static SAFEUPLOAD_STAGE_WRITER_LEASE Lease;
static UCHAR Blob[16];
static atomic_int References, Operations, Pages, Mandatory, Closed, RundownWaits, ReaderWaits, PeakPages, Refusals[2];
static pthread_mutex_t PauseLock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t PauseChanged = PTHREAD_COND_INITIALIZER;
static int Paused, ReleaseReaders;
enum { NoFault, ReadProbe, Auth, Operation, Revision, Process, Allocation, Recheck, WriteProbe };
static _Thread_local int Fault, IdentityCalls, PauseReader;

static int KeGetCurrentIrql(void) { return PASSIVE_LEVEL; }
static void FltAcquirePushLockExclusive(pthread_mutex_t *lock) { assert(pthread_mutex_lock(lock) == 0); }
static void FltAcquirePushLockShared(pthread_mutex_t *lock) { FltAcquirePushLockExclusive(lock); }
static void FltReleasePushLock(pthread_mutex_t *lock) { assert(pthread_mutex_unlock(lock) == 0); }
static LONG InterlockedCompareExchange(LONG *p, LONG value, LONG expected)
{ LONG prior = *p; if (prior == expected) *p = value; return prior; }
static int SafeUploadStageMandatoryTeardownActive(void) { return atomic_load(&Mandatory); }
static void KeClearEvent(KEVENT *event)
{ pthread_mutex_lock(&event->Lock); event->Signalled = 0; pthread_mutex_unlock(&event->Lock); }
static void KeSetEvent(KEVENT *event, int increment, int wait)
{
    (void)increment; (void)wait;
    pthread_mutex_lock(&event->Lock); event->Signalled = 1;
    pthread_cond_broadcast(&event->Changed); pthread_mutex_unlock(&event->Lock);
}
static int KeWaitForSingleObject(KEVENT *event, int reason, int mode, int alertable, PVOID timeout)
{
    (void)reason; (void)mode; (void)alertable; (void)timeout;
    assert(event == &StageWriterMetadataReadersDrained);
    atomic_fetch_add(&ReaderWaits, 1);
    pthread_mutex_lock(&PauseLock); pthread_cond_broadcast(&PauseChanged); pthread_mutex_unlock(&PauseLock);
    pthread_mutex_lock(&event->Lock);
    while (!event->Signalled) pthread_cond_wait(&event->Changed, &event->Lock);
    pthread_mutex_unlock(&event->Lock); return 0;
}
static void ExWaitForRundownProtectionRelease(int *opens)
{ assert(opens == &StagePublicOpens); assert(StageWriterMetadataReaders == 0); ++RundownWaits; }
static void ProbeForRead(PVOID input, size_t length, size_t alignment)
{ (void)input; (void)length; (void)alignment; if (Fault == ReadProbe) longjmp(Exception, 1); }
static void ProbeForWrite(PVOID output, size_t length, size_t alignment)
{ (void)output; (void)length; (void)alignment; if (Fault == WriteProbe) longjmp(Exception, 1); }
static BOOLEAN SafeUploadStageProtocolMetadataIdentity(PVOID port, PVOID *cookie, UINT64 *epoch, UINT64 *revision)
{
    ++IdentityCalls;
    if (Fault == Auth || (Fault == Recheck && IdentityCalls == 2)) return FALSE;
    *cookie = port; *epoch = 1; *revision = Fault == Revision ? 2 : 1; return TRUE;
}
static void SafeUploadStagePublicReferenceBackend(PSAFEUPLOAD_STAGE_PUBLIC_BACKEND backend)
{ assert(backend == &Lease.Lifetime); assert(StageWriterMetadataReaders > 0 || StagePublicAdmissionClosed); ++References; }
static void SafeUploadStagePublicDereferenceBackend(PSAFEUPLOAD_STAGE_PUBLIC_BACKEND backend)
{ assert(backend == &Lease.Lifetime); assert(atomic_fetch_sub(&References, 1) > 0); }
static void SafeUploadStagePublicReleaseWriter(PSAFEUPLOAD_STAGE_WRITER_LEASE lease)
{ assert(lease == &Lease); SafeUploadStagePublicDereferenceBackend(&lease->Lifetime); }
static BOOLEAN SafeUploadStagePublicAcquireOperation(PSAFEUPLOAD_STAGE_PUBLIC_BACKEND backend, PFLT_INSTANCE *instance, PFILE_OBJECT *object)
{
    assert(backend == &Lease.Lifetime);
    pthread_mutex_lock(&StagePublicListLock);
    assert(StageWriterMetadataReaders > 0 && StageWriterMetadataReaders <= STAGE_WRITER_MAX_METADATA_READERS);
    pthread_mutex_unlock(&StagePublicListLock);
    if (Fault == Operation) return FALSE;
    ++Operations; ++References; *instance = backend; *object = backend;
    if (PauseReader) {
        pthread_mutex_lock(&PauseLock); ++Paused; pthread_cond_broadcast(&PauseChanged);
        while (!ReleaseReaders) pthread_cond_wait(&PauseChanged, &PauseLock);
        pthread_mutex_unlock(&PauseLock);
    }
    return TRUE;
}
static void SafeUploadStagePublicReleaseOperation(PSAFEUPLOAD_STAGE_PUBLIC_BACKEND backend)
{ assert(atomic_fetch_sub(&Operations, 1) > 0); SafeUploadStagePublicDereferenceBackend(backend); }
static BOOLEAN StageWriterProcessRunning(PVOID process) { (void)process; return Fault != Process; }
static PVOID ExAllocatePool2(int flags, size_t size, int tag)
{
    (void)flags; (void)tag;
    assert(size == 4232); assert(atomic_load(&Operations) > 0);
    if (Fault == Allocation) return NULL;
    int pages = atomic_fetch_add(&Pages, 1) + 1;
    assert(pages <= STAGE_WRITER_MAX_METADATA_READERS);
    int peak = atomic_load(&PeakPages);
    while (peak < pages && !atomic_compare_exchange_weak(&PeakPages, &peak, pages)) { }
    return calloc(1, size);
}
static void ExFreePoolWithTag(PVOID page, int tag)
{ (void)tag; assert(atomic_fetch_sub(&Pages, 1) > 0); free(page); }
static void SafeUploadStagePublicRecordWriterRefusal(int reason) { ++Refusals[reason]; }
static void SafeUploadStagePublicCloseBackend(PSAFEUPLOAD_STAGE_PUBLIC_BACKEND backend)
{ assert(backend == &Lease.Lifetime); assert(Operations == 0 && Pages == 0 && StageWriterMetadataReaders == 0); ++Closed; }
/* PRODUCTION_BODIES */

static SAFEUPLOAD_WRITER_METADATA_REQUEST request(void)
{
    SAFEUPLOAD_WRITER_METADATA_REQUEST r = {0};
    r.Control.Version = SAFEUPLOAD_PROTOCOL_VERSION; r.Control.StructSize = sizeof(r);
    r.Control.Command = SAFEUPLOAD_CONTROL_WRITER_METADATA; r.ExtensionVersion = SAFEUPLOAD_WRITER_METADATA_VERSION;
    r.Phase = SAFEUPLOAD_WRITER_METADATA_DISCOVER; r.DriverInstanceId.Bytes[0] = 1; r.ReservationId.Bytes[0] = 2; r.RequestId = 1;
    return r;
}
static NTSTATUS call(SAFEUPLOAD_WRITER_METADATA_REQUEST r, ULONG *returned)
{
    SAFEUPLOAD_WRITER_METADATA_PAGE page;
    IdentityCalls = 0; *returned = 999;
    return SafeUploadStageWriterMetadataControl(&Lease, &r, sizeof(r), &page, sizeof(page), returned);
}
static void drained(void)
{
    assert(StageWriterMetadataReaders == 0 && StageWriterMetadataReadersDrained.Signalled);
    assert(References == 0 && Operations == 0 && Pages == 0);
}
static void *reader(void *unused)
{
    (void)unused; PauseReader = 1; ULONG returned;
    assert(call(request(), &returned) == STATUS_SUCCESS && returned == 4232); return NULL;
}
static void *closer(void *unused)
{ (void)unused; SafeUploadStagePublicCloseAllBackends(); return NULL; }
int main(void)
{
    _Static_assert(sizeof(SAFEUPLOAD_WRITER_METADATA_REQUEST) == 136, "request layout");
    ULONG returned;
    SAFEUPLOAD_WRITER_METADATA_REQUEST r = request();
    StagePublicBackends.Flink = StagePublicBackends.Blink = &Lease.Lifetime.Link;
    Lease.Lifetime.Link.Flink = Lease.Lifetime.Link.Blink = &StagePublicBackends;
    Lease.Lifetime.WriterLease = Lease.MetadataPublished = TRUE; Lease.MetadataCookie = &Lease; Lease.Metadata = Blob;
    Lease.MetadataHeader.DriverInstanceId = r.DriverInstanceId; Lease.MetadataHeader.ReservationId = r.ReservationId;
    Lease.MetadataHeader.RequestId = Lease.MetadataHeader.ConnectionEpoch = Lease.MetadataHeader.AuthorityRevision = 1;
    Lease.MetadataHeader.SnapshotId.Bytes[0] = 3; Lease.MetadataHeader.TotalBytes = sizeof(Blob);
    /* Every post-reservation failure class must return its slot and all pins. */
    for (Fault = NoFault; Fault <= WriteProbe; ++Fault) {
        NTSTATUS status = call(r, &returned);
        assert(Fault == NoFault ? status == STATUS_SUCCESS && returned == 4232 : status < 0 && returned == 0);
        drained();
    }
    Fault = NoFault;
    r.RequestId = 999; assert(call(r, &returned) == STATUS_NOT_FOUND && returned == 0); drained();
    r = request(); r.Phase = SAFEUPLOAD_WRITER_METADATA_READ; r.ConnectionEpoch = r.AuthorityRevision = 1;
    r.SnapshotId = Lease.MetadataHeader.SnapshotId; r.Offset = 1;
    assert(call(r, &returned) == STATUS_INVALID_PARAMETER && returned == 0); drained();
    r.Offset = 0; assert(call(r, &returned) == STATUS_SUCCESS); drained();
    r.Phase = SAFEUPLOAD_WRITER_METADATA_CONFIRM; r.Offset = sizeof(Blob);
    assert(call(r, &returned) == STATUS_SUCCESS); drained();
    r.SnapshotId.Bytes[0] = 99; assert(call(r, &returned) == STATUS_REVISION_MISMATCH); drained();
    Mandatory = 1;
    assert(call(request(), &returned) == STATUS_FLT_DELETING_OBJECT && returned == 0); drained();
    Mandatory = 0;
    /* Four native callers pin operations. A fifth cannot get a pin or page. */
    pthread_t readers[STAGE_WRITER_MAX_METADATA_READERS], closeThread;
    for (int i = 0; i < STAGE_WRITER_MAX_METADATA_READERS; ++i) assert(pthread_create(&readers[i], NULL, reader, NULL) == 0);
    pthread_mutex_lock(&PauseLock);
    while (Paused != STAGE_WRITER_MAX_METADATA_READERS) pthread_cond_wait(&PauseChanged, &PauseLock);
    pthread_mutex_unlock(&PauseLock);
    assert(StageWriterMetadataReaders == STAGE_WRITER_MAX_METADATA_READERS && Operations == STAGE_WRITER_MAX_METADATA_READERS);
    int references = atomic_load(&References), refusals = atomic_load(&Refusals[StageWriterMetadataResourceLimit]);
    assert(call(request(), &returned) == STATUS_INSUFFICIENT_RESOURCES && returned == 0);
    assert(References == references && Pages == 0 && Refusals[StageWriterMetadataResourceLimit] == refusals + 1);
    /* Isolate reader veto from backend count, then verify mandatory local drain. */
    assert(!SafeUploadStagePublicTryCloseAdmission() && !StagePublicAdmissionClosed);
    Mandatory = 1;
    assert(pthread_create(&closeThread, NULL, closer, NULL) == 0);
    pthread_mutex_lock(&PauseLock);
    while (ReaderWaits == 0) pthread_cond_wait(&PauseChanged, &PauseLock);
    assert(Closed == 0 && RundownWaits == 0);
    assert(call(request(), &returned) == STATUS_FLT_DELETING_OBJECT && returned == 0);
    ReleaseReaders = 1; pthread_cond_broadcast(&PauseChanged); pthread_mutex_unlock(&PauseLock);
    for (int i = 0; i < STAGE_WRITER_MAX_METADATA_READERS; ++i) assert(pthread_join(readers[i], NULL) == 0);
    assert(pthread_join(closeThread, NULL) == 0); drained(); assert(Closed == 1 && RundownWaits == 1);
    SafeUploadStagePublicCloseAllBackends(); assert(Closed == 1 && RundownWaits == 1);
    SafeUploadStagePublicReopenAdmission(); assert(StagePublicAdmissionClosed);
    Mandatory = 0; SafeUploadStagePublicReopenAdmission(); assert(!StagePublicAdmissionClosed);
    assert(call(request(), &returned) == STATUS_SUCCESS); drained();
    assert(SafeUploadStagePublicTryCloseAdmission());
    assert(call(request(), &returned) == STATUS_FLT_DELETING_OBJECT); drained();
    puts("writer metadata reader controls: saturation, failure cleanup, voluntary veto, local teardown passed");
    return 0;
}
