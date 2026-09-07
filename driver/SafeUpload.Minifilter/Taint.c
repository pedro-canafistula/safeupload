/*++

Module Name:

    Taint.c

Abstract:

    Process taint table: which processes have obtained access to sensitive
    content, and therefore must not write to a monitored destination.

    This is what makes it possible to refuse a copy before a single byte is
    written. The expensive question - "is this file sensitive?" - is asked
    once, when the source is opened, and its answer is remembered against
    the process. The cheap question - "may this process write here?" - is
    then a hash lookup, which is why it can be answered in pre-create,
    where refusing costs nothing and leaves nothing behind.

    Three costs are accepted deliberately, because no product solves them
    and pretending otherwise would be worse than writing them down:

    - False positives. A process that read something sensitive and then
      writes something unrelated is refused. The TTL bounds how long.

    - Long-lived processes. Explorer and browsers accumulate taint that a
      TTL, not correctness, is what releases.

    - Indirect paths. Process A reads, hands the content to B over IPC, B
      writes. Not covered, and not detectable from here.

Environment:

    Kernel mode

--*/

#include "Filter.h"

//
//  Buckets keyed by PID. The table is small in practice - tens of entries -
//  but bucketing keeps the walk short without the complexity of anything
//  cleverer.
//

#define SAFEUPLOAD_TAINT_BUCKETS 64

typedef struct _SAFEUPLOAD_TAINT_ENTRY {

    LIST_ENTRY Link;

    ULONG ProcessId;

    //
    //  What was found. Carried through so that a later version can report
    //  why a write was refused instead of merely that it was.
    //

    UINT32 Categories;

    //
    //  Interrupt time when the taint was recorded. Monotonic, unaffected by
    //  clock changes - which matters, because a user adjusting the system
    //  clock must not extend or cancel a taint.
    //

    ULONGLONG TaintedAt;

} SAFEUPLOAD_TAINT_ENTRY, *PSAFEUPLOAD_TAINT_ENTRY;

static EX_PUSH_LOCK SafeUploadTaintLock;
static LIST_ENTRY SafeUploadTaintBuckets[SAFEUPLOAD_TAINT_BUCKETS];
static BOOLEAN SafeUploadTaintNotifyRegistered = FALSE;

static
VOID
SafeUploadProcessNotify (
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create
    );

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(PAGE, SafeUploadInitializeTaint)
    #pragma alloc_text(PAGE, SafeUploadFreeTaint)
    #pragma alloc_text(PAGE, SafeUploadProcessNotify)
#endif


static
ULONG
SafeUploadTaintBucket (
    _In_ ULONG ProcessId
    )
/*++

Routine Description:

    Bucket index for a PID. Process ids are multiples of four, so the low
    two bits carry no information and are shifted out before folding.

--*/
{
    return (ProcessId >> 2) % SAFEUPLOAD_TAINT_BUCKETS;
}


static
BOOLEAN
SafeUploadTaintExpired (
    _In_ PSAFEUPLOAD_TAINT_ENTRY Entry,
    _In_ ULONGLONG Now
    )
/*++

Routine Description:

    Whether an entry has outlived the TTL.

    The TTL is not a detail: without it a long-lived process that once
    opened a sensitive document would be barred from writing to removable
    media for the rest of its life, which for explorer.exe means until the
    machine reboots.

--*/
{
    return (BOOLEAN) ((Now - Entry->TaintedAt) > SAFEUPLOAD_TAINT_TTL_INTERVALS);
}


VOID
SafeUploadInitializeTaint (
    VOID
    )
/*++

Routine Description:

    Prepares the table and registers for process exit notifications.

    IRQL: PASSIVE_LEVEL. Called from DriverEntry.

    PsSetCreateProcessNotifyRoutine is used rather than its Ex variant on
    purpose: the Ex version requires the driver image to be linked with
    /INTEGRITYCHECK and signed accordingly, and this driver needs nothing
    the Ex version offers - only the fact that a process has gone.

--*/
{
    ULONG index;
    NTSTATUS status;

    PAGED_CODE();

    FltInitializePushLock( &SafeUploadTaintLock );

    for (index = 0; index < SAFEUPLOAD_TAINT_BUCKETS; index += 1) {

        InitializeListHead( &SafeUploadTaintBuckets[index] );
    }

    status = PsSetCreateProcessNotifyRoutine( SafeUploadProcessNotify, FALSE );

    if (NT_SUCCESS( status )) {

        SafeUploadTaintNotifyRegistered = TRUE;

    } else {

        //
        //  Not fatal. Without the notification, entries are released by the
        //  TTL alone and a recycled PID could briefly inherit a taint that
        //  is not its own - which is why the notification is wanted, and
        //  why its absence is worth tracing rather than ignoring.
        //

        SafeUploadTrace( "PsSetCreateProcessNotifyRoutine failed, status 0x%08X\n",
                         status );
    }
}


VOID
SafeUploadFreeTaint (
    VOID
    )
/*++

Routine Description:

    Unregisters the notification and empties the table.

    IRQL: PASSIVE_LEVEL. Called from the unload path.

    The notification has to go first and unconditionally: leaving a
    registered callback pointing into an image that is about to be unloaded
    is a bugcheck waiting for the next process to exit.

--*/
{
    PSAFEUPLOAD_TAINT_ENTRY entry;
    PLIST_ENTRY link;
    ULONG index;

    PAGED_CODE();

    if (SafeUploadTaintNotifyRegistered) {

        (VOID) PsSetCreateProcessNotifyRoutine( SafeUploadProcessNotify, TRUE );
        SafeUploadTaintNotifyRegistered = FALSE;
    }

    FltAcquirePushLockExclusive( &SafeUploadTaintLock );

    for (index = 0; index < SAFEUPLOAD_TAINT_BUCKETS; index += 1) {

        while (!IsListEmpty( &SafeUploadTaintBuckets[index] )) {

            link = RemoveHeadList( &SafeUploadTaintBuckets[index] );
            entry = CONTAINING_RECORD( link, SAFEUPLOAD_TAINT_ENTRY, Link );

            ExFreePoolWithTag( entry, SAFEUPLOAD_POOL_TAG );
        }
    }

    FltReleasePushLock( &SafeUploadTaintLock );

    FltDeletePushLock( &SafeUploadTaintLock );
}


static
VOID
SafeUploadProcessNotify (
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create
    )
/*++

Routine Description:

    Called by the system when a process is created or destroyed. Only the
    destruction matters here.

    Without this the table would grow for the life of the driver, and worse:
    Windows recycles process ids, so a new process could inherit the taint
    of a dead one. A false positive that appears minutes later, on an
    unrelated program, is close to undiagnosable.

    IRQL: PASSIVE_LEVEL.

--*/
{
    UNREFERENCED_PARAMETER( ParentId );

    PAGED_CODE();

    if (Create) {

        return;
    }

    SafeUploadClearProcessTaint( HandleToULong( ProcessId ) );
}


VOID
SafeUploadTaintProcess (
    _In_ ULONG ProcessId,
    _In_ UINT32 Categories
    )
/*++

Routine Description:

    Records that a process has obtained access to sensitive content.

    Re-tainting an already tainted process refreshes its timestamp rather
    than adding a second entry: the TTL should measure time since the last
    contact with sensitive content, not since the first.

    IRQL: <= APC_LEVEL.

Arguments:

    ProcessId - The process that opened the file.

    Categories - What was found, for reporting later.

--*/
{
    PSAFEUPLOAD_TAINT_ENTRY entry;
    PLIST_ENTRY link;
    ULONG bucket;
    ULONGLONG now;

    if (ProcessId == SAFEUPLOAD_IDLE_PROCESS_ID ||
        ProcessId == SAFEUPLOAD_SYSTEM_PROCESS_ID) {

        return;
    }

    bucket = SafeUploadTaintBucket( ProcessId );
    now = KeQueryInterruptTime();

    FltAcquirePushLockExclusive( &SafeUploadTaintLock );

    for (link = SafeUploadTaintBuckets[bucket].Flink;
         link != &SafeUploadTaintBuckets[bucket];
         link = link->Flink) {

        entry = CONTAINING_RECORD( link, SAFEUPLOAD_TAINT_ENTRY, Link );

        if (entry->ProcessId == ProcessId) {

            entry->TaintedAt = now;
            entry->Categories |= Categories;

            FltReleasePushLock( &SafeUploadTaintLock );
            return;
        }
    }

    //
    //  Allocated under the lock, which is acceptable because tainting is
    //  rare: it happens once per sensitive file a process opens, not once
    //  per operation.
    //

    entry = (PSAFEUPLOAD_TAINT_ENTRY) ExAllocatePool2( POOL_FLAG_NON_PAGED,
                                                       sizeof( SAFEUPLOAD_TAINT_ENTRY ),
                                                       SAFEUPLOAD_POOL_TAG );

    if (entry != NULL) {

        entry->ProcessId = ProcessId;
        entry->Categories = Categories;
        entry->TaintedAt = now;

        InsertHeadList( &SafeUploadTaintBuckets[bucket], &entry->Link );
    }

    FltReleasePushLock( &SafeUploadTaintLock );

    if (entry != NULL) {

        SafeUploadTrace( "processo %lu marcado\n", ProcessId );
    }
}


VOID
SafeUploadClearProcessTaint (
    _In_ ULONG ProcessId
    )
/*++

Routine Description:

    Removes any taint recorded for a process.

    IRQL: <= APC_LEVEL.

--*/
{
    PSAFEUPLOAD_TAINT_ENTRY entry;
    PSAFEUPLOAD_TAINT_ENTRY removed = NULL;
    PLIST_ENTRY link;
    ULONG bucket;

    bucket = SafeUploadTaintBucket( ProcessId );

    FltAcquirePushLockExclusive( &SafeUploadTaintLock );

    for (link = SafeUploadTaintBuckets[bucket].Flink;
         link != &SafeUploadTaintBuckets[bucket];
         link = link->Flink) {

        entry = CONTAINING_RECORD( link, SAFEUPLOAD_TAINT_ENTRY, Link );

        if (entry->ProcessId == ProcessId) {

            RemoveEntryList( &entry->Link );
            removed = entry;
            break;
        }
    }

    FltReleasePushLock( &SafeUploadTaintLock );

    if (removed != NULL) {

        ExFreePoolWithTag( removed, SAFEUPLOAD_POOL_TAG );
    }
}


BOOLEAN
SafeUploadIsProcessTainted (
    _In_ ULONG ProcessId
    )
/*++

Routine Description:

    Whether a process is currently carrying taint.

    This is the lookup that runs in pre-create, on the path where a write to
    a monitored destination is about to be refused. It has to be cheap, and
    it is: one hash, one short list walk, no allocation, no I/O.

    An expired entry is removed as it is found. Sweeping the whole table
    would be wasted work, and an entry nobody looks at costs nothing but the
    memory the process exit notification will reclaim anyway.

    IRQL: <= APC_LEVEL.

Arguments:

    ProcessId - The process attempting the write.

Return Value:

    TRUE when the process has touched sensitive content within the TTL.

--*/
{
    PSAFEUPLOAD_TAINT_ENTRY entry;
    PSAFEUPLOAD_TAINT_ENTRY expired = NULL;
    PLIST_ENTRY link;
    BOOLEAN tainted = FALSE;
    ULONG bucket;
    ULONGLONG now;

    bucket = SafeUploadTaintBucket( ProcessId );
    now = KeQueryInterruptTime();

    FltAcquirePushLockExclusive( &SafeUploadTaintLock );

    for (link = SafeUploadTaintBuckets[bucket].Flink;
         link != &SafeUploadTaintBuckets[bucket];
         link = link->Flink) {

        entry = CONTAINING_RECORD( link, SAFEUPLOAD_TAINT_ENTRY, Link );

        if (entry->ProcessId != ProcessId) {

            continue;
        }

        if (SafeUploadTaintExpired( entry, now )) {

            RemoveEntryList( &entry->Link );
            expired = entry;

        } else {

            tainted = TRUE;
        }

        break;
    }

    FltReleasePushLock( &SafeUploadTaintLock );

    if (expired != NULL) {

        ExFreePoolWithTag( expired, SAFEUPLOAD_POOL_TAG );
    }

    return tainted;
}
