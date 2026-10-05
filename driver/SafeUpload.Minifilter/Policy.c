/*++

Module Name:

    Policy.c

Abstract:

    The scope policy, as pushed down from user mode over the communication
    port.

    Two properties matter here, and they pull in opposite directions:

    - Reads are on the hot path. Every create that survives the cheap gates
      consults the policy, thousands of times a second.

    - Writes are rare. The policy changes when the agent loads it and when
      an operator edits it.

    So the policy is an immutable snapshot behind a push lock: readers take
    it shared and never allocate, and a write builds an entirely new
    snapshot before swapping it in. Nothing is ever modified in place, which
    is what makes a reader safe without copying anything.

    Path prefixes arrive already in NT form. Converting DOS paths to NT form
    is user mode's job, done once when the policy is loaded - doing it here
    would mean converting on every operation, which is precisely the cost
    this design exists to avoid.

Environment:

    Kernel mode

--*/

#include "Filter.h"

//
//  Guards SafeUploadPolicy. Shared for readers, exclusive for the swap.
//

static EX_PUSH_LOCK SafeUploadPolicyLock;

//
//  The current snapshot, or NULL when user mode has not pushed one yet.
//  NULL means nothing is in scope, which is the correct reading: without a
//  policy there is no monitored destination and no monitored extension.
//

static PSAFEUPLOAD_POLICY SafeUploadPolicy = NULL;

/* Fixed DriverEntry storage keeps an identified boot policy independent of
 * pool allocation. An authenticated service policy replaces this snapshot
 * and clears the boot-only union atomically. */
static SAFEUPLOAD_POLICY SafeUploadBootSnapshot;
static SAFEUPLOAD_POLICY_MESSAGE SafeUploadBootMessage;
static SAFEUPLOAD_BOOT_SCOPE_SET SafeUploadBootScopes;
static BOOLEAN SafeUploadBootScopesActive;

static volatile LONG SafeUploadPolicyGeneration = 0;

static BOOLEAN SafeUploadPolicySnapshotMatchesDestination(
    _In_opt_ const SAFEUPLOAD_POLICY *Policy,
    _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind,
    _In_opt_ PCUNICODE_STRING NormalizedPath,
    _In_ BOOLEAN IncludeAncestors);

#if SAFEUPLOAD_STAGING_PROTOTYPE

#define SAFEUPLOAD_POLICY_DRAIN_TIMEOUT_100NS (30LL * 10 * 1000 * 1000)

struct _SAFEUPLOAD_ADMISSION_EPOCH {
    LIST_ENTRY DrainLink;
    volatile LONG References;
    volatile LONG ActiveCallbacks;
    volatile LONG Accepting;
    UINT32 Generation;
    KEVENT Drained;
};

static KSPIN_LOCK SafeUploadEpochLock;
static KMUTEX SafeUploadPolicyUpdateMutex;
#define SafeUploadPolicyUpdateLockAcquire() \
    ((VOID)KeWaitForSingleObject(&SafeUploadPolicyUpdateMutex, Executive, KernelMode, FALSE, NULL))
#define SafeUploadPolicyUpdateLockRelease() \
    ((VOID)KeReleaseMutex(&SafeUploadPolicyUpdateMutex, FALSE))
static PSAFEUPLOAD_ADMISSION_EPOCH SafeUploadCurrentEpoch;
static LIST_ENTRY SafeUploadDrainingEpochs;
static volatile LONG SafeUploadEpochGeneration;
static volatile LONG SafeUploadPolicyFailedClosed;
static volatile LONG SafeUploadPolicyFinalizing;
static volatile LONG SafeUploadForceNextEpochTimeout;

/* A policy update pauses new per-file cutoffs and drains the active count before
 * changing epochs. The worker holds no policy/update lock across cache I/O. */
static KSPIN_LOCK SafeUploadActivationCutoffLock;
static KEVENT SafeUploadActivationCutoffsDrained;
static volatile LONG SafeUploadActivationCutoffsActive;
static volatile LONG SafeUploadActivationCutoffsPaused;
static NTSTATUS SafeUploadPolicyActivationCutoffsPause(VOID);
static VOID SafeUploadPolicyActivationCutoffsResume(VOID);

//
//  The candidate snapshot while a policy update is in transition (from before
//  the durable two-phase commit), guarded by SafeUploadPolicyLock. Admission
//  checks match the current/pending union while epoch tokens drain lower I/O.
//

static const SAFEUPLOAD_POLICY *SafeUploadPendingPolicy = NULL;

#endif

#if SAFEUPLOAD_STAGING_PROTOTYPE
static PSAFEUPLOAD_ADMISSION_EPOCH SafeUploadEpochAllocate(VOID)
{
    PSAFEUPLOAD_ADMISSION_EPOCH epoch = ExAllocatePool2(POOL_FLAG_NON_PAGED,
        sizeof(*epoch), SAFEUPLOAD_POOL_TAG);
    if (epoch == NULL) return NULL;
    RtlZeroMemory(epoch, sizeof(*epoch));
    epoch->References = 1; /* Current-epoch or drain-list ownership. */
    epoch->Accepting = 1;
    epoch->Generation = (UINT32)InterlockedIncrement(&SafeUploadEpochGeneration);
    KeInitializeEvent(&epoch->Drained, NotificationEvent, FALSE);
    InitializeListHead(&epoch->DrainLink);
    return epoch;
}

static VOID SafeUploadEpochReference(_In_ PSAFEUPLOAD_ADMISSION_EPOCH Epoch)
{
    InterlockedIncrement(&Epoch->References);
}

static VOID SafeUploadEpochDereference(_In_opt_ PSAFEUPLOAD_ADMISSION_EPOCH Epoch)
{
    if (Epoch != NULL && InterlockedDecrement(&Epoch->References) == 0)
        ExFreePoolWithTag(Epoch, SAFEUPLOAD_POOL_TAG);
}

/* Pageable policy-update routines call these resident lock boundaries. */
__declspec(noinline) static VOID SafeUploadEpochReplaceCurrent(_In_ PSAFEUPLOAD_ADMISSION_EPOCH Fresh)
{
    PSAFEUPLOAD_ADMISSION_EPOCH old;
    KIRQL irql;

    KeAcquireSpinLock(&SafeUploadEpochLock, &irql);
    old = SafeUploadCurrentEpoch;
    if (old != NULL) {
        InterlockedExchange(&old->Accepting, 0);
        if (InterlockedCompareExchange(&old->ActiveCallbacks, 0, 0) == 0)
            KeSetEvent(&old->Drained, IO_NO_INCREMENT, FALSE);
        InsertTailList(&SafeUploadDrainingEpochs, &old->DrainLink);
    }
    SafeUploadCurrentEpoch = Fresh;
    KeReleaseSpinLock(&SafeUploadEpochLock, irql);
}

__declspec(noinline) static PSAFEUPLOAD_ADMISSION_EPOCH SafeUploadEpochReferenceDrainHead(VOID)
{
    PSAFEUPLOAD_ADMISSION_EPOCH epoch = NULL;
    KIRQL irql;

    KeAcquireSpinLock(&SafeUploadEpochLock, &irql);
    if (!IsListEmpty(&SafeUploadDrainingEpochs)) {
        epoch = CONTAINING_RECORD(SafeUploadDrainingEpochs.Flink,
            SAFEUPLOAD_ADMISSION_EPOCH, DrainLink);
        SafeUploadEpochReference(epoch);
    }
    KeReleaseSpinLock(&SafeUploadEpochLock, irql);
    return epoch;
}

__declspec(noinline) static BOOLEAN SafeUploadEpochRemoveDrained(_In_ PSAFEUPLOAD_ADMISSION_EPOCH Epoch)
{
    KIRQL irql;
    BOOLEAN removed = FALSE;

    KeAcquireSpinLock(&SafeUploadEpochLock, &irql);
    if (!IsListEmpty(&Epoch->DrainLink) && Epoch->DrainLink.Flink != &Epoch->DrainLink) {
        RemoveEntryList(&Epoch->DrainLink);
        InitializeListHead(&Epoch->DrainLink);
        removed = TRUE;
    }
    KeReleaseSpinLock(&SafeUploadEpochLock, irql);
    return removed;
}

/* Replace the accepting epoch atomically with respect to admission tokens.
 * The old current-epoch reference transfers to SafeUploadDrainingEpochs. */
static NTSTATUS SafeUploadEpochCloseAndReplace(VOID)
{
    PSAFEUPLOAD_ADMISSION_EPOCH fresh;
    fresh = SafeUploadEpochAllocate();
    if (fresh == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    SafeUploadEpochReplaceCurrent(fresh);
    return STATUS_SUCCESS;
}

static NTSTATUS SafeUploadEpochDrainAll(VOID)
{
    LARGE_INTEGER timeout;
    ULONGLONG start = KeQueryInterruptTime();
    BOOLEAN forceTimeout = InterlockedExchange(&SafeUploadForceNextEpochTimeout, 0) != 0;
    if (forceTimeout) return STATUS_IO_TIMEOUT;
    for (;;) {
        PSAFEUPLOAD_ADMISSION_EPOCH epoch;
        ULONGLONG elapsed, remaining;
        epoch = SafeUploadEpochReferenceDrainHead();
        if (epoch == NULL) return STATUS_SUCCESS;
        elapsed = KeQueryInterruptTime() - start;
        if (elapsed >= (ULONGLONG)SAFEUPLOAD_POLICY_DRAIN_TIMEOUT_100NS) {
            SafeUploadEpochDereference(epoch);
            return STATUS_IO_TIMEOUT;
        }
        remaining = (ULONGLONG)SAFEUPLOAD_POLICY_DRAIN_TIMEOUT_100NS - elapsed;
        timeout.QuadPart = -(LONGLONG)remaining;
        if (KeWaitForSingleObject(&epoch->Drained, Executive, KernelMode, FALSE, &timeout) != STATUS_SUCCESS) {
            SafeUploadEpochDereference(epoch);
            return STATUS_IO_TIMEOUT;
        }
        if (SafeUploadEpochRemoveDrained(epoch)) {
            SafeUploadEpochDereference(epoch); /* drain-list ownership */
        }
        SafeUploadEpochDereference(epoch); /* wait reference */
    }
}

__declspec(noinline) static NTSTATUS SafeUploadEpochAcquireCurrent(
    _Inout_ PSAFEUPLOAD_ADMISSION_EPOCH_TOKEN Token)
{
    PSAFEUPLOAD_ADMISSION_EPOCH epoch;
    KIRQL irql;

    KeAcquireSpinLock(&SafeUploadEpochLock, &irql);
    epoch = SafeUploadCurrentEpoch;
    if (epoch == NULL || InterlockedCompareExchange(&epoch->Accepting, 0, 0) == 0) {
        KeReleaseSpinLock(&SafeUploadEpochLock, irql);
        return STATUS_RETRY;
    }
    SafeUploadEpochReference(epoch);
    InterlockedIncrement(&epoch->ActiveCallbacks);
    Token->Signature = SAFEUPLOAD_ADMISSION_EPOCH_TOKEN_SIGNATURE;
    Token->Epoch = epoch;
    Token->OperationKind = 1;
    KeReleaseSpinLock(&SafeUploadEpochLock, irql);
    return STATUS_SUCCESS;
}

NTSTATUS SafeUploadPolicyAdmissionAcquire(_Outptr_ PSAFEUPLOAD_ADMISSION_EPOCH_TOKEN *Token)
{
    PSAFEUPLOAD_ADMISSION_EPOCH_TOKEN token;
    NTSTATUS status;
    *Token = NULL;
    token = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*token), SAFEUPLOAD_POOL_TAG);
    if (token == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(token, sizeof(*token));
    status = SafeUploadEpochAcquireCurrent(token);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(token, SAFEUPLOAD_POOL_TAG);
        return status;
    }
    *Token = token;
    return STATUS_SUCCESS;
}

VOID SafeUploadPolicyAdmissionRelease(_In_opt_ PSAFEUPLOAD_ADMISSION_EPOCH_TOKEN Token)
{
    PSAFEUPLOAD_ADMISSION_EPOCH epoch;
    if (Token == NULL || Token->Signature != SAFEUPLOAD_ADMISSION_EPOCH_TOKEN_SIGNATURE) return;
    epoch = Token->Epoch;
    Token->Signature = 0;
    if (Token->PagingWriteContext != NULL) {
        PVOID pagingContext = Token->PagingWriteContext;
        Token->PagingWriteContext = NULL;
        SafeUploadStageWritersPagingWriteEnd(pagingContext);
    }
    if (epoch != NULL && InterlockedDecrement(&epoch->ActiveCallbacks) == 0 &&
        InterlockedCompareExchange(&epoch->Accepting, 0, 0) == 0)
        KeSetEvent(&epoch->Drained, IO_NO_INCREMENT, FALSE);
    SafeUploadEpochDereference(epoch);
    ExFreePoolWithTag(Token, SAFEUPLOAD_POOL_TAG);
}

BOOLEAN SafeUploadPolicyAdmissionMustRetry(VOID)
{
    return InterlockedCompareExchange(&SafeUploadPolicyFailedClosed, 0, 0) != 0 ||
        InterlockedCompareExchange(&SafeUploadPolicyFinalizing, 0, 0) != 0;
}

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SafeUploadPolicyActivationCutoffBegin)
#pragma alloc_text(PAGE, SafeUploadPolicyActivationCutoffEnd)
#pragma alloc_text(PAGE, SafeUploadPolicyActivationCutoffsPause)
#pragma alloc_text(PAGE, SafeUploadPolicyActivationCutoffsResume)
#endif

/* These lock boundaries stay in nonpaged code. Their pageable callers only
 * prepare/consume state at PASSIVE_LEVEL; no caller raises IRQL in PAGE code. */
__declspec(noinline) static VOID SafeUploadPolicySetActivationCutoffsPaused(_In_ BOOLEAN Paused)
{
    KIRQL irql;

    KeAcquireSpinLock(&SafeUploadActivationCutoffLock, &irql);
    InterlockedExchange(&SafeUploadActivationCutoffsPaused, Paused ? 1 : 0);
    if (Paused && InterlockedCompareExchange(&SafeUploadActivationCutoffsActive, 0, 0) == 0)
        KeSetEvent(&SafeUploadActivationCutoffsDrained, IO_NO_INCREMENT, FALSE);
    KeReleaseSpinLock(&SafeUploadActivationCutoffLock, irql);
}

__declspec(noinline) static NTSTATUS SafeUploadPolicyTryBeginActivationCutoff(VOID)
{
    KIRQL irql;
    NTSTATUS status = STATUS_SUCCESS;

    KeAcquireSpinLock(&SafeUploadActivationCutoffLock, &irql);
    if (InterlockedCompareExchange(&SafeUploadActivationCutoffsPaused, 0, 0) != 0 ||
        InterlockedCompareExchange(&SafeUploadPolicyFailedClosed, 0, 0) != 0 ||
        InterlockedCompareExchange(&SafeUploadPolicyFinalizing, 0, 0) != 0) {
        status = STATUS_RETRY;
    } else if (InterlockedIncrement(&SafeUploadActivationCutoffsActive) == 1) {
        KeClearEvent(&SafeUploadActivationCutoffsDrained);
    }
    KeReleaseSpinLock(&SafeUploadActivationCutoffLock, irql);
    return status;
}

__declspec(noinline) static VOID SafeUploadPolicyEndActivationCutoff(VOID)
{
    KIRQL irql;
    LONG remaining;

    KeAcquireSpinLock(&SafeUploadActivationCutoffLock, &irql);
    remaining = InterlockedDecrement(&SafeUploadActivationCutoffsActive);
    if (remaining <= 0) {
        if (remaining < 0) InterlockedExchange(&SafeUploadActivationCutoffsActive, 0);
        KeSetEvent(&SafeUploadActivationCutoffsDrained, IO_NO_INCREMENT, FALSE);
    }
    KeReleaseSpinLock(&SafeUploadActivationCutoffLock, irql);
}

__declspec(noinline) static PSAFEUPLOAD_ADMISSION_EPOCH SafeUploadPolicyDetachCurrentEpoch(VOID)
{
    PSAFEUPLOAD_ADMISSION_EPOCH epoch;
    KIRQL irql;

    KeAcquireSpinLock(&SafeUploadEpochLock, &irql);
    epoch = SafeUploadCurrentEpoch;
    SafeUploadCurrentEpoch = NULL;
    if (epoch != NULL) {
        InterlockedExchange(&epoch->Accepting, 0);
        if (InterlockedCompareExchange(&epoch->ActiveCallbacks, 0, 0) == 0)
            KeSetEvent(&epoch->Drained, IO_NO_INCREMENT, FALSE);
    }
    KeReleaseSpinLock(&SafeUploadEpochLock, irql);
    return epoch;
}

static NTSTATUS SafeUploadPolicyActivationCutoffsPause(VOID)
{
    LARGE_INTEGER timeout;
    NTSTATUS status;

    PAGED_CODE();
    SafeUploadPolicySetActivationCutoffsPaused(TRUE);

    timeout.QuadPart = -SAFEUPLOAD_POLICY_DRAIN_TIMEOUT_100NS;
    status = KeWaitForSingleObject(&SafeUploadActivationCutoffsDrained,
        Executive, KernelMode, FALSE, &timeout);
    return status == STATUS_SUCCESS ? STATUS_SUCCESS : STATUS_IO_TIMEOUT;
}

static VOID SafeUploadPolicyActivationCutoffsResume(VOID)
{
    PAGED_CODE();
    SafeUploadPolicySetActivationCutoffsPaused(FALSE);
    SafeUploadStageWritersQueueRecheck();
}

NTSTATUS SafeUploadPolicyActivationCutoffBegin(VOID)
{
    PAGED_CODE();
    return SafeUploadPolicyTryBeginActivationCutoff();
}

VOID SafeUploadPolicyActivationCutoffEnd(VOID)
{
    PAGED_CODE();
    SafeUploadPolicyEndActivationCutoff();
}

VOID SafeUploadPolicyAdmissionForceNextTimeout(VOID)
{
    InterlockedExchange(&SafeUploadForceNextEpochTimeout, 1);
}

__declspec(noinline) static VOID SafeUploadPolicyFillEpochStatus(_In_ BOOLEAN Pending,
    _Out_ PSAFEUPLOAD_ADMISSION_EPOCH_STATUS Status)
{
    PSAFEUPLOAD_ADMISSION_EPOCH epoch;
    KIRQL irql;
    RtlZeroMemory(Status, sizeof(*Status));
    Status->StructSize = sizeof(*Status);
    KeAcquireSpinLock(&SafeUploadEpochLock, &irql);
    epoch = SafeUploadCurrentEpoch;
    if (epoch != NULL) {
        Status->EpochGeneration = epoch->Generation;
        Status->ActiveCallbacks = (UINT32)max(0,
            InterlockedCompareExchange(&epoch->ActiveCallbacks, 0, 0));
    }
    Status->PolicyGeneration = (UINT32)InterlockedCompareExchange(&SafeUploadPolicyGeneration, 0, 0);
    if (Pending) Status->Flags |= SAFEUPLOAD_ADMISSION_EPOCH_FLAG_PENDING;
    if (InterlockedCompareExchange(&SafeUploadPolicyFailedClosed, 0, 0) != 0)
        Status->Flags |= SAFEUPLOAD_ADMISSION_EPOCH_FLAG_FAILED_CLOSED;
    if (InterlockedCompareExchange(&SafeUploadPolicyFinalizing, 0, 0) != 0)
        Status->Flags |= SAFEUPLOAD_ADMISSION_EPOCH_FLAG_FINALIZING;
    Status->ChangeSequence = (UINT64)(UINT32)InterlockedCompareExchange(&SafeUploadEpochGeneration, 0, 0);
    KeReleaseSpinLock(&SafeUploadEpochLock, irql);
}

NTSTATUS SafeUploadPolicyAdmissionEpochStatus(_Out_ PSAFEUPLOAD_ADMISSION_EPOCH_STATUS Status)
{
    SAFEUPLOAD_ADMISSION_EPOCH_STATUS snapshot;
    BOOLEAN pending;
    FltAcquirePushLockShared(&SafeUploadPolicyLock);
    pending = SafeUploadPendingPolicy != NULL;
    FltReleasePushLock(&SafeUploadPolicyLock);
    SafeUploadPolicyFillEpochStatus(pending, &snapshot);
    RtlCopyMemory(Status, &snapshot, sizeof(snapshot));
    return STATUS_SUCCESS;
}

BOOLEAN SafeUploadPolicyEntryIsNewlyScoped(_In_ SAFEUPLOAD_VOLUME_KIND VolumeKind,
    _In_ PCUNICODE_STRING NormalizedPath)
{
    BOOLEAN current, unionMatch;
    FltAcquirePushLockShared(&SafeUploadPolicyLock);
    current = SafeUploadPolicySnapshotMatchesDestination(SafeUploadPolicy, VolumeKind,
        NormalizedPath, FALSE);
    unionMatch = current || SafeUploadPolicySnapshotMatchesDestination(
        SafeUploadPendingPolicy, VolumeKind, NormalizedPath, FALSE);
    FltReleasePushLock(&SafeUploadPolicyLock);
    return unionMatch && !current;
}

BOOLEAN SafeUploadPolicyEntryIsCurrentlyScoped(_In_ SAFEUPLOAD_VOLUME_KIND VolumeKind,
    _In_ PCUNICODE_STRING NormalizedPath)
{
    BOOLEAN current;
    FltAcquirePushLockShared(&SafeUploadPolicyLock);
    current = SafeUploadPolicySnapshotMatchesDestination(SafeUploadPolicy, VolumeKind,
        NormalizedPath, FALSE);
    FltReleasePushLock(&SafeUploadPolicyLock);
    return current;
}
#endif

static
BOOLEAN
SafeUploadPathUnderPrefix (
    _In_ PCUNICODE_STRING Prefix,
    _In_ PCUNICODE_STRING Path
    )
{
    USHORT prefixChars;

    if (Prefix->Length == 0 ||
        !RtlPrefixUnicodeString( Prefix, Path, TRUE )) {
        return FALSE;
    }

    if (Path->Length == Prefix->Length) {
        return TRUE;
    }

    prefixChars = Prefix->Length / sizeof( WCHAR );
    return (BOOLEAN) (Prefix->Buffer[prefixChars - 1] == L'\\' ||
                      Path->Buffer[prefixChars] == L'\\');
}

/* Caller holds SafeUploadPolicyLock shared. Keep current, pending, and union
 * matching on one implementation so broad volume flags and prefix boundaries
 * cannot drift between policy snapshots. */
static BOOLEAN SafeUploadPolicySnapshotMatchesDestination(
    _In_opt_ const SAFEUPLOAD_POLICY *Policy,
    _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind,
    _In_opt_ PCUNICODE_STRING NormalizedPath,
    _In_ BOOLEAN IncludeAncestors)
{
    UINT32 index;
    if (Policy != NULL) {
        if ((VolumeKind == SafeUploadVolumeUnknown &&
             FlagOn(Policy->Flags, SAFEUPLOAD_POLICY_FLAG_REMOVABLE | SAFEUPLOAD_POLICY_FLAG_NETWORK)) ||
            (VolumeKind == SafeUploadVolumeRemovable &&
             FlagOn(Policy->Flags, SAFEUPLOAD_POLICY_FLAG_REMOVABLE)) ||
            (VolumeKind == SafeUploadVolumeNetwork &&
             FlagOn(Policy->Flags, SAFEUPLOAD_POLICY_FLAG_NETWORK))) return TRUE;

        if (NormalizedPath != NULL && NormalizedPath->Length != 0) {
            for (index = 0; index < Policy->PrefixCount; index += 1) {
                if (SafeUploadPathUnderPrefix(&Policy->Prefixes[index], NormalizedPath) ||
                    (IncludeAncestors && SafeUploadPathUnderPrefix(NormalizedPath, &Policy->Prefixes[index]))) {
                    return TRUE;
                }
            }
        }
    }

    if (SafeUploadBootScopesActive) {
        if (((VolumeKind == SafeUploadVolumeUnknown || VolumeKind == SafeUploadVolumeRemovable) &&
             FlagOn(SafeUploadBootScopes.Flags, SAFEUPLOAD_BOOT_POLICY_FLAG_REMOVABLE)) ||
            ((VolumeKind == SafeUploadVolumeUnknown || VolumeKind == SafeUploadVolumeNetwork) &&
             FlagOn(SafeUploadBootScopes.Flags, SAFEUPLOAD_BOOT_POLICY_FLAG_NETWORK))) return TRUE;
        if (NormalizedPath != NULL && NormalizedPath->Length != 0) {
            for (index = 0; index < SafeUploadBootScopes.PrefixCount; index += 1) {
                UNICODE_STRING prefix;
                prefix.Buffer = SafeUploadBootScopes.Prefixes[index];
                prefix.Length = (USHORT)(SafeUploadBootScopes.PrefixChars[index] * sizeof(WCHAR));
                prefix.MaximumLength = prefix.Length;
                if (SafeUploadPathUnderPrefix(&prefix, NormalizedPath) ||
                    (IncludeAncestors && SafeUploadPathUnderPrefix(NormalizedPath, &prefix))) return TRUE;
            }
        }
    }

    return FALSE;
}

static
VOID
SafeUploadBuildStringTable (
    _In_ PCWCH Storage,
    _In_ UINT32 EntryCount,
    _In_ UINT32 EntryChars,
    _Out_writes_(EntryCount) PUNICODE_STRING Table
    );

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(PAGE, SafeUploadInitializePolicy)
    #pragma alloc_text(PAGE, SafeUploadFreePolicy)
    #pragma alloc_text(PAGE, SafeUploadSetPolicy)
    #pragma alloc_text(PAGE, SafeUploadFinalizeBootPolicy)
    #pragma alloc_text(PAGE, SafeUploadBuildStringTable)
#if SAFEUPLOAD_STAGING_PROTOTYPE
    #pragma alloc_text(PAGE, SafeUploadPolicyCopyScope)
    #pragma alloc_text(PAGE, SafeUploadPolicySetPending)
#endif
    #pragma alloc_text(PAGE, SafeUploadPolicyMayMatchVolume)
#endif


VOID
SafeUploadInitializePolicy (
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    Prepares the policy lock. Called from DriverEntry before the port
    exists, because the first thing a client does is push a policy.

    IRQL: PASSIVE_LEVEL.

--*/
{
    NTSTATUS status;
    UINT32 bootPolicyState = SAFEUPLOAD_BOOT_POLICY_STATE_UNREADABLE;

    PAGED_CODE();

    FltInitializePushLock( &SafeUploadPolicyLock );
#if SAFEUPLOAD_STAGING_PROTOTYPE
    KeInitializeMutex(&SafeUploadPolicyUpdateMutex, 0);
    KeInitializeSpinLock(&SafeUploadEpochLock);
    KeInitializeSpinLock(&SafeUploadActivationCutoffLock);
    KeInitializeEvent(&SafeUploadActivationCutoffsDrained, NotificationEvent, TRUE);
    InitializeListHead(&SafeUploadDrainingEpochs);
    SafeUploadEpochGeneration = 0;
    SafeUploadPolicyFailedClosed = 0;
    SafeUploadPolicyFinalizing = 0;
    SafeUploadForceNextEpochTimeout = 0;
    SafeUploadActivationCutoffsActive = 0;
    SafeUploadActivationCutoffsPaused = 0;
    SafeUploadCurrentEpoch = SafeUploadEpochAllocate();
#endif
    SafeUploadPolicy = NULL;
    SafeUploadPolicyGeneration = 0;
    SafeUploadBootScopesActive = FALSE;
    SafeUploadData.AuthenticatedClient = 0;
    SafeUploadData.BootPolicyState = bootPolicyState;
    RtlZeroMemory(&SafeUploadBootSnapshot, sizeof(SafeUploadBootSnapshot));
    RtlZeroMemory(&SafeUploadBootMessage, sizeof(SafeUploadBootMessage));
    RtlZeroMemory(&SafeUploadBootScopes, sizeof(SafeUploadBootScopes));

    SafeUploadData.BootStartMode = TRUE;
    status = SafeUploadReadBootPolicy(RegistryPath, &SafeUploadBootMessage,
        &SafeUploadBootScopes, &bootPolicyState, &SafeUploadData.BootStartMode);
    SafeUploadData.BootPolicyState = bootPolicyState;
    if (!NT_SUCCESS(status)) {
        /* The bounded reader classifies a missing key, ACL rejection, and
         * unreadable registry path separately. Keep that reported state; the
         * zeroed scope set means no destination could be identified. */
        SafeUploadTrace("boot policy read failed 0x%08X; state=%u; identified-prefixes=%u flags=0x%X\n",
            status, SafeUploadData.BootPolicyState, SafeUploadBootScopes.PrefixCount,
            SafeUploadBootScopes.Flags);
        return;
    }

    SafeUploadBootScopesActive = SafeUploadBootScopes.PrefixCount != 0 ||
        SafeUploadBootScopes.Flags != 0 || SafeUploadBootScopes.Overflow;
    if (SafeUploadBootScopesActive) {
        RtlCopyMemory(&SafeUploadBootSnapshot.Data, &SafeUploadBootMessage,
            sizeof(SAFEUPLOAD_POLICY_MESSAGE));
        SafeUploadBootSnapshot.ExtensionCount = 0;
        SafeUploadBootSnapshot.PrefixCount = SafeUploadBootMessage.PrefixCount;
        SafeUploadBootSnapshot.SourcePrefixCount = 0;
        SafeUploadBootSnapshot.ImageCount = 0;
        SafeUploadBootSnapshot.Flags = SafeUploadBootMessage.Flags;
        SafeUploadBootSnapshot.VerdictTimeoutIntervals =
            -((LONGLONG)SAFEUPLOAD_VERDICT_TIMEOUT_MS * 10 * 1000);
        SafeUploadBuildStringTable(&SafeUploadBootSnapshot.Data.Prefixes[0][0],
            SafeUploadBootSnapshot.PrefixCount, SAFEUPLOAD_MAX_PREFIX_CHARS,
            SafeUploadBootSnapshot.Prefixes);
        SafeUploadPolicy = &SafeUploadBootSnapshot;
    }
}


VOID
SafeUploadFreePolicy (
    VOID
    )
/*++

Routine Description:

    Releases the current snapshot and the lock. Called from the unload path,
    after the channel has been drained, so no reader can be in flight.

    IRQL: PASSIVE_LEVEL.

--*/
{
    PSAFEUPLOAD_POLICY previous;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    const SAFEUPLOAD_POLICY *pending;
    PSAFEUPLOAD_ADMISSION_EPOCH epoch;
    PLIST_ENTRY link;
#endif

    PAGED_CODE();

    FltAcquirePushLockExclusive( &SafeUploadPolicyLock );

    previous = SafeUploadPolicy;
    SafeUploadPolicy = NULL;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    pending = SafeUploadPendingPolicy;
    SafeUploadPendingPolicy = NULL;
#endif

    FltReleasePushLock( &SafeUploadPolicyLock );

#if SAFEUPLOAD_STAGING_PROTOTYPE
    epoch = SafeUploadPolicyDetachCurrentEpoch();
    if (epoch != NULL) {
        NT_ASSERT(InterlockedCompareExchange(&epoch->ActiveCallbacks, 0, 0) == 0);
        SafeUploadEpochDereference(epoch);
    }
    while (!IsListEmpty(&SafeUploadDrainingEpochs)) {
        link = RemoveHeadList(&SafeUploadDrainingEpochs);
        epoch = CONTAINING_RECORD(link, SAFEUPLOAD_ADMISSION_EPOCH, DrainLink);
        NT_ASSERT(InterlockedCompareExchange(&epoch->ActiveCallbacks, 0, 0) == 0);
        SafeUploadEpochDereference(epoch);
    }
    if (pending != NULL && pending != previous && pending != &SafeUploadBootSnapshot)
        ExFreePoolWithTag((PVOID)pending, SAFEUPLOAD_POOL_TAG);
#endif

    if (previous != NULL && previous != &SafeUploadBootSnapshot) {

        ExFreePoolWithTag( previous, SAFEUPLOAD_POOL_TAG );
    }

    RtlZeroMemory(&SafeUploadBootScopes, sizeof(SafeUploadBootScopes));
    SafeUploadBootScopesActive = FALSE;

    FltDeletePushLock( &SafeUploadPolicyLock );
}

BOOLEAN SafeUploadIsAuthenticatedClient(VOID)
{
    return SafeUploadData.ClientPort != NULL &&
        InterlockedCompareExchange(&SafeUploadData.AuthenticatedClient, 0, 0) != 0;
}


static
VOID
SafeUploadBuildStringTable (
    _In_ PCWCH Storage,
    _In_ UINT32 EntryCount,
    _In_ UINT32 EntryChars,
    _Out_writes_(EntryCount) PUNICODE_STRING Table
    )
/*++

Routine Description:

    Points a table of UNICODE_STRINGs at the fixed-width character storage
    that came down in the message, measuring each entry once.

    Measuring here rather than at match time is the whole point: a prefix
    can be 260 characters, and running wcslen over it on every create would
    put a string walk in the hot path for nothing.

    IRQL: PASSIVE_LEVEL.

Arguments:

    Storage - Start of the fixed-width array in the snapshot.

    EntryCount - How many entries are populated.

    EntryChars - Width of each entry, in WCHARs, terminator included.

    Table - Receives one UNICODE_STRING per entry.

--*/
{
    UINT32 index;
    UINT32 length;
    PCWCH entry;

    PAGED_CODE();

    for (index = 0; index < EntryCount; index += 1) {

        entry = Storage + ((SIZE_T) index * EntryChars);

        //
        //  Bounded by the entry width, never by a terminator alone: the
        //  message came from user mode and an unterminated entry must not
        //  walk off the end.
        //

        for (length = 0; length < EntryChars; length += 1) {

            if (entry[length] == L'\0') {

                break;
            }
        }

        Table[index].Buffer = (PWCH) entry;
        Table[index].Length = (USHORT) (length * sizeof( WCHAR ));
        Table[index].MaximumLength = Table[index].Length;
    }
}


NTSTATUS
SafeUploadSetPolicy (
    _In_ CONST SAFEUPLOAD_POLICY_MESSAGE *Message
    )
{
    PSAFEUPLOAD_POLICY snapshot;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    BOOLEAN alreadyPending = FALSE;
    NTSTATUS status;
#else
    PSAFEUPLOAD_POLICY previous;   /* only the normal build swaps the snapshot in place */
#endif

    PAGED_CODE();
    if (Message == NULL || Message->ExtensionCount > SAFEUPLOAD_MAX_EXTENSIONS ||
        Message->PrefixCount > SAFEUPLOAD_MAX_PREFIXES ||
        Message->SourcePrefixCount > SAFEUPLOAD_MAX_SOURCE_PREFIXES ||
        Message->ImageCount > SAFEUPLOAD_MAX_IMAGES) return STATUS_INVALID_PARAMETER;

    snapshot = (PSAFEUPLOAD_POLICY)ExAllocatePool2(POOL_FLAG_NON_PAGED,
        sizeof(SAFEUPLOAD_POLICY), SAFEUPLOAD_POOL_TAG);
    if (snapshot == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(&snapshot->Data, Message, sizeof(SAFEUPLOAD_POLICY_MESSAGE));
    snapshot->ExtensionCount = Message->ExtensionCount;
    snapshot->PrefixCount = Message->PrefixCount;
    snapshot->SourcePrefixCount = Message->SourcePrefixCount;
    snapshot->ImageCount = Message->ImageCount;
    snapshot->Flags = Message->Flags;
    {
        UINT32 timeoutMs = Message->VerdictTimeoutMs;
        if (timeoutMs == 0) timeoutMs = (UINT32)SAFEUPLOAD_VERDICT_TIMEOUT_MS;
        else if (timeoutMs < SAFEUPLOAD_VERDICT_TIMEOUT_MIN_MS) timeoutMs = SAFEUPLOAD_VERDICT_TIMEOUT_MIN_MS;
        else if (timeoutMs > SAFEUPLOAD_VERDICT_TIMEOUT_MAX_MS) timeoutMs = SAFEUPLOAD_VERDICT_TIMEOUT_MAX_MS;
        snapshot->VerdictTimeoutIntervals = -((LONGLONG)timeoutMs * 10 * 1000);
    }
    SafeUploadBuildStringTable(&snapshot->Data.Extensions[0][0], snapshot->ExtensionCount,
        SAFEUPLOAD_MAX_EXTENSION_CHARS, snapshot->Extensions);
    SafeUploadBuildStringTable(&snapshot->Data.Prefixes[0][0], snapshot->PrefixCount,
        SAFEUPLOAD_MAX_PREFIX_CHARS, snapshot->Prefixes);
    SafeUploadBuildStringTable(&snapshot->Data.SourcePrefixes[0][0], snapshot->SourcePrefixCount,
        SAFEUPLOAD_MAX_PREFIX_CHARS, snapshot->SourcePrefixes);
    SafeUploadBuildStringTable(&snapshot->Data.Images[0][0], snapshot->ImageCount,
        SAFEUPLOAD_MAX_IMAGE_CHARS, snapshot->Images);

#if SAFEUPLOAD_STAGING_PROTOTYPE
    SafeUploadPolicyUpdateLockAcquire();

    /* Let any already-running file cutoff finish while its paging writes can
     * still use the accepting epoch. No policy lock is held while we wait. */
    status = SafeUploadPolicyActivationCutoffsPause();
    if (!NT_SUCCESS(status)) {
        if (InterlockedCompareExchange(&SafeUploadPolicyFailedClosed, 0, 0) == 0)
            SafeUploadPolicyActivationCutoffsResume();
        SafeUploadPolicyUpdateLockRelease();
        ExFreePoolWithTag(snapshot, SAFEUPLOAD_POOL_TAG);
        return STATUS_IO_TIMEOUT;
    }

    FltAcquirePushLockExclusive(&SafeUploadPolicyLock);
    if (SafeUploadPendingPolicy != NULL) {
        if (!RtlEqualMemory(&SafeUploadPendingPolicy->Data, Message, sizeof(*Message))) {
            FltReleasePushLock(&SafeUploadPolicyLock);
            if (InterlockedCompareExchange(&SafeUploadPolicyFailedClosed, 0, 0) == 0)
                SafeUploadPolicyActivationCutoffsResume();
            SafeUploadPolicyUpdateLockRelease();
            ExFreePoolWithTag(snapshot, SAFEUPLOAD_POOL_TAG);
            return STATUS_DEVICE_BUSY;
        }
        alreadyPending = TRUE;
        ExFreePoolWithTag(snapshot, SAFEUPLOAD_POOL_TAG);
        snapshot = (PSAFEUPLOAD_POLICY)SafeUploadPendingPolicy;
    } else {
        SafeUploadPendingPolicy = snapshot;
    }
    InterlockedExchange(&SafeUploadPolicyFinalizing, 1);
    status = SafeUploadEpochCloseAndReplace();
    if (!NT_SUCCESS(status) && !alreadyPending) SafeUploadPendingPolicy = NULL;
    FltReleasePushLock(&SafeUploadPolicyLock);
    if (!NT_SUCCESS(status)) {
        InterlockedExchange(&SafeUploadPolicyFinalizing, 0);
        if (InterlockedCompareExchange(&SafeUploadPolicyFailedClosed, 0, 0) == 0)
            SafeUploadPolicyActivationCutoffsResume();
        SafeUploadPolicyUpdateLockRelease();
        if (!alreadyPending) ExFreePoolWithTag(snapshot, SAFEUPLOAD_POOL_TAG);
        return status;
    }
    status = SafeUploadEpochDrainAll();
    if (!NT_SUCCESS(status)) {
        InterlockedExchange(&SafeUploadPolicyFailedClosed, 1);
        InterlockedExchange(&SafeUploadPolicyFinalizing, 0);
        SafeUploadPolicyUpdateLockRelease();
        return STATUS_IO_TIMEOUT;
    }
    InterlockedExchange(&SafeUploadPolicyFailedClosed, 0);
    status = SafeUploadStageWritersApplyPendingScope();
    if (!NT_SUCCESS(status)) {
        InterlockedExchange(&SafeUploadPolicyFailedClosed, 1);
        InterlockedExchange(&SafeUploadPolicyFinalizing, 0);
        SafeUploadPolicyUpdateLockRelease();
        return status;
    }
    {
        ULONG prefixCount = snapshot->PrefixCount;
        ULONG policyFlags = snapshot->Flags;
        LONG epochGeneration = SafeUploadEpochGeneration;
        LONG policyGeneration = SafeUploadPolicyGeneration;
        InterlockedExchange(&SafeUploadPolicyFinalizing, 0);
        SafeUploadPolicyActivationCutoffsResume();
        SafeUploadPolicyUpdateLockRelease();
        SafeUploadTrace("policy candidate pending; epoch=%ld generation=%ld prefixes=%u flags=0x%X\n",
            epochGeneration, policyGeneration, prefixCount, policyFlags);
    }
    return STATUS_SUCCESS;
#else
    FltAcquirePushLockExclusive(&SafeUploadPolicyLock);
    previous = SafeUploadPolicy;
    SafeUploadPolicy = snapshot;
    (VOID)InterlockedIncrement(&SafeUploadPolicyGeneration);
    FltReleasePushLock(&SafeUploadPolicyLock);
    if (previous != NULL && previous != &SafeUploadBootSnapshot)
        ExFreePoolWithTag(previous, SAFEUPLOAD_POOL_TAG);
    SafeUploadTrace("policy set: %u extensoes, %u prefixos, %u imagens, flags 0x%X\n",
        snapshot->ExtensionCount, snapshot->PrefixCount, snapshot->ImageCount, snapshot->Flags);
    return STATUS_SUCCESS;
#endif
}

NTSTATUS SafeUploadFinalizeBootPolicy(_In_ CONST SAFEUPLOAD_POLICY_MESSAGE *Message)
{
    NTSTATUS status = STATUS_SUCCESS;
    PAGED_CODE();
    if (!SafeUploadIsAuthenticatedClient()) return STATUS_ACCESS_DENIED;
    if (Message == NULL || Message->Control.Version != SAFEUPLOAD_PROTOCOL_VERSION ||
        Message->Control.StructSize != sizeof(*Message) || Message->Control.Command != SAFEUPLOAD_CONTROL_SET_POLICY ||
        Message->Control.Reserved != 0) return STATUS_INVALID_PARAMETER;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    SafeUploadPolicyUpdateLockAcquire();
    FltAcquirePushLockShared(&SafeUploadPolicyLock);
    if (SafeUploadPendingPolicy == NULL) {
        BOOLEAN alreadyCurrent = SafeUploadPolicy != NULL &&
            RtlEqualMemory(&SafeUploadPolicy->Data, Message, sizeof(*Message));
        FltReleasePushLock(&SafeUploadPolicyLock);
        SafeUploadPolicyUpdateLockRelease();
        return alreadyCurrent ? STATUS_SUCCESS : STATUS_REVISION_MISMATCH;
    }
    if (!RtlEqualMemory(&SafeUploadPendingPolicy->Data, Message, sizeof(*Message))) {
        FltReleasePushLock(&SafeUploadPolicyLock);
        SafeUploadPolicyUpdateLockRelease();
        return STATUS_REVISION_MISMATCH;
    }
    FltReleasePushLock(&SafeUploadPolicyLock);

    status = SafeUploadPolicyActivationCutoffsPause();
    if (!NT_SUCCESS(status)) {
        if (InterlockedCompareExchange(&SafeUploadPolicyFailedClosed, 0, 0) == 0)
            SafeUploadPolicyActivationCutoffsResume();
        SafeUploadPolicyUpdateLockRelease();
        return STATUS_IO_TIMEOUT;
    }

    InterlockedExchange(&SafeUploadPolicyFinalizing, 1);
    status = SafeUploadEpochCloseAndReplace();
    if (NT_SUCCESS(status)) status = SafeUploadEpochDrainAll();
    if (!NT_SUCCESS(status)) {
        InterlockedExchange(&SafeUploadPolicyFailedClosed, 1);
        InterlockedExchange(&SafeUploadPolicyFinalizing, 0);
        SafeUploadPolicyUpdateLockRelease();
        return status == STATUS_IO_TIMEOUT ? STATUS_IO_TIMEOUT : status;
    }

    FltAcquirePushLockExclusive(&SafeUploadPolicyLock);
    if (SafeUploadPendingPolicy == NULL ||
        !RtlEqualMemory(&SafeUploadPendingPolicy->Data, Message, sizeof(*Message))) {
        status = STATUS_REVISION_MISMATCH;
    } else {
        PSAFEUPLOAD_POLICY previous = SafeUploadPolicy;
        SafeUploadPolicy = (PSAFEUPLOAD_POLICY)SafeUploadPendingPolicy;
        SafeUploadPendingPolicy = NULL;
        RtlZeroMemory(&SafeUploadBootScopes, sizeof(SafeUploadBootScopes));
        SafeUploadBootScopesActive = FALSE;
        SafeUploadData.BootPolicyState = SAFEUPLOAD_BOOT_POLICY_STATE_VALID;
        (VOID)InterlockedIncrement(&SafeUploadPolicyGeneration);
        FltReleasePushLock(&SafeUploadPolicyLock);
        SafeUploadStageWritersReconcileCurrentScope();
        if (previous != NULL && previous != &SafeUploadBootSnapshot)
            ExFreePoolWithTag(previous, SAFEUPLOAD_POOL_TAG);
        InterlockedExchange(&SafeUploadPolicyFailedClosed, 0);
        InterlockedExchange(&SafeUploadPolicyFinalizing, 0);
        SafeUploadPolicyActivationCutoffsResume();
        SafeUploadPolicyUpdateLockRelease();
        return STATUS_SUCCESS;
    }
    FltReleasePushLock(&SafeUploadPolicyLock);
    InterlockedExchange(&SafeUploadPolicyFailedClosed, 1);
    InterlockedExchange(&SafeUploadPolicyFinalizing, 0);
    SafeUploadPolicyUpdateLockRelease();
    return status;
#else
    FltAcquirePushLockExclusive(&SafeUploadPolicyLock);
    if (SafeUploadPolicy == NULL || !RtlEqualMemory(&SafeUploadPolicy->Data, Message, sizeof(*Message))) {
        status = STATUS_REVISION_MISMATCH;
    } else {
        RtlZeroMemory(&SafeUploadBootScopes, sizeof(SafeUploadBootScopes));
        SafeUploadBootScopesActive = FALSE;
        SafeUploadData.BootPolicyState = SAFEUPLOAD_BOOT_POLICY_STATE_VALID;
    }
    FltReleasePushLock(&SafeUploadPolicyLock);
    return status;
#endif
}

LONG
SafeUploadCurrentPolicyGeneration (
    VOID
    )
{
    return InterlockedCompareExchange( &SafeUploadPolicyGeneration, 0, 0 );
}


BOOLEAN
SafeUploadPolicyClassifiesAllSources (
    VOID
    )
{
    BOOLEAN enabled = FALSE;

    FltAcquirePushLockShared( &SafeUploadPolicyLock );

    if (SafeUploadPolicy != NULL) {
        enabled = BooleanFlagOn( SafeUploadPolicy->Flags,
                                 SAFEUPLOAD_POLICY_FLAG_CLASSIFY_ALL_SOURCES );
    }

    FltReleasePushLock( &SafeUploadPolicyLock );

    return enabled;
}


BOOLEAN
SafeUploadPolicyAllowsOverride (
    VOID
    )
/*++

Routine Description:

    Whether the policy lets a user justify a refusal and proceed.

    Defaults to FALSE with no policy pushed, which is the safe direction: a
    driver that is loaded but not configured must not hand out exceptions.

    IRQL: <= APC_LEVEL, for the push lock.

--*/
{
    BOOLEAN allowed = FALSE;

    FltAcquirePushLockShared( &SafeUploadPolicyLock );

    if (SafeUploadPolicy != NULL) {

        allowed = BooleanFlagOn( SafeUploadPolicy->Flags,
                                 SAFEUPLOAD_POLICY_FLAG_ALLOW_OVERRIDE );
    }

    FltReleasePushLock( &SafeUploadPolicyLock );

    return allowed;
}


BOOLEAN
SafeUploadPolicyAuditOnly (
    VOID
    )
/*++

Routine Description:

    Whether the policy in force asks for audit only.

    Defaults to FALSE when no policy has been pushed: a driver that is
    loaded but not configured inspects nothing anyway, so the answer only
    matters once a policy exists.

    IRQL: <= APC_LEVEL, for the push lock.

--*/
{
    BOOLEAN auditOnly = FALSE;

    FltAcquirePushLockShared( &SafeUploadPolicyLock );

    if (SafeUploadPolicy != NULL) {

        auditOnly = BooleanFlagOn( SafeUploadPolicy->Flags,
                                   SAFEUPLOAD_POLICY_FLAG_AUDIT_ONLY );
    }

    FltReleasePushLock( &SafeUploadPolicyLock );

    return auditOnly;
}


LONGLONG
SafeUploadPolicyVerdictTimeout (
    VOID
    )
/*++

Routine Description:

    The verdict deadline currently in force, as the negative 100ns interval
    KeWaitForSingleObject wants.

    Falls back to the driver's default when no policy has been pushed yet.
    That case is real: the port can be connected and a request answered
    before SET_POLICY arrives.

    IRQL: <= APC_LEVEL, for the push lock.

Return Value:

    The interval to wait.

--*/
{
    LONGLONG intervals = -(SAFEUPLOAD_VERDICT_TIMEOUT_MS * 10 * 1000);

    FltAcquirePushLockShared( &SafeUploadPolicyLock );

    if (SafeUploadPolicy != NULL) {

        intervals = SafeUploadPolicy->VerdictTimeoutIntervals;
    }

    FltReleasePushLock( &SafeUploadPolicyLock );

    return intervals;
}


BOOLEAN
SafeUploadPolicyMatchesExtension (
    _In_ PCUNICODE_STRING FileName
    )
/*++

Routine Description:

    Whether the final component of a name carries a monitored extension.

    Reads the name the caller supplied rather than a resolved one: this runs
    before anything expensive, and its job is to reject, cheaply, the
    overwhelming majority of operations. An inconclusive answer errs towards
    letting the operation reach the slow path, which resolves the real name.

    IRQL: <= APC_LEVEL. Takes a push lock shared and allocates nothing.

Arguments:

    FileName - Name as supplied by the caller. May be empty.

Return Value:

    FALSE when the operation certainly falls outside the monitored
    extensions.

--*/
{
    UNICODE_STRING extension;
    BOOLEAN matched = FALSE;
    UINT32 index;
    USHORT charCount;
    USHORT dotIndex = 0;
    USHORT walk;

    if (FileName == NULL || FileName->Length == 0 || FileName->Buffer == NULL) {

        //
        //  Nothing to judge - an open by file ID, for instance. Let it
        //  reach the slow path.
        //

        return TRUE;
    }

    charCount = (USHORT) (FileName->Length / sizeof( WCHAR ));

    //
    //  Walk back to the last dot of the final component. A separator ends
    //  the search: a dot in a directory name is not an extension.
    //

    for (walk = charCount; walk > 0; walk -= 1) {

        WCHAR current = FileName->Buffer[walk - 1];

        if (current == L'\\' || current == L':') {

            break;
        }

        if (current == L'.') {

            dotIndex = walk - 1;
            break;
        }
    }

    if (dotIndex == 0) {

        return FALSE;
    }

    extension.Buffer = &FileName->Buffer[dotIndex];
    extension.Length = (USHORT) ((charCount - dotIndex) * sizeof( WCHAR ));
    extension.MaximumLength = extension.Length;

    FltAcquirePushLockShared( &SafeUploadPolicyLock );

    if (SafeUploadPolicy != NULL) {

        for (index = 0; index < SafeUploadPolicy->ExtensionCount; index += 1) {

            if (RtlCompareUnicodeString( &extension,
                                         &SafeUploadPolicy->Extensions[index],
                                         TRUE ) == 0) {

                matched = TRUE;
                break;
            }
        }
    }

    FltReleasePushLock( &SafeUploadPolicyLock );

    return matched;
}


static
BOOLEAN
SafeUploadPolicyMatchesDestinationNamespace (
    _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind,
    _In_opt_ PCUNICODE_STRING NormalizedPath,
    _In_ BOOLEAN IncludeAncestors
    )
/*++

Routine Description:

    Whether an operation is heading somewhere the policy monitors.

    Removable media and network shares qualify by the kind of volume alone -
    every path on them is a destination. A fixed volume qualifies only when
    the path falls under one of the monitored prefixes, which is how cloud
    sync folders enter scope: from the file system's point of view they are
    ordinary local directories.

    IRQL: <= APC_LEVEL. Takes a push lock shared and allocates nothing.

Arguments:

    VolumeKind - Classification recorded in the instance context.

    NormalizedPath - Path in NT form, when one is available. Without it only
        the volume kind can be judged.

    IncludeAncestors - Also match a name above a monitored prefix, for
        namespace mutation admission. Component boundaries apply both ways.

Return Value:

    TRUE when the operation is in scope.

--*/
{
    BOOLEAN matched;

    FltAcquirePushLockShared( &SafeUploadPolicyLock );
    matched = SafeUploadPolicySnapshotMatchesDestination(
        SafeUploadPolicy, VolumeKind, NormalizedPath, IncludeAncestors);

    FltReleasePushLock( &SafeUploadPolicyLock );

    return matched;
}

BOOLEAN
SafeUploadPolicyMatchesDestination (
    _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind,
    _In_opt_ PCUNICODE_STRING NormalizedPath
    )
{
    return SafeUploadPolicyMatchesDestinationNamespace( VolumeKind, NormalizedPath, FALSE );
}

BOOLEAN SafeUploadPolicyHasDestinationScopes(_In_ SAFEUPLOAD_VOLUME_KIND VolumeKind)
{
    BOOLEAN hasScopes = FALSE;
    FltAcquirePushLockShared(&SafeUploadPolicyLock);
    if (SafeUploadPolicy != NULL) {
        hasScopes = SafeUploadPolicy->PrefixCount != 0 ||
            ((VolumeKind == SafeUploadVolumeUnknown || VolumeKind == SafeUploadVolumeRemovable) &&
             FlagOn(SafeUploadPolicy->Flags, SAFEUPLOAD_POLICY_FLAG_REMOVABLE)) ||
            ((VolumeKind == SafeUploadVolumeUnknown || VolumeKind == SafeUploadVolumeNetwork) &&
             FlagOn(SafeUploadPolicy->Flags, SAFEUPLOAD_POLICY_FLAG_NETWORK));
    }
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (!hasScopes && SafeUploadPendingPolicy != NULL) {
        hasScopes = SafeUploadPendingPolicy->PrefixCount != 0 ||
            ((VolumeKind == SafeUploadVolumeUnknown || VolumeKind == SafeUploadVolumeRemovable) &&
             FlagOn(SafeUploadPendingPolicy->Flags, SAFEUPLOAD_POLICY_FLAG_REMOVABLE)) ||
            ((VolumeKind == SafeUploadVolumeUnknown || VolumeKind == SafeUploadVolumeNetwork) &&
             FlagOn(SafeUploadPendingPolicy->Flags, SAFEUPLOAD_POLICY_FLAG_NETWORK));
    }
#endif
    if (!hasScopes && SafeUploadBootScopesActive) {
        hasScopes = SafeUploadBootScopes.PrefixCount != 0 || SafeUploadBootScopes.Overflow ||
            ((VolumeKind == SafeUploadVolumeUnknown || VolumeKind == SafeUploadVolumeRemovable) &&
             FlagOn(SafeUploadBootScopes.Flags, SAFEUPLOAD_BOOT_POLICY_FLAG_REMOVABLE)) ||
            ((VolumeKind == SafeUploadVolumeUnknown || VolumeKind == SafeUploadVolumeNetwork) &&
             FlagOn(SafeUploadBootScopes.Flags, SAFEUPLOAD_BOOT_POLICY_FLAG_NETWORK));
    }
    FltReleasePushLock(&SafeUploadPolicyLock);
    return hasScopes;
}

BOOLEAN SafeUploadPolicyMayMatchVolume(
    _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind,
    _In_opt_ PFLT_VOLUME Volume)
{
    WCHAR volumeNameBuffer[SAFEUPLOAD_MAX_PREFIX_CHARS];
    UNICODE_STRING volumeName;
    BOOLEAN mayMatch = FALSE;
    ULONG index;
    NTSTATUS status;

    PAGED_CODE();
    if (Volume == NULL) return SafeUploadPolicyHasDestinationScopes(VolumeKind);

    volumeName.Buffer = volumeNameBuffer;
    volumeName.Length = 0;
    volumeName.MaximumLength = sizeof(volumeNameBuffer);
    status = FltGetVolumeName(Volume, &volumeName, NULL);

    FltAcquirePushLockShared(&SafeUploadPolicyLock);
    if (!NT_SUCCESS(status) || volumeName.Length == 0 || (volumeName.Length & 1) != 0) {
        /* A failed volume-name query cannot prove that this is outside every
         * configured prefix. Fail closed whenever any current, pending, or
         * boot destination scope exists. */
        mayMatch = (SafeUploadPolicy != NULL &&
                (SafeUploadPolicy->PrefixCount != 0 ||
                 ((VolumeKind == SafeUploadVolumeUnknown || VolumeKind == SafeUploadVolumeRemovable) &&
                  FlagOn(SafeUploadPolicy->Flags, SAFEUPLOAD_POLICY_FLAG_REMOVABLE)) ||
                 ((VolumeKind == SafeUploadVolumeUnknown || VolumeKind == SafeUploadVolumeNetwork) &&
                  FlagOn(SafeUploadPolicy->Flags, SAFEUPLOAD_POLICY_FLAG_NETWORK)))) ||
#if SAFEUPLOAD_STAGING_PROTOTYPE
            (SafeUploadPendingPolicy != NULL &&
                (SafeUploadPendingPolicy->PrefixCount != 0 ||
                 ((VolumeKind == SafeUploadVolumeUnknown || VolumeKind == SafeUploadVolumeRemovable) &&
                  FlagOn(SafeUploadPendingPolicy->Flags, SAFEUPLOAD_POLICY_FLAG_REMOVABLE)) ||
                 ((VolumeKind == SafeUploadVolumeUnknown || VolumeKind == SafeUploadVolumeNetwork) &&
                  FlagOn(SafeUploadPendingPolicy->Flags, SAFEUPLOAD_POLICY_FLAG_NETWORK)))) ||
#endif
            (SafeUploadBootScopesActive &&
                (SafeUploadBootScopes.PrefixCount != 0 || SafeUploadBootScopes.Overflow ||
                 ((VolumeKind == SafeUploadVolumeUnknown || VolumeKind == SafeUploadVolumeRemovable) &&
                  FlagOn(SafeUploadBootScopes.Flags, SAFEUPLOAD_BOOT_POLICY_FLAG_REMOVABLE)) ||
                 ((VolumeKind == SafeUploadVolumeUnknown || VolumeKind == SafeUploadVolumeNetwork) &&
                  FlagOn(SafeUploadBootScopes.Flags, SAFEUPLOAD_BOOT_POLICY_FLAG_NETWORK))));
    } else {
        if (SafeUploadPolicy != NULL) {
            mayMatch = ((VolumeKind == SafeUploadVolumeUnknown || VolumeKind == SafeUploadVolumeRemovable) &&
                    FlagOn(SafeUploadPolicy->Flags, SAFEUPLOAD_POLICY_FLAG_REMOVABLE)) ||
                ((VolumeKind == SafeUploadVolumeUnknown || VolumeKind == SafeUploadVolumeNetwork) &&
                    FlagOn(SafeUploadPolicy->Flags, SAFEUPLOAD_POLICY_FLAG_NETWORK)) ||
                ((VolumeKind == SafeUploadVolumeUnknown || VolumeKind == SafeUploadVolumeNetwork) &&
                    SafeUploadPolicy->PrefixCount != 0);
            for (index = 0; !mayMatch && index < SafeUploadPolicy->PrefixCount; ++index) {
                mayMatch = SafeUploadPathUnderPrefix(&volumeName, &SafeUploadPolicy->Prefixes[index]);
            }
        }
#if SAFEUPLOAD_STAGING_PROTOTYPE
        if (!mayMatch && SafeUploadPendingPolicy != NULL) {
            mayMatch = ((VolumeKind == SafeUploadVolumeUnknown || VolumeKind == SafeUploadVolumeRemovable) &&
                    FlagOn(SafeUploadPendingPolicy->Flags, SAFEUPLOAD_POLICY_FLAG_REMOVABLE)) ||
                ((VolumeKind == SafeUploadVolumeUnknown || VolumeKind == SafeUploadVolumeNetwork) &&
                    FlagOn(SafeUploadPendingPolicy->Flags, SAFEUPLOAD_POLICY_FLAG_NETWORK)) ||
                ((VolumeKind == SafeUploadVolumeUnknown || VolumeKind == SafeUploadVolumeNetwork) &&
                    SafeUploadPendingPolicy->PrefixCount != 0);
            for (index = 0; !mayMatch && index < SafeUploadPendingPolicy->PrefixCount; ++index) {
                mayMatch = SafeUploadPathUnderPrefix(&volumeName, &SafeUploadPendingPolicy->Prefixes[index]);
            }
        }
#endif
        if (!mayMatch && SafeUploadBootScopesActive) {
            mayMatch = ((VolumeKind == SafeUploadVolumeUnknown || VolumeKind == SafeUploadVolumeRemovable) &&
                    FlagOn(SafeUploadBootScopes.Flags, SAFEUPLOAD_BOOT_POLICY_FLAG_REMOVABLE)) ||
                ((VolumeKind == SafeUploadVolumeUnknown || VolumeKind == SafeUploadVolumeNetwork) &&
                    FlagOn(SafeUploadBootScopes.Flags, SAFEUPLOAD_BOOT_POLICY_FLAG_NETWORK)) ||
                ((VolumeKind == SafeUploadVolumeUnknown || VolumeKind == SafeUploadVolumeNetwork) &&
                    SafeUploadBootScopes.PrefixCount != 0);
            for (index = 0; !mayMatch && index < SafeUploadBootScopes.PrefixCount; ++index) {
                UNICODE_STRING prefix;
                prefix.Buffer = SafeUploadBootScopes.Prefixes[index];
                prefix.Length = (USHORT)(SafeUploadBootScopes.PrefixChars[index] * sizeof(WCHAR));
                prefix.MaximumLength = prefix.Length;
                mayMatch = SafeUploadPathUnderPrefix(&volumeName, &prefix);
            }
            if (!mayMatch && SafeUploadBootScopes.Overflow) mayMatch = TRUE;
        }
    }
    FltReleasePushLock(&SafeUploadPolicyLock);
    return mayMatch;
}

BOOLEAN
SafeUploadPolicyTouchesDestinationNamespace (
    _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind,
    _In_opt_ PCUNICODE_STRING NormalizedPath
    )
{
    /* A directory above a monitored prefix can move the entire destination
       out of policy. Check both directions under the same policy snapshot. */
    return SafeUploadPolicyMatchesDestinationNamespace( VolumeKind, NormalizedPath, TRUE );
}


BOOLEAN
SafeUploadPolicyExcludesImage (
    _In_ PCUNICODE_STRING ImageName
    )
/*++

Routine Description:

    Whether a process image is on the policy's exclusion list.

    This is the RN-014 list, and it exists for the same reason the driver
    already skips its own client: a process the agent depends on must not
    have its I/O routed through the agent.

    IRQL: <= APC_LEVEL.

Arguments:

    ImageName - Final component of the process image.

Return Value:

    TRUE when the process must never be inspected.

--*/
{
    BOOLEAN matched = FALSE;
    UINT32 index;

    if (ImageName == NULL || ImageName->Length == 0) {

        return FALSE;
    }

    FltAcquirePushLockShared( &SafeUploadPolicyLock );

    if (SafeUploadPolicy != NULL) {

        for (index = 0; index < SafeUploadPolicy->ImageCount; index += 1) {

            if (RtlCompareUnicodeString( ImageName,
                                         &SafeUploadPolicy->Images[index],
                                         TRUE ) == 0) {

                matched = TRUE;
                break;
            }
        }
    }

    FltReleasePushLock( &SafeUploadPolicyLock );

    return matched;
}


BOOLEAN
SafeUploadPolicyMatchesSource (
    _In_ PCUNICODE_STRING NormalizedPath
    )
/*++

Routine Description:

    Whether a path sits somewhere the policy considers worth inspecting for
    sensitive content.

    This is the other half of scope, and it is not the same question as the
    destination list. Destination scope asks where a file must not end up;
    source scope asks which files are worth reading to find out whether they
    are sensitive at all.

    Without it the chain that blocks before any byte is written cannot
    start: a document opened from a user folder would never be inspected,
    the process would never be marked as having handled sensitive content,
    and the later write to a pen drive would have nothing to go on.

    IRQL: <= APC_LEVEL. Takes a push lock shared and allocates nothing.

Arguments:

    NormalizedPath - Path in NT form.

Return Value:

    TRUE when the path is under a monitored source prefix.

--*/
{
    BOOLEAN matched = FALSE;
    UINT32 index;

    if (NormalizedPath == NULL || NormalizedPath->Length == 0) {

        return FALSE;
    }

    FltAcquirePushLockShared( &SafeUploadPolicyLock );

    if (SafeUploadPolicy != NULL) {

        if (FlagOn( SafeUploadPolicy->Flags,
                    SAFEUPLOAD_POLICY_FLAG_CLASSIFY_ALL_SOURCES )) {
            matched = TRUE;
        }

        for (index = 0; !matched && index < SafeUploadPolicy->SourcePrefixCount; index += 1) {

            if (SafeUploadPathUnderPrefix( &SafeUploadPolicy->SourcePrefixes[index],
                                           NormalizedPath )) {

                matched = TRUE;
                break;
            }
        }
    }

    FltReleasePushLock( &SafeUploadPolicyLock );

    return matched;
}

#if SAFEUPLOAD_STAGING_PROTOTYPE

VOID
SafeUploadPolicySetPending (
    _In_opt_ const SAFEUPLOAD_POLICY *Pending
    )
/*++

Routine Description:

    Publishes (or clears) the candidate snapshot of a policy update in
    transition. Taking the lock exclusively waits out every reader, so a
    snapshot is never freed while the current-or-pending destination matcher
    is inspecting it.

    IRQL: PASSIVE_LEVEL.

--*/
{
    PAGED_CODE();

    FltAcquirePushLockExclusive( &SafeUploadPolicyLock );
    SafeUploadPendingPolicy = Pending;
    FltReleasePushLock( &SafeUploadPolicyLock );
}

#endif

BOOLEAN
SafeUploadPolicyMatchesCurrentOrPendingDestination (
    _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind,
    _In_opt_ PCUNICODE_STRING NormalizedPath,
    _In_ BOOLEAN IncludeAncestors
    )
/*++

Routine Description:

    Tests the current policy and, in prototype builds, the pending snapshot
    under one shared lock. Callers may also request component-bounded
    ancestor matching for namespace
    mutations such as reparse changes on a parent of a protected prefix.

    IRQL: <= APC_LEVEL.

--*/
{
    BOOLEAN matched;

    FltAcquirePushLockShared( &SafeUploadPolicyLock );
    matched = SafeUploadPolicySnapshotMatchesDestination(
        SafeUploadPolicy, VolumeKind, NormalizedPath, IncludeAncestors);
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (!matched) {
        matched = SafeUploadPolicySnapshotMatchesDestination(
            SafeUploadPendingPolicy, VolumeKind, NormalizedPath, IncludeAncestors);
    }
#endif
    FltReleasePushLock( &SafeUploadPolicyLock );

    return matched;
}

#if SAFEUPLOAD_STAGING_PROTOTYPE

NTSTATUS
SafeUploadPolicyCopyScope (
    _In_opt_ const SAFEUPLOAD_POLICY *Candidate,
    _Out_ PSAFEUPLOAD_SCOPE_COPY Scope
    )
/*++

Routine Description:

    Copies the destination prefixes of a snapshot (the candidate, or the
    current policy when Candidate is NULL) so the fence scan can do file I/O
    without holding the policy lock.

    IRQL: PASSIVE_LEVEL.

--*/
{
    const SAFEUPLOAD_POLICY *source = Candidate;
    UINT32 index;

    PAGED_CODE();

    RtlZeroMemory( Scope, sizeof( *Scope ) );

    if (source == NULL) {

        FltAcquirePushLockShared( &SafeUploadPolicyLock );
        source = SafeUploadPolicy;

        if (source == NULL) {

            FltReleasePushLock( &SafeUploadPolicyLock );
            return STATUS_SUCCESS;
        }
    }

    Scope->Flags = source->Flags;

    for (index = 0; index < source->PrefixCount && index < SAFEUPLOAD_MAX_PREFIXES; index += 1) {

        USHORT bytes = source->Prefixes[index].Length;

        //
        //  A prefix the scan cannot represent must not be silently dropped: its
        //  descendants would be in scope but never scanned. Fail closed.
        //

        if (bytes == 0 || (bytes & 1) != 0 ||
            bytes > SAFEUPLOAD_MAX_PREFIX_CHARS * sizeof( WCHAR )) {

            if (Candidate == NULL) {

                FltReleasePushLock( &SafeUploadPolicyLock );
            }
            return STATUS_INVALID_PARAMETER;
        }

        RtlCopyMemory( Scope->Prefix[Scope->Count], source->Prefixes[index].Buffer, bytes );
        Scope->Length[Scope->Count] = bytes;
        Scope->Count += 1;
    }

    if (Candidate == NULL) {

        FltReleasePushLock( &SafeUploadPolicyLock );
    }

    return STATUS_SUCCESS;
}

#endif
