#ifndef SAFEUPLOAD_STAGE_NATIVE_RECORDS_H
#define SAFEUPLOAD_STAGE_NATIVE_RECORDS_H
#include "StagePublic.h"
#include "StagePublicRelay.h"

#if SAFEUPLOAD_STAGING_PROTOTYPE
typedef struct _SAFEUPLOAD_STAGE_NATIVE_RECORD SAFEUPLOAD_STAGE_NATIVE_RECORD,
    *PSAFEUPLOAD_STAGE_NATIVE_RECORD;

/* Internal bookkeeping, not another wire/journal state machine. Generation
 * can be unknown before the pre-CREATE RPC returns; the immutable operation
 * binding is sufficient to reconcile that RPC against the durable head. */
typedef struct _SAFEUPLOAD_STAGE_NATIVE_BINDING {
    GUID DriverInstanceId;
    GUID TransferId;
    GUID RequestNonce;
    GUID OperationId;
    UINT64 ConnectionEpoch;
    ULONG OsBootSequence;
    ULONG CreateOptions;
    SAFEUPLOAD_STAGE_PUBLIC_BINDING Public;
} SAFEUPLOAD_STAGE_NATIVE_BINDING, *PSAFEUPLOAD_STAGE_NATIVE_BINDING;

typedef struct _SAFEUPLOAD_STAGE_PUBLIC_MUTATION {
    UINT64 Sequence, Generation;
    GUID TransferId, Nonce, OperationId;
    ULONG InformationClass, DispositionFlags, RequestorMode, Facts;
    NTSTATUS Status;
    LONG64 ActorProcessCreationTime;
    ULONG ActorProcessId, ActorSessionId, ActorSidBytes;
    UCHAR ActorSid[SAFEUPLOAD_NATIVE_REPLAY_SID_BYTES];
} SAFEUPLOAD_STAGE_PUBLIC_MUTATION, *PSAFEUPLOAD_STAGE_PUBLIC_MUTATION;

typedef struct _SAFEUPLOAD_STAGE_NATIVE_SNAPSHOT {
    SAFEUPLOAD_STAGE_NATIVE_BINDING Binding;
    UINT64 JournalGeneration;
    BOOLEAN Forwarded;
    BOOLEAN CreateOutcomeKnown;
    BOOLEAN CreateAccepted;
    BOOLEAN IdentityAndDeleteGrantChecked;
    BOOLEAN LastHandleCleanedUp;
    BOOLEAN CancelledBeforeHandle;
    BOOLEAN CancelledCloseObserved;
    BOOLEAN CleanupCoverageLost;
    NTSTATUS CreateStatus;
    NTSTATUS IdentityStatus;
    FLT_INSTANCE_TEARDOWN_FLAGS TeardownReason;
    BOOLEAN PublicOpenPrepared;
    BOOLEAN PublicOpenConfirmed;
    BOOLEAN PublicCleanupOutstanding;
    UINT64 PublishedGeneration;
    SAFEUPLOAD_STAGE_IDENTITY_V19 PublishedIdentity;
    ACCESS_MASK GrantedAccess; /* explicit requested subset, only after checked native CREATE */
    SAFEUPLOAD_STAGE_PUBLIC_MUTATION PublicOperation;
} SAFEUPLOAD_STAGE_NATIVE_SNAPSHOT, *PSAFEUPLOAD_STAGE_NATIVE_SNAPSHOT;

_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadStageNativeInitialize(_In_ const GUID *DriverInstanceId, _In_ ULONG OsBootSequence,
    _In_ PKEVENT WakeEvent);
_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadStageNativeUninitialize(VOID);

/* Reserve before sending the durable pre-CREATE intent. The pending CREATE
 * owns the original object lifetime; the map uses a non-owning exact key.
 * No handle/object reference or optional context keeps the open alive. */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStageNativeReserve(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT FileObject,
    _In_ const SAFEUPLOAD_STAGE_NATIVE_BINDING *Binding,
    _Outptr_result_nullonfailure_ PSAFEUPLOAD_STAGE_NATIVE_RECORD *Record);
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStageNativeMarkForwarded(_In_ PSAFEUPLOAD_STAGE_NATIVE_RECORD Record,
    _In_ UINT64 DurableGeneration, _In_ UINT64 ExpectedRevision, _In_ UINT64 AuthorityRevision,
    _In_opt_ const SAFEUPLOAD_PUBLIC_RELAY_REPLY *PublicOpenReceipt);
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStageNativeSnapshot(_In_ PSAFEUPLOAD_STAGE_NATIVE_RECORD Record,
    _Out_ PSAFEUPLOAD_STAGE_NATIVE_SNAPSHOT Snapshot, _Out_ PUINT64 Revision);
/* On successful MarkForwarded, return Record as the original CREATE's
 * completion context. Its producer reference transfers to that post callback;
 * do not ReleaseRecord afterwards. Complete all cancel gates before marking. */
/* Use after a failed/canceled preparation, including an uncertain RPC reply.
 * Its negative CREATE receipt stays replayable until the exact service ACK. */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStageNativeMarkNotForwarded(_In_ PSAFEUPLOAD_STAGE_NATIVE_RECORD Record);
_IRQL_requires_max_(APC_LEVEL)
VOID SafeUploadStageNativeReleaseRecord(_In_ PSAFEUPLOAD_STAGE_NATIVE_RECORD Record);

/* Ordinary native-object disposition stays in the original callback. No
 * worker reissues an operation or substitutes another security subject. */
_IRQL_requires_max_(APC_LEVEL)
FLT_PREOP_CALLBACK_STATUS SafeUploadStagePublicDispositionPre(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _Outptr_result_maybenull_ PVOID *CompletionContext,
    _Out_ PBOOLEAN Handled);
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN SafeUploadStagePublicDispositionPost(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStagePublicDispositionConfirm(_In_ const SAFEUPLOAD_STAGE_NATIVE_SNAPSHOT *Snapshot,
    _In_ const SAFEUPLOAD_PUBLIC_RELAY_REPLY *Reply, _In_ UINT64 AuthorityRevision);

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN SafeUploadStageNativePostCreate(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);
_IRQL_requires_max_(APC_LEVEL)
VOID SafeUploadStageNativePostCleanup(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _In_ FLT_POST_OPERATION_FLAGS Flags);
/* The key is removed before CLOSE can permit object-address reuse. A CLOSE
 * proves the special upper-filter cancellation case only with the original
 * cancel flag and no created handle, captured before forwarding CLOSE. */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN SafeUploadStageNativePreClose(_In_ PCFLT_RELATED_OBJECTS Objects,
    _Outptr_result_maybenull_ PVOID *CompletionContext);
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN SafeUploadStageNativePostClose(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);
_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadStageNativeInstanceTeardownStart(_In_ PFLT_INSTANCE Instance,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason);

/* All pages must use one unchanged revision. A partial/stale replay cannot
 * authorize absence. The future authenticated exporter owns transport and
 * current connection provenance; this internal snapshot grants no permit. */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS SafeUploadStageNativeReadPage(_In_ UINT64 ExpectedRevision, _In_ ULONG Offset,
    _Out_writes_to_(Capacity, *Count) PSAFEUPLOAD_STAGE_NATIVE_SNAPSHOT Rows, _In_ ULONG Capacity,
    _Out_ PULONG Count, _Out_ PUINT64 Revision, _Out_ PBOOLEAN Complete);
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS SafeUploadStagePublicOpenReadPage(_In_ UINT64 ExpectedRevision, _In_ ULONG Offset,
    _Out_writes_to_(Capacity, *Count) PSAFEUPLOAD_STAGE_NATIVE_SNAPSHOT Rows, _In_ ULONG Capacity,
    _Out_ PULONG Count, _Out_ PUINT64 Revision, _Out_ PBOOLEAN Complete);
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStagePublicOpenReplayControl(_In_opt_ PVOID PortCookie,
    _In_reads_bytes_(InputLength) PVOID Input, _In_ ULONG InputLength,
    _Out_writes_bytes_(OutputLength) PVOID Output, _In_ ULONG OutputLength, _Out_ PULONG Returned);
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS SafeUploadStageNativeReadIdentity(_Out_ GUID *DriverInstanceId, _Out_ PULONG OsBootSequence);
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS SafeUploadStageNativeReadRevision(_Out_ PUINT64 Revision);
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStageNativeReplayControl(_In_opt_ PVOID PortCookie,
    _In_reads_bytes_(InputLength) PVOID Input, _In_ ULONG InputLength,
    _Out_writes_bytes_(OutputLength) PVOID Output, _In_ ULONG OutputLength,
    _Out_ PULONG Returned);
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStageNativeNameControl(_In_opt_ PVOID PortCookie,
    _In_reads_bytes_(InputLength) PVOID Input, _In_ ULONG InputLength,
    _Out_writes_bytes_(OutputLength) PVOID Output, _In_ ULONG OutputLength,
    _Out_ PULONG Returned);
/* Call only after the authenticated service's exact terminal cleanup ACK,
 * never merely after releasing the exceptional publication hold. */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStageNativeAcknowledge(_In_ const SAFEUPLOAD_STAGE_NATIVE_BINDING *Binding);
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStagePublicOpenConfirm(_In_ const SAFEUPLOAD_STAGE_NATIVE_BINDING *Binding,
    _In_ UINT64 AuthorityRevision);
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN SafeUploadStageNativeTryCloseAdmission(VOID);
VOID SafeUploadStageNativeReopenAdmission(VOID);
#endif
#endif
