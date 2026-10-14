#ifndef SAFEUPLOAD_STAGE_H
#define SAFEUPLOAD_STAGE_H

#include "Filter.h"
#include "StageBoundAllocation.h"
#include "StageNativeWire.h"
#include "StagePublicRelay.h"
#if SAFEUPLOAD_STAGING_PROTOTYPE
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStageCancelPrivate(_In_ const SAFEUPLOAD_PRIVATE_CANCEL_REQUEST *Request,
    _Out_ PSAFEUPLOAD_PRIVATE_CANCEL_REPLY Reply);
#endif

NTSTATUS SafeUploadStageInitialize(VOID);
#if SAFEUPLOAD_STAGING_PROTOTYPE
VOID SafeUploadStageSetFilteringReady(VOID);
struct _SAFEUPLOAD_STAGE_NATIVE_SNAPSHOT;
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStageNativeExchange(_In_ const struct _SAFEUPLOAD_STAGE_NATIVE_SNAPSHOT *Snapshot,
    _In_ UINT64 MapRevision, _In_ UINT32 Phase, _Out_ PSAFEUPLOAD_NATIVE_LIFECYCLE_REPLY Reply,
    _Out_opt_ PUINT64 AuthorityRevision);
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStagePublicOpenExchange(_In_ const struct _SAFEUPLOAD_STAGE_NATIVE_SNAPSHOT *Snapshot,
    _In_ UINT64 MapRevision, _In_ UINT32 Phase,
    _Out_ PSAFEUPLOAD_PUBLIC_RELAY_REPLY Reply, _Out_opt_ PUINT64 AuthorityRevision);
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN SafeUploadStageProtocolNativeForwardAllowed(_In_ UINT64 ConnectionEpoch, _In_ UINT64 AuthorityRevision);
_IRQL_requires_max_(DISPATCH_LEVEL)
UINT64 SafeUploadStageProtocolNativeAuthority(VOID);
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN SafeUploadStageProtocolBoundAllocationReady(VOID);
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN SafeUploadStageProtocolMetadataIdentity(_In_opt_ PVOID ExpectedCookie,
    _Out_ PVOID *Cookie, _Out_ PUINT64 Epoch, _Out_ PUINT64 Revision);
#endif
NTSTATUS SafeUploadStageStartWorker(VOID);
VOID SafeUploadStageStopWorker(VOID);
NTSTATUS SafeUploadStagePrepareUnload(_In_ BOOLEAN Mandatory);
_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadStageReleaseInstanceReferences(VOID);
#if SAFEUPLOAD_STAGING_PROTOTYPE
BOOLEAN SafeUploadStageUnloadIsQuarantined(VOID);
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN SafeUploadStageMandatoryTeardownActive(VOID);
_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadStageBeginMandatoryTeardown(VOID);
_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadStageDrainMandatoryTeardown(VOID);
#endif
VOID SafeUploadStageRecordUnloadVeto(_In_ UINT32 Reason, _In_ NTSTATUS Status);
VOID SafeUploadStageGetUnloadStatus(_Out_ PUINT32 Streams, _Out_ PUINT32 FileObjects,
    _Out_ PUINT32 Reason, _Out_ PUINT32 Status);
VOID SafeUploadStageFree(VOID);
BOOLEAN SafeUploadStageCanDetach(VOID);
FLT_PREOP_CALLBACK_STATUS SafeUploadStageDispatch(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, PVOID *CompletionContext);
FLT_POSTOP_CALLBACK_STATUS SafeUploadStagePostOperation(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags);
NTSTATUS SafeUploadStageGenerateName(PFLT_INSTANCE Instance, PFILE_OBJECT FileObject,
    PFLT_CALLBACK_DATA Data, FLT_FILE_NAME_OPTIONS Options, PBOOLEAN CacheName,
    PFLT_NAME_CONTROL Output);
NTSTATUS SafeUploadStageNormalizeComponent(PFLT_INSTANCE Instance, PCUNICODE_STRING Parent,
    USHORT VolumeNameLength, PCUNICODE_STRING Component, PFILE_NAMES_INFORMATION Output,
    ULONG Length, FLT_NORMALIZE_NAME_FLAGS Flags, PVOID *Context);

VOID SafeUploadCopyRequestImageName(_In_ PFLT_CALLBACK_DATA Data, _Inout_ PSAFEUPLOAD_REQUEST Request);
VOID SafeUploadStageInitializeProtocol(VOID);
#if SAFEUPLOAD_STAGING_PROTOTYPE
_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadStageProtocolPublishClientPort(_In_ PVOID ConnectionCookie);
VOID SafeUploadStageProtocolConnectionReset(_In_ PVOID ConnectionCookie);
VOID SafeUploadStageProtocolAuthenticationChanged(_In_ PVOID ConnectionCookie);
BOOLEAN SafeUploadStageProtocolConnectionCurrent(_In_ PVOID ConnectionCookie);
VOID SafeUploadStageServiceDisconnected(_In_ PVOID ConnectionCookie);
BOOLEAN SafeUploadStageProtocolIsReady(VOID);
/* Short capability-handoff snapshot. The caller releases its process/channel
 * hold with SafeUploadConnectionReleaseAuthenticatedProcess. This is not a
 * disposition permit and must not be held while waiting for last close. */
_Success_(return != FALSE)
BOOLEAN SafeUploadStageProtocolPinPublicService(_In_ LONG ExpectedChannelGeneration,
    _Outptr_result_nullonfailure_ PVOID *ConnectionCookie,
    _Out_ PLONG64 ConnectionGeneration,
    _Outptr_result_nullonfailure_ PEPROCESS *Process);
BOOLEAN SafeUploadStageProtocolIsDrainReplayOnly(VOID);
LONG SafeUploadStageProtocolChannelGeneration(VOID);
NTSTATUS SafeUploadStageRenameExchangeV19(_In_ PSAFEUPLOAD_EXCHANGE Exchange);
#endif
BOOLEAN SafeUploadStageProtectedName(_In_ PFLT_FILE_NAME_INFORMATION Name, _In_ SAFEUPLOAD_VOLUME_KIND Kind);
BOOLEAN SafeUploadStageTouchesProtectedNamespace(_In_ PFLT_FILE_NAME_INFORMATION Name, _In_ SAFEUPLOAD_VOLUME_KIND Kind);
BOOLEAN SafeUploadStageProtectedPath(_In_ PUNICODE_STRING Name, _In_ USHORT VolumeLength, _In_ SAFEUPLOAD_VOLUME_KIND Kind);
/* What the create gate's alias check proved about a writer open of a name outside every scope (T3d): no link of the file at that
 * name is inside a current or pending scope (or no file had the name), checked against policy scope sequence ScopeSequence. The
 * writer registry turns it into the entry's OUTSIDE classification when the same file is bound under the same sequence. */
typedef struct _SAFEUPLOAD_CREATE_ALIAS_PROOF {
    BOOLEAN Valid;
    BOOLEAN Absent;                 /* no file had the name: valid only for the open that creates the file */
    ULONGLONG ScopeSequence;        /* SafeUploadPolicyScopeSequenceSnapshot() read before the check */
    FILE_ID_INFORMATION Identity;   /* the file the check examined, when it existed */
} SAFEUPLOAD_CREATE_ALIAS_PROOF, *PSAFEUPLOAD_CREATE_ALIAS_PROOF;
NTSTATUS SafeUploadStageCheckNamedAliases(_In_ PFLT_INSTANCE Instance, _In_ PFLT_FILE_NAME_INFORMATION Name,
    _In_ SAFEUPLOAD_VOLUME_KIND Kind, _Out_ PBOOLEAN Protected, _Inout_opt_ PSAFEUPLOAD_CREATE_ALIAS_PROOF Proof);
NTSTATUS SafeUploadStageCheckObjectAliases(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT Object,
    _In_ PUNICODE_STRING Volume, _In_ SAFEUPLOAD_VOLUME_KIND Kind, _Out_ PBOOLEAN Protected);
BOOLEAN SafeUploadPublicationCreate(_In_ PUNICODE_STRING Name, _In_ ULONG Disposition, _In_ BOOLEAN Writer);
BOOLEAN SafeUploadPublicationRename(_In_ PFLT_VOLUME TargetVolume, _In_ PUNICODE_STRING Source,
    _In_ PUNICODE_STRING Destination, _Out_ PBOOLEAN QuarantineRefused);
NTSTATUS SafeUploadStageAllocate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PUNICODE_STRING OriginalName,
    _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind, _In_opt_ PUNICODE_STRING PreviousStageName,
    _In_opt_ PUNICODE_STRING TombstoneStageName,
    _Out_writes_(SAFEUPLOAD_MAX_STAGE_NAME_CHARS) PWCH StageName, _Out_ PUSHORT StageNameLength);
#if SAFEUPLOAD_STAGING_PROTOTYPE
NTSTATUS SafeUploadStageAllocateV19(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PUNICODE_STRING OriginalName,
    _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind, _In_opt_ PUNICODE_STRING PreviousStageName,
    _In_opt_ PUNICODE_STRING TombstoneStageName,
    _Out_writes_(SAFEUPLOAD_MAX_STAGE_NAME_CHARS) PWCH StageName, _Out_ PUSHORT StageNameLength,
    _In_ const GUID *DriverInstanceId,
    _Out_ PUINT64 DestinationGeneration, _Out_ PSAFEUPLOAD_STAGE_IDENTITY_V19 StageIdentity,
    _Out_ PSAFEUPLOAD_STAGE_ALLOCATE_V19 AllocationIntent,
    _Out_ PSAFEUPLOAD_REQUEST AllocationRequest, _Out_ PBOOLEAN AllocationMayExist);
NTSTATUS SafeUploadStageReplayAllocationV19(_In_ const SAFEUPLOAD_REQUEST *AllocationRequest,
    _Out_writes_(SAFEUPLOAD_MAX_STAGE_NAME_CHARS) PWCH StageName, _Out_ PUSHORT StageNameLength,
    _Out_ PUINT64 DestinationGeneration, _Out_ PSAFEUPLOAD_STAGE_IDENTITY_V19 StageIdentity);
struct _SAFEUPLOAD_STAGE_WRITER_LEASE;
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStageAllocateBoundV23(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ struct _SAFEUPLOAD_STAGE_WRITER_LEASE *WriterLease,
    _In_ PUNICODE_STRING CanonicalName, _In_ const SAFEUPLOAD_STAGE_ALLOCATE_V23 *Binding,
    _In_ const GUID *DriverInstanceId,
    _Out_writes_(SAFEUPLOAD_MAX_STAGE_NAME_CHARS) PWCH StageName, _Out_ PUSHORT StageNameLength,
    _Out_ PUINT64 DestinationGeneration, _Out_ PSAFEUPLOAD_STAGE_IDENTITY_V19 StageIdentity,
    _Out_ PSAFEUPLOAD_STAGE_ALLOCATE_V19 RetainedIntent,
    _Out_ PSAFEUPLOAD_REQUEST AllocationRequest, _Out_ PBOOLEAN AllocationMayExist);
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStageReplayAllocationBoundV23(_In_ struct _SAFEUPLOAD_STAGE_WRITER_LEASE *WriterLease,
    _In_ const SAFEUPLOAD_REQUEST *AllocationRequest,
    _Out_writes_(SAFEUPLOAD_MAX_STAGE_NAME_CHARS) PWCH StageName, _Out_ PUSHORT StageNameLength,
    _Out_ PUINT64 DestinationGeneration, _Out_ PSAFEUPLOAD_STAGE_IDENTITY_V19 StageIdentity);
NTSTATUS SafeUploadStageReconcileV20(_In_ const GUID *DriverInstanceId,
    _In_ LONG ExpectedChannelGeneration, _In_opt_ const SAFEUPLOAD_REQUEST *DrainReplayRequest);
NTSTATUS SafeUploadStageAttachmentExchangeV20(_In_ ULONG ProcessId,
    _In_ PUNICODE_STRING DestinationName, _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind,
    _In_ UINT32 Operation, _In_ const GUID *TransferId,
    _In_ UINT64 DestinationGeneration, _In_ const SAFEUPLOAD_STAGE_IDENTITY_V19 *StageIdentity,
    _In_ const GUID *DriverInstanceId,
    _In_ const SAFEUPLOAD_STAGE_IDENTITY_V19 *ParentDirectoryIdentity,
    _Inout_ PSAFEUPLOAD_REQUEST RequestSnapshot, _Out_ PUINT32 Result,
    _Out_ PBOOLEAN RequestMayExist);
BOOLEAN SafeUploadStageAttachmentRequestV20Matches(_In_ const SAFEUPLOAD_REQUEST *RequestSnapshot,
    _In_ ULONG ProcessId, _In_ PUNICODE_STRING DestinationName,
    _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind, _In_ UINT32 Operation,
    _In_ const GUID *TransferId, _In_ UINT64 DestinationGeneration,
    _In_ const SAFEUPLOAD_STAGE_IDENTITY_V19 *StageIdentity,
    _In_ const GUID *DriverInstanceId,
    _In_ const SAFEUPLOAD_STAGE_IDENTITY_V19 *ParentDirectoryIdentity);
NTSTATUS SafeUploadStageEpochDrainV20(_In_ const GUID *DriverInstanceId,
    _In_ UINT64 DrainNonce, _Inout_ PSAFEUPLOAD_REQUEST RequestSnapshot,
    _Out_ PUINT32 Result);
#endif
NTSTATUS SafeUploadStageSeal(_In_ ULONG ProcessId, _In_ PUNICODE_STRING StageName);
NTSTATUS SafeUploadStageDiscard(_In_ ULONG ProcessId, _In_ PUNICODE_STRING StageName);
#if SAFEUPLOAD_STAGING_PROTOTYPE
NTSTATUS SafeUploadStageSealVersionV19(_In_ ULONG ProcessId, _In_ PUNICODE_STRING StageName,
    _In_ const SAFEUPLOAD_STAGE_IDENTITY_V19 *StageIdentity, _In_ UINT64 DestinationGeneration);
NTSTATUS SafeUploadStageDiscardVersionV19(_In_ ULONG ProcessId, _In_ PUNICODE_STRING StageName,
    _In_ const GUID *ReservationId, _In_ const SAFEUPLOAD_STAGE_IDENTITY_V19 *StageIdentity,
    _In_ UINT64 DestinationGeneration, _In_ UINT32 Kind, _Out_ PUINT32 Result);
#endif
NTSTATUS SafeUploadStageExchangeResult(_In_ NTSTATUS SendStatus, _In_ BOOLEAN Answered, _In_ UINT32 Verdict);
BOOLEAN SafeUploadStageTxfSetInformationMustRefuse(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects);
BOOLEAN SafeUploadStageTxfCreateMustRefuse(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects);
BOOLEAN SafeUploadStageTxfFsctlMustRefuse(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects);
VOID SafeUploadStageTxfRecordRefused(VOID);
FLT_PREOP_CALLBACK_STATUS SafeUploadStageTxfFsctlPreOperation(
    _In_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS Objects,
    _Out_ PVOID *CompletionContext);

#if SAFEUPLOAD_STAGING_PROTOTYPE
/* StageStream.c, T4 stage-version lifetime: events that wake the stage worker. */
NTSTATUS SafeUploadStageDispose(_In_ PSAFEUPLOAD_STAGE_DISPOSE_MESSAGE Message, _Out_ PUINT32 Held);
VOID SafeUploadStageServiceConnected(_In_ PVOID ConnectionCookie);
VOID SafeUploadStageProcessExited(_In_ HANDLE ProcessId);
_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadStageAttachInstanceTeardownStart(_In_ PFLT_INSTANCE Instance);
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN SafeUploadStageAttachInstanceRetiring(_In_ PFLT_INSTANCE Instance);
_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadStageAttachInstanceTeardownComplete(_In_ PFLT_INSTANCE Instance);
VOID SafeUploadStageGetLifetimeCounters(_Out_ PSAFEUPLOAD_STAGE_LIFETIME_COUNTERS Counters);

/* DenyRing.c: always-on record of operations completed with an error status. */
VOID SafeUploadDenyRingInitialize(VOID);
VOID SafeUploadDenySiteHint(_In_ PFLT_CALLBACK_DATA Data, _In_ PVOID Site);
VOID SafeUploadDenyDetail(_In_ PFLT_CALLBACK_DATA Data, _In_ UINT32 Reason, _In_ NTSTATUS Aux, _In_opt_ PCUNICODE_STRING Name);
VOID SafeUploadDenyNote(_In_ PFLT_CALLBACK_DATA Data, _In_opt_ PCFLT_RELATED_OBJECTS Objects,
    _In_ NTSTATUS Status, _In_ BOOLEAN PostOperation);
NTSTATUS SafeUploadDenyRingReadBatch(_In_ UINT64 AfterSequence, _Out_ PSAFEUPLOAD_DENY_RING_BATCH Batch);
VOID SafeUploadDenyGetCounters(_Out_ PSAFEUPLOAD_DIAG_COUNTERS Counters);

extern volatile LONG SafeUploadAdmissionTraceControlState;
extern volatile LONG SafeUploadAdmissionTraceSectionEvents;
BOOLEAN SafeUploadStageAdmissionTraceBegin(_In_ LONG TraceState);
VOID SafeUploadStageAdmissionTraceRecord(_In_ const SAFEUPLOAD_ADMISSION_TRACE_ENTRY *Entry);
VOID SafeUploadStageAdmissionTraceNoteLost(_In_ LONG TraceState);
VOID SafeUploadStageAdmissionTraceNoteTicketLost(VOID);
VOID SafeUploadStageAdmissionTraceEnd(VOID);
NTSTATUS SafeUploadStageAdmissionTraceControl(_In_ UINT32 Command, _In_ UINT32 Options);
NTSTATUS SafeUploadStageAdmissionTraceReadBatch(
    _In_ UINT64 Cursor,
    _In_ UINT64 SnapshotSequence,
    _Out_ PSAFEUPLOAD_ADMISSION_TRACE_BATCH Batch);
NTSTATUS SafeUploadStageAdmissionProbe(
    _In_ PCUNICODE_STRING VolumeName,
    _In_ PCUNICODE_STRING RelativePath);
NTSTATUS SafeUploadStageRegistryEntryProbe(_In_ PCUNICODE_STRING VolumeName,
    _In_ PCUNICODE_STRING RelativePath, _Out_ PSAFEUPLOAD_REGISTRY_ENTRY_STATUS Status);
NTSTATUS SafeUploadStageAdmissionDeleteStreamContext(
    _In_ PCUNICODE_STRING VolumeName,
    _In_ PCUNICODE_STRING RelativePath);
NTSTATUS SafeUploadStageOpenByIdentity(_In_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING VolumeName, _In_ PFILE_OBJECT SourceObject,
    _Out_ PHANDLE Handle, _Outptr_result_nullonfailure_ PFILE_OBJECT *Object,
    _Out_ PUINT32 ProbeStage);
VOID SafeUploadStageAdmissionReady(VOID);
VOID SafeUploadStageAdmissionTopologyBegin(VOID);
VOID SafeUploadStageAdmissionTopologyEnd(VOID);
VOID SafeUploadStageAdmissionTopologyTeardownBegin(VOID);
VOID SafeUploadStageAdmissionTopologyTeardownEnd(VOID);
VOID SafeUploadStageAdmissionCoverageBegin(VOID);
VOID SafeUploadStageAdmissionCoverageEnd(VOID);
/* Quiescent observation of the existing counters; no I/O under a lock. */
BOOLEAN SafeUploadStageAdmissionReadTopology(_Out_ PUINT64 Topology, _Out_ PUINT64 Coverage);
NTSTATUS SafeUploadStageAdmissionCoverageStatus(
    _Out_ PSAFEUPLOAD_ADMISSION_COVERAGE_STATUS Status);
NTSTATUS SafeUploadStageAdmissionVolumeStatus(
    _Out_ PSAFEUPLOAD_ADMISSION_VOLUME_STATUS Status,
    _In_ BOOLEAN EnforceCanaryDeadline);
NTSTATUS SafeUploadStageAdmissionCanaryHold(_In_ PCUNICODE_STRING VolumeName,
    _In_ UINT32 HoldMilliseconds, _Out_ PSAFEUPLOAD_ADMISSION_CANARY_HOLD_REPLY Reply);
VOID SafeUploadStageAdmissionCanaryHoldCancel(VOID);
NTSTATUS SafeUploadStageVolumeFlags(_In_ PFLT_VOLUME Volume, _Out_ PUINT32 Flags);
UINT32 SafeUploadStageWritersGlobalUnknown(VOID);
VOID SafeUploadStageWritersInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason);
VOID SafeUploadStageWritersInstanceContextFreed(
    _Inout_ PSAFEUPLOAD_INSTANCE_TEARDOWN_TOKEN Token,
    _In_ BOOLEAN Published);
VOID SafeUploadStageCanaryTick(VOID);
NTSTATUS SafeUploadStageAdmissionStartWorker(VOID);
VOID SafeUploadStageAdmissionStopWorker(VOID);
_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadStageAdmissionBeginTeardown(VOID);

/* StageWriters.c: bounded writer-history ledger and activation state. */
/* Count before acquiring references/forwarding; release after final local drain.
 * These resident hooks serialize with SOP retirement, not with service ACKs. */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID SafeUploadStageWritersOwnerAcquire(VOID);
_IRQL_requires_max_(APC_LEVEL)
VOID SafeUploadStageWritersOwnerRelease(VOID);
_IRQL_requires_max_(DISPATCH_LEVEL)
LONG SafeUploadStageWritersOwnerCount(VOID);
_IRQL_requires_max_(APC_LEVEL)
VOID SafeUploadStageWritersInvalidateLifetime(_Inout_ PSAFEUPLOAD_STREAM_CONTEXT Context);

#define SAFEUPLOAD_WRITERS_ONLY_CONTEXT ((PVOID)(ULONG_PTR)0x1000)
BOOLEAN SafeUploadStageWritersWantPostCreate(_In_ PFLT_CALLBACK_DATA Data);
NTSTATUS SafeUploadStageWritersReserveCreate(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects, _Outptr_result_maybenull_ PVOID *Reservation,
    _Out_ PBOOLEAN Required, _In_opt_ const SAFEUPLOAD_CREATE_ALIAS_PROOF *AliasProof);
VOID SafeUploadStageWritersTrackingLostAt(_In_opt_ PFLT_INSTANCE Instance, _In_ LONG Reason,
    _In_ ULONG OriginSite);
#define SafeUploadStageWritersTrackingLost(Instance, Reason) \
    SafeUploadStageWritersTrackingLostAt((Instance), (Reason), (ULONG)__LINE__)
VOID SafeUploadStageWritersSetCompletion(_In_ PVOID Reservation,
    _In_opt_ PVOID LegacyCompletionContext, _In_ BOOLEAN LegacyCallbackRequired);
BOOLEAN SafeUploadStageWritersIsReservation(_In_opt_ PVOID Context);
VOID SafeUploadStageWritersCancelReservation(_In_opt_ PVOID Reservation);
NTSTATUS SafeUploadStageWritersPrepareRename(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ PCUNICODE_STRING Source,
    _In_ PCUNICODE_STRING Destination,
    _In_ BOOLEAN LinkOperation, _Outptr_result_maybenull_ PVOID *RenameContext);
BOOLEAN SafeUploadStageWritersIsRenameContext(_In_opt_ PVOID Context);
VOID SafeUploadStageWritersCompleteRename(_In_ PFLT_INSTANCE Instance, _In_opt_ PVOID Context,
    _In_ BOOLEAN Succeeded, _In_ BOOLEAN Draining);
NTSTATUS SafeUploadStageWritersPostCreate(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_POST_OPERATION_FLAGS Flags,
    _In_opt_ PVOID Reservation, _Out_opt_ PVOID *LegacyCompletionContext,
    _Out_opt_ PBOOLEAN LegacyCallbackRequired);
_IRQL_requires_max_(APC_LEVEL)
VOID SafeUploadStageWritersOnCleanup(_In_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects);
BOOLEAN SafeUploadStageWritersNameActivating(_In_ PFLT_INSTANCE Instance, _In_ PCUNICODE_STRING Name);
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN SafeUploadStageWritersIsTrackedWriter(_In_opt_ PFLT_INSTANCE Instance,
    _In_opt_ PFILE_OBJECT FileObject);
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN SafeUploadStageWritersBeginMutatingIo(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_opt_ PFLT_INSTANCE Instance,
    _In_opt_ PFILE_OBJECT FileObject, _Outptr_result_maybenull_ PVOID *CompletionContext,
    _Out_ PBOOLEAN TrackedWriter);
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN SafeUploadStageWritersBeginPagingIo(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_opt_ PFLT_INSTANCE Instance,
    _In_opt_ PFILE_OBJECT FileObject, _Outptr_result_maybenull_ PVOID *CompletionContext,
    _Out_ PBOOLEAN ExactSopTracked);
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID SafeUploadStageWritersSetMutatingIoCompletion(_In_opt_ PVOID CompletionContext,
    _In_ PFLT_CALLBACK_DATA Data, _In_ FLT_POST_OPERATION_FLAGS Flags);
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN SafeUploadStageWritersIsMutatingIoContext(_In_opt_ PVOID CompletionContext);
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID SafeUploadStageWritersEndMutatingIo(_In_opt_ PVOID CompletionContext);
LONG SafeUploadStageWritersObserverTicketsOutstanding(VOID);
_IRQL_requires_max_(APC_LEVEL)
VOID SafeUploadStageWritersAttachMutatingIo(_In_opt_ PVOID RenameContext,
    _Inout_ PVOID *MutatingIoContext);
/* Result of SafeUploadStageWritersSopOutsideWhy: why a stream is not known to be outside every scope. The low byte is the reason; for STATE,
 * CLASS and UNKNOWN the byte above it holds the entry's value. A refusal in the deny ring carries 0xE5000000 | value in its aux status. */
#define SAFEUPLOAD_SOP_OUTSIDE_KNOWN           0x00
#define SAFEUPLOAD_SOP_OUTSIDE_NO_OBJECT       0x01   /* no instance, file object or section-object pointer */
#define SAFEUPLOAD_SOP_OUTSIDE_NO_ENTRY        0x02   /* no registry entry for this stream: it was never seen opened for writing */
#define SAFEUPLOAD_SOP_OUTSIDE_RETIRED         0x03
#define SAFEUPLOAD_SOP_OUTSIDE_OTHER_INSTANCE  0x04
#define SAFEUPLOAD_SOP_OUTSIDE_OTHER_SOP       0x05
#define SAFEUPLOAD_SOP_OUTSIDE_STATE           0x06
#define SAFEUPLOAD_SOP_OUTSIDE_CLASS           0x07
#define SAFEUPLOAD_SOP_OUTSIDE_UNKNOWN         0x08
#define SAFEUPLOAD_SOP_OUTSIDE_ALIAS_PENDING   0x09
#define SAFEUPLOAD_SOP_OUTSIDE_SCAN_PENDING    0x0A
#define SAFEUPLOAD_SOP_OUTSIDE_RENAME          0x0B
#define SAFEUPLOAD_SOP_OUTSIDE_TRANSITION      0x0C   /* a scope that may grow the union is published and not yet applied */
_IRQL_requires_max_(APC_LEVEL)
ULONG SafeUploadStageWritersSopOutsideWhy(_In_ PFLT_INSTANCE Instance, _In_opt_ PFILE_OBJECT FileObject);
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN SafeUploadStageWritersSopKnownOutside(_In_ PFLT_INSTANCE Instance, _In_opt_ PFILE_OBJECT FileObject);
_IRQL_requires_max_(APC_LEVEL)
ULONG SafeUploadStageWritersAdmitNestedMutation(_In_ PFLT_INSTANCE Instance, _In_opt_ PFILE_OBJECT FileObject,
    _Outptr_result_maybenull_ PVOID *Context);
_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadStageWritersAwaitClassification(_In_ PFLT_INSTANCE Instance, _In_opt_ PFILE_OBJECT FileObject);
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN SafeUploadStageWritersSopMatchesPolicy(_In_ PFLT_INSTANCE Instance,
    _In_opt_ PFILE_OBJECT FileObject, _In_ BOOLEAN IncludeAncestors);
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStageWritersClassifyById(_In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject, _Out_ PBOOLEAN InScope);
_IRQL_requires_max_(APC_LEVEL)
VOID SafeUploadStageWritersMutationDraining(_In_ PFLT_INSTANCE Instance,
    _In_opt_ PVOID SectionObjectPointer);
NTSTATUS SafeUploadStageWritersActivatingStatusPage(_In_ UINT32 StartIndex,
    _Out_ PSAFEUPLOAD_ACTIVATING_STATUS_PAGE Page);
NTSTATUS SafeUploadStageWritersActivatingDiagnosticStatusPage(_In_ UINT32 StartIndex,
    _Out_ PSAFEUPLOAD_ACTIVATING_DIAGNOSTIC_STATUS_PAGE Page);
NTSTATUS SafeUploadStageWritersActivatingTargetStatus(_In_ PCUNICODE_STRING Name,
    _Out_ PSAFEUPLOAD_ACTIVATING_TARGET_STATUS Result);
NTSTATUS SafeUploadStageWritersAdmissionCoverage(_In_ UINT32 PolicyGeneration,
    _Out_ PULONGLONG RegistrySequenceStart, _Out_ PULONGLONG RegistrySequenceEnd,
    _Out_ PUINT32 WriterEntries, _Out_ PUINT32 WriterEntriesNotReady,
    _Out_ PUINT32 WriterEntriesUnknown, _Out_ PUINT32 GlobalUnknown);
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN SafeUploadStageWritersAdmissionCoverageCurrent(
    _Out_ PULONGLONG RegistrySequence, _Out_ PUINT32 GlobalUnknown);
UINT32 SafeUploadStageWritersSnapshot(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT FileObject);
/* C(F): writable CreateSections acquired and not yet released (observe-only). */
VOID SafeUploadStageWritersInitialize(VOID);
_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadStageWritersCloseAnchors(VOID);
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN SafeUploadStageWritersUnloadReady(VOID);
_IRQL_requires_max_(APC_LEVEL)
VOID SafeUploadStageWritersUninitialize(VOID);
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS SafeUploadStageSectionAcquired(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID *CompletionContext);
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID SafeUploadStageSectionAcquireFailed(_In_ PVOID CompletionContext);
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID SafeUploadStageSectionAcquireDraining(_In_opt_ PFLT_INSTANCE Instance,
    _In_opt_ PVOID CompletionContext);
_IRQL_requires_max_(APC_LEVEL)
VOID SafeUploadStageSectionReleasePrepare(_In_ PFLT_CALLBACK_DATA Data,
    _In_opt_ PFLT_INSTANCE Instance,
    _Outptr_result_maybenull_ PVOID *CompletionContext);
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID SafeUploadStageSectionReleaseComplete(_In_opt_ PFLT_INSTANCE Instance,
    _In_opt_ PVOID CompletionContext, _In_ BOOLEAN Succeeded, _In_ BOOLEAN Draining);
_IRQL_requires_max_(DISPATCH_LEVEL)
UINT32 SafeUploadStageSectionsInFlight(_In_opt_ PVOID SectionObjectPointer);
_IRQL_requires_max_(APC_LEVEL)
VOID SafeUploadStageWritersGetStatus(_Out_ PSAFEUPLOAD_WRITER_STATE_STATUS Status);
VOID SafeUploadStageWritersGetReclaimStats(_Out_ PUINT64 Passes, _Out_ PUINT64 ParkedPasses, _Out_ PUINT64 MoreWorkRequeues,
    _Out_ PUINT64 WakeupsSkipped);
NTSTATUS SafeUploadStageWritersPromotionTraceReadBatch(
    _In_ const SAFEUPLOAD_PROMOTION_TRACE_REQUEST *Request,
    _Out_ PSAFEUPLOAD_PROMOTION_TRACE_BATCH Batch);
NTSTATUS SafeUploadStageWritersRegistryEvaluate(_In_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING VolumeName, _In_ PCUNICODE_STRING NormalizedName,
    _In_ PFILE_OBJECT SourceObject,
    _Out_ PSAFEUPLOAD_REGISTRY_ENTRY_STATUS Status);
BOOLEAN SafeUploadStageWritersRegistrySnapshotByName(_In_ PFLT_INSTANCE Instance,
    _In_ PFLT_VOLUME Volume, _In_ PCUNICODE_STRING Name,
    _Out_ PSAFEUPLOAD_REGISTRY_ENTRY_STATUS Status);
VOID SafeUploadStageWritersSetCapacity(_In_ UINT32 Capacity);
VOID SafeUploadStageWritersRecordTxfRefused(VOID);
NTSTATUS SafeUploadStageTransactionNotification(_In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PFLT_CONTEXT TransactionContext, _In_ ULONG NotificationMask);
#endif

#endif
