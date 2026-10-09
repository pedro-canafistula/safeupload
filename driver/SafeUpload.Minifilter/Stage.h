#ifndef SAFEUPLOAD_STAGE_H
#define SAFEUPLOAD_STAGE_H

#include "Filter.h"

NTSTATUS SafeUploadStageInitialize(VOID);
NTSTATUS SafeUploadStageStartWorker(VOID);
VOID SafeUploadStageStopWorker(VOID);
NTSTATUS SafeUploadStagePrepareUnload(VOID);
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
BOOLEAN SafeUploadStageProtectedName(_In_ PFLT_FILE_NAME_INFORMATION Name, _In_ SAFEUPLOAD_VOLUME_KIND Kind);
BOOLEAN SafeUploadStageTouchesProtectedNamespace(_In_ PFLT_FILE_NAME_INFORMATION Name, _In_ SAFEUPLOAD_VOLUME_KIND Kind);
BOOLEAN SafeUploadStageProtectedPath(_In_ PUNICODE_STRING Name, _In_ USHORT VolumeLength, _In_ SAFEUPLOAD_VOLUME_KIND Kind);
NTSTATUS SafeUploadStageCheckNamedAliases(_In_ PFLT_INSTANCE Instance, _In_ PFLT_FILE_NAME_INFORMATION Name,
    _In_ SAFEUPLOAD_VOLUME_KIND Kind, _Out_ PBOOLEAN Protected);
NTSTATUS SafeUploadStageCheckObjectAliases(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT Object,
    _In_ PUNICODE_STRING Volume, _In_ SAFEUPLOAD_VOLUME_KIND Kind, _Out_ PBOOLEAN Protected);
BOOLEAN SafeUploadPublicationCreate(_In_ PUNICODE_STRING Name, _In_ ULONG Disposition, _In_ BOOLEAN Writer);
BOOLEAN SafeUploadPublicationRename(_In_ PFLT_VOLUME TargetVolume, _In_ PUNICODE_STRING Source,
    _In_ PUNICODE_STRING Destination, _Out_ PBOOLEAN QuarantineRefused);
NTSTATUS SafeUploadStageAllocate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PUNICODE_STRING OriginalName,
    _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind, _In_opt_ PUNICODE_STRING PreviousStageName,
    _In_opt_ PUNICODE_STRING TombstoneStageName,
    _Out_writes_(SAFEUPLOAD_MAX_STAGE_NAME_CHARS) PWCH StageName, _Out_ PUSHORT StageNameLength);
NTSTATUS SafeUploadStageSeal(_In_ ULONG ProcessId, _In_ PUNICODE_STRING StageName);
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
/* DenyRing.c: always-on record of operations completed with an error status. */
VOID SafeUploadDenyRingInitialize(VOID);
VOID SafeUploadDenySiteHint(_In_ PFLT_CALLBACK_DATA Data, _In_ PVOID Site);
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

/* StageWriters.c: bounded writer-history ledger and activation state. */
#define SAFEUPLOAD_WRITERS_ONLY_CONTEXT ((PVOID)(ULONG_PTR)0x1000)
BOOLEAN SafeUploadStageWritersWantPostCreate(_In_ PFLT_CALLBACK_DATA Data);
NTSTATUS SafeUploadStageWritersReserveCreate(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects, _Outptr_result_maybenull_ PVOID *Reservation,
    _Out_ PBOOLEAN Required);
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
VOID SafeUploadStageWritersGetReclaimStats(_Out_ PUINT64 Passes, _Out_ PUINT64 ParkedPasses, _Out_ PUINT64 MoreWorkRequeues);
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
