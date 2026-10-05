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
extern volatile LONG SafeUploadAdmissionTraceControlState;
extern volatile LONG SafeUploadAdmissionTraceSectionEvents;
BOOLEAN SafeUploadStageAdmissionTraceBegin(_In_ LONG TraceState);
VOID SafeUploadStageAdmissionTraceRecord(_In_ const SAFEUPLOAD_ADMISSION_TRACE_ENTRY *Entry);
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
NTSTATUS SafeUploadStageAdmissionVolumeStatus(_Out_ PSAFEUPLOAD_ADMISSION_VOLUME_STATUS Status);
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
VOID SafeUploadStageWritersTrackingLost(_In_opt_ PFLT_INSTANCE Instance, _In_ LONG Reason);
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
VOID SafeUploadStageWritersOnCleanup(_In_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects);
BOOLEAN SafeUploadStageWritersNameActivating(_In_ PFLT_INSTANCE Instance, _In_ PCUNICODE_STRING Name);
BOOLEAN SafeUploadStageWritersIsActivatingSop(_In_opt_ PVOID SectionObjectPointer);
BOOLEAN SafeUploadStageWritersSopMatchesPolicy(_In_opt_ PVOID SectionObjectPointer,
    _In_ BOOLEAN IncludeAncestors, _Out_ PBOOLEAN Known);
NTSTATUS SafeUploadStageWritersClassifyById(_In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject, _Out_ PBOOLEAN InScope);
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN SafeUploadStageWritersPagingWriteBegin(_In_ PFLT_INSTANCE Instance,
    _In_opt_ PVOID SectionObjectPointer,
    _Outptr_result_maybenull_ PVOID *CompletionContext);
VOID SafeUploadStageWritersPagingWriteEnd(_In_opt_ PVOID CompletionContext);
VOID SafeUploadStageWritersMutationDraining(_In_ PFLT_INSTANCE Instance,
    _In_opt_ PVOID SectionObjectPointer);
NTSTATUS SafeUploadStageWritersActivatingStatusPage(_In_ UINT32 StartIndex,
    _Out_ PSAFEUPLOAD_ACTIVATING_STATUS_PAGE Page);
UINT32 SafeUploadStageWritersSnapshot(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT FileObject);
/* C(F): writable CreateSections acquired and not yet released (observe-only). */
VOID SafeUploadStageWritersInitialize(VOID);
VOID SafeUploadStageWritersUninitialize(VOID);
NTSTATUS SafeUploadStageSectionAcquired(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID *CompletionContext);
VOID SafeUploadStageSectionAcquireFailed(_In_ PVOID CompletionContext);
VOID SafeUploadStageSectionAcquireDraining(_In_opt_ PFLT_INSTANCE Instance,
    _In_opt_ PVOID CompletionContext);
VOID SafeUploadStageSectionReleasePrepare(_In_ PFLT_CALLBACK_DATA Data,
    _Outptr_result_maybenull_ PVOID *CompletionContext);
VOID SafeUploadStageSectionReleaseComplete(_In_opt_ PFLT_INSTANCE Instance,
    _In_opt_ PVOID CompletionContext, _In_ BOOLEAN Succeeded, _In_ BOOLEAN Draining);
UINT32 SafeUploadStageSectionsInFlight(_In_opt_ PVOID SectionObjectPointer);
VOID SafeUploadStageWritersGetStatus(_Out_ PSAFEUPLOAD_WRITER_STATE_STATUS Status);
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
