#ifndef SAFEUPLOAD_STAGE_H
#define SAFEUPLOAD_STAGE_H

#include "Filter.h"

NTSTATUS SafeUploadStageInitialize(VOID);
NTSTATUS SafeUploadStageStartWorker(VOID);
VOID SafeUploadStageStopWorker(VOID);
NTSTATUS SafeUploadStagePrepareUnload(VOID);
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
#endif

#endif
