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
BOOLEAN SafeUploadPublicationCreate(_In_ PUNICODE_STRING Name, _In_ ULONG Disposition, _In_ BOOLEAN Writer);
BOOLEAN SafeUploadPublicationRename(_In_ PUNICODE_STRING Source, _In_ PUNICODE_STRING Destination);
NTSTATUS SafeUploadStageAllocate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PUNICODE_STRING OriginalName,
    _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind, _In_opt_ PUNICODE_STRING PreviousStageName,
    _Out_writes_(SAFEUPLOAD_MAX_STAGE_NAME_CHARS) PWCH StageName, _Out_ PUSHORT StageNameLength);
NTSTATUS SafeUploadStageSeal(_In_ ULONG ProcessId, _In_ PUNICODE_STRING StageName);

#endif
