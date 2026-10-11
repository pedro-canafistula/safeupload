#ifndef SAFEUPLOAD_STAGE_PUBLIC_H
#define SAFEUPLOAD_STAGE_PUBLIC_H
#include "Filter.h"

#if SAFEUPLOAD_STAGING_PROTOTYPE
typedef struct _SAFEUPLOAD_STAGE_PUBLIC_BACKEND SAFEUPLOAD_STAGE_PUBLIC_BACKEND,
    *PSAFEUPLOAD_STAGE_PUBLIC_BACKEND;

/* Kernel-only binding. It grants no service permit and changes no wire ABI. */
typedef struct _SAFEUPLOAD_STAGE_PUBLIC_BINDING {
    ACCESS_MASK OriginalDesiredAccess;
    ACCESS_MASK GrantedAccess;
    ULONG OriginalShareAccess;
    BOOLEAN ParentCaseSensitive;
    FILE_ID_INFORMATION VolumeRootIdentity;
    FILE_ID_INFORMATION ParentIdentity;
    FILE_ID_INFORMATION PublicIdentity;
    USHORT CanonicalLeafBytes;
    WCHAR CanonicalLeaf[256];
} SAFEUPLOAD_STAGE_PUBLIC_BINDING, *PSAFEUPLOAD_STAGE_PUBLIC_BINDING;

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStagePublicCaptureSubject(_In_ PFLT_CALLBACK_DATA Data,
    _Out_ PSECURITY_CLIENT_CONTEXT Subject);

/* Runs on an unimpersonated system worker, outside namespace/stream/spin
 * locks. Capture Subject in the original CREATE before queueing. NTFS checks
 * the full original path with that subject before metadata anchors are opened;
 * relative metadata opens cannot bypass the caller's traversal checks. */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStagePublicOpenBackend(_In_ PFLT_INSTANCE Instance,
    _In_ PUNICODE_STRING PublicName, _In_ PSECURITY_CLIENT_CONTEXT Subject,
    _In_ ACCESS_MASK OriginalDesiredAccess, _In_ ULONG OriginalShareAccess,
    _In_ ULONG OriginalCreateOptions, _In_ BOOLEAN CaseSensitiveOpen,
    _Outptr_result_nullonfailure_ PSAFEUPLOAD_STAGE_PUBLIC_BACKEND *Backend);

/* The caller already owns a reference or protects an owned pointer under its
 * own lock. An operation owns an additional reference until ReleaseOperation. */
VOID SafeUploadStagePublicReferenceBackend(_In_ PSAFEUPLOAD_STAGE_PUBLIC_BACKEND Backend);
_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadStagePublicDereferenceBackend(_In_opt_ PSAFEUPLOAD_STAGE_PUBLIC_BACKEND Backend);
_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadStagePublicCloseBackend(_In_ PSAFEUPLOAD_STAGE_PUBLIC_BACKEND Backend);
BOOLEAN SafeUploadStagePublicAcquireOperation(_In_ PSAFEUPLOAD_STAGE_PUBLIC_BACKEND Backend,
    _Out_ PFLT_INSTANCE *Instance, _Out_ PFILE_OBJECT *FileObject);
_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadStagePublicReleaseOperation(_In_ PSAFEUPLOAD_STAGE_PUBLIC_BACKEND Backend);
VOID SafeUploadStagePublicGetBinding(_In_ PSAFEUPLOAD_STAGE_PUBLIC_BACKEND Backend,
    _Out_ PSAFEUPLOAD_STAGE_PUBLIC_BINDING Binding);
LONG SafeUploadStagePublicBackendCount(VOID);
#endif
#endif
