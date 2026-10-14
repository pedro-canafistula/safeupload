#ifndef SAFEUPLOAD_BOUND_PUBLICATION_INTERNAL_H
#define SAFEUPLOAD_BOUND_PUBLICATION_INTERNAL_H
#include "Filter.h"
#include "StageBoundPublication.h"
#if SAFEUPLOAD_STAGING_PROTOTYPE
/* Kernel-only ownership, never part of V18/V23/V26. Acquisition holds the
 * original version until ReleaseSource; directory references are metadata
 * locators, never caller authority. No temporary-file handle is owned here. */
typedef struct _SAFEUPLOAD_PUBLICATION_SOURCE {
    PVOID Version;
    PVOID Writer;
    PFLT_INSTANCE Instance;
    PFILE_OBJECT Root, Parent;
    PSECURITY_DESCRIPTOR Construction, Stored;
    ULONG ConstructionBytes, StoredBytes, SectorSize;
} SAFEUPLOAD_PUBLICATION_SOURCE, *PSAFEUPLOAD_PUBLICATION_SOURCE;

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStagePublicationAcquireSource(_In_ const SAFEUPLOAD_BOUND_PUBLICATION_REQUEST *Request,
    _Out_ PSAFEUPLOAD_PUBLICATION_SOURCE Source);
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN SafeUploadStagePublicationSourceCurrent(_In_ const SAFEUPLOAD_BOUND_PUBLICATION_REQUEST *Request,
    _In_ const SAFEUPLOAD_PUBLICATION_SOURCE *Source);
_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadStagePublicationReleaseSource(_Inout_ PSAFEUPLOAD_PUBLICATION_SOURCE Source);
_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadStagePublicCloseWriterEvidence(_In_ PVOID Writer);
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN SafeUploadStagePublicPublicationCurrent(_In_ PVOID Writer);
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN SafeUploadStagePublicPublicationBeginObservation(_In_ PVOID Writer);
_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadStagePublicPublicationEndObservation(_In_ PVOID Writer);
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStagePublicPublicationSecurity(_In_ PVOID Writer,
    _In_ const SAFEUPLOAD_BOUND_PUBLICATION_REQUEST *Request,
    _Inout_ PSAFEUPLOAD_PUBLICATION_SOURCE Source);

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadBoundPublicationInitialize(_In_ const GUID *Driver, _In_ ULONG Boot);
_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadBoundPublicationUninitialize(VOID);
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadBoundPublicationControl(_In_opt_ PVOID Cookie,
    _In_reads_bytes_(InputLength) PVOID Input, _In_ ULONG InputLength,
    _Out_writes_bytes_to_(OutputLength, *Returned) PVOID Output, _In_ ULONG OutputLength,
    _Out_ PULONG Returned);
_IRQL_requires_max_(APC_LEVEL)
FLT_PREOP_CALLBACK_STATUS SafeUploadBoundPublicationPre(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _Outptr_result_maybenull_ PVOID *Context,
    _Out_ PBOOLEAN Handled);
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN SafeUploadBoundPublicationPost(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _In_opt_ PVOID Context,
    _In_ FLT_POST_OPERATION_FLAGS Flags);
_IRQL_requires_max_(APC_LEVEL)
VOID SafeUploadBoundPublicationRevokeConnection(_In_ PVOID Cookie);
_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadBoundPublicationInstanceTeardown(_In_ PFLT_INSTANCE Instance,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason);
/* NativeLock -> publication lock. A conservative instance exclusion also
 * covers a pending native DELETE and its delayed cleanup. */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN SafeUploadBoundPublicationNamespaceAvailable(_In_ PFLT_INSTANCE Instance);
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID SafeUploadBoundPublicationNamespaceCoverageLost(VOID);
BOOLEAN SafeUploadBoundPublicationTryCloseAdmission(VOID);
VOID SafeUploadBoundPublicationReopenAdmission(VOID);
VOID SafeUploadBoundPublicationCloseAdmission(VOID);
_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadBoundPublicationDrainLocal(VOID);
#endif
#endif
