#ifndef SAFEUPLOAD_STAGE_PUBLIC_H
#define SAFEUPLOAD_STAGE_PUBLIC_H
#include "Filter.h"

#if SAFEUPLOAD_STAGING_PROTOTYPE
typedef struct _SAFEUPLOAD_STAGE_PUBLIC_BACKEND SAFEUPLOAD_STAGE_PUBLIC_BACKEND,
    *PSAFEUPLOAD_STAGE_PUBLIC_BACKEND;
typedef struct _SAFEUPLOAD_STAGE_WRITER_LEASE SAFEUPLOAD_STAGE_WRITER_LEASE,
    *PSAFEUPLOAD_STAGE_WRITER_LEASE;
/* Kernel diagnostics only; do not append these to a published wire layout. */
typedef enum _SAFEUPLOAD_STAGE_WRITER_REFUSAL {
    StageWriterNoRefusal = 0,
    StageWriterSubjectUnrepresentable,
    StageWriterNativeCreateSecurityUnproved,
    StageWriterPublicationSecurityNotEquivalent,
    StageWriterCreatorGrantUnproved,
    StageWriterCreateSemanticsUnproved,
    StageWriterLookupUnproved,
    StageWriterMetadataUnproved,
    StageWriterSnapshotChanged,
    StageWriterCaptureLimit,
    StageWriterMetadataBindingMismatch,
    StageWriterMetadataStale,
    StageWriterMetadataResourceLimit,
    StageWriterMetadataReplayUnbound,
    StageWriterSeedCoherenceUnproved,
    StageWriterSeedCompletionUnproved,
    StageWriterSeedIoFailed,
    StageWriterRefusalCount
} SAFEUPLOAD_STAGE_WRITER_REFUSAL;
#define SAFEUPLOAD_STAGE_CREATE_EA_LIMIT 65536UL
#define SAFEUPLOAD_STAGE_CREATE_SECURITY_LIMIT 131228UL
/* Immutable original CREATE inputs owned by the attach transaction. Capturing
 * these is not authorization. EA/security storage is released by that owner. */
typedef struct _SAFEUPLOAD_STAGE_CREATE_INPUT {
    ACCESS_MASK DesiredAccess;
    ACCESS_MASK OriginalDesiredAccess;
    ACCESS_MASK RemainingDesiredAccess;
    ACCESS_MASK PreviouslyGrantedAccess;
    ULONG Options;
    USHORT FileAttributes;
    USHORT ShareAccess;
    LARGE_INTEGER AllocationSize;
    UCHAR OperationFlags;
    KPROCESSOR_MODE RequestorMode;
    BOOLEAN NativeEligible;
    BOOLEAN SuppliedSecurity;
    ULONG EaLength;
    PVOID EaBuffer;
    ULONG SecurityBytes;
    PSECURITY_DESCRIPTOR Security;
    UNICODE_STRING LookupName; /* Opened absolute form, or unchanged relative/raw ID form. */
    PFILE_OBJECT LookupRoot; /* Referenced original RelatedFileObject, never a name reconstruction. */
    HANDLE LookupRootHandle; /* Internal locator only, captured before the original root can clean up. */
    BOOLEAN LookupById;
} SAFEUPLOAD_STAGE_CREATE_INPUT, *PSAFEUPLOAD_STAGE_CREATE_INPUT;

/* Kernel-only binding. It grants no service permit and changes no wire ABI. */
typedef struct _SAFEUPLOAD_STAGE_PUBLIC_BINDING {
    ACCESS_MASK OriginalDesiredAccess;
    ACCESS_MASK GrantedAccess;
    ULONG OriginalShareAccess;
    ULONG CallerProcessId;
    LONGLONG CallerProcessCreationTime;
    ULONG CallerSessionId;
    ULONG CallerSidBytes;
    UCHAR CallerSid[SECURITY_MAX_SID_SIZE];
    BOOLEAN ParentCaseSensitive;
    FILE_ID_INFORMATION VolumeRootIdentity;
    GUID MountManagerVolumeId; /* Distinguishes a sector clone with identical filesystem IDs. */
    FILE_ID_INFORMATION ParentIdentity;
    FILE_ID_INFORMATION PublicIdentity;
    USHORT CanonicalLeafBytes;
    WCHAR CanonicalLeaf[256];
} SAFEUPLOAD_STAGE_PUBLIC_BINDING, *PSAFEUPLOAD_STAGE_PUBLIC_BINDING;

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStagePublicCaptureSubject(_In_ PFLT_CALLBACK_DATA Data,
    _Out_ PSECURITY_CLIENT_CONTEXT Subject);
/* Metadata identity only: retain the actual token level. Never impersonate
 * this copy or promote it; the unchanged original CREATE performs access checks. */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStagePublicCaptureNativeSubject(_In_ PFLT_CALLBACK_DATA Data,
    _Out_ PSECURITY_CLIENT_CONTEXT Subject);
/* Retain the actual static subject for a later caller-checked probe. This
 * copy grants no authority and must never be promoted to a stronger level. */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStagePublicCaptureCreateSubject(_In_ PFLT_CALLBACK_DATA Data,
    _Out_ PSECURITY_CLIENT_CONTEXT Subject);
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStagePublicCaptureCreateLookup(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _Inout_ PSAFEUPLOAD_STAGE_CREATE_INPUT Input);
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID SafeUploadStagePublicFreeCreateLookup(_Inout_ PSAFEUPLOAD_STAGE_CREATE_INPUT Input);
_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadStagePublicCloseCreateLookup(_Inout_ PSAFEUPLOAD_STAGE_CREATE_INPUT Input);

/* Preparation only, NOT permission to allocate/expose/publish. No live CREATE
 * calls this factory in increment 2. The caller owns the returned lease until
 * ReleaseWriter; future independent CREATEs need independent leases. */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStagePublicOpenWriter(_In_ PFLT_INSTANCE Instance,
    _In_ const SAFEUPLOAD_STAGE_CREATE_INPUT *Input, _In_ PSECURITY_CLIENT_CONTEXT Subject,
    _In_ PEPROCESS OriginalRequestorProcess,
    _Outptr_result_nullonfailure_ PSAFEUPLOAD_STAGE_WRITER_LEASE *Lease,
    _Out_ SAFEUPLOAD_STAGE_WRITER_REFUSAL *Reason);
_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadStagePublicReleaseWriter(_In_opt_ PSAFEUPLOAD_STAGE_WRITER_LEASE Lease);
/* Outside namespace/stream locks after RPC. Caller must additionally validate
 * reservation/predecessor/policy/channel/cancellation under its own lock. */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStagePublicRevalidateWriter(_In_ PSAFEUPLOAD_STAGE_WRITER_LEASE Lease,
    _Out_ SAFEUPLOAD_STAGE_WRITER_REFUSAL *Reason);
/* Always refuses in this increment: construction/creator/round-trip mechanisms
 * have no qualified producer. Never derive construction from queried security. */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStagePublicCheckWriterSecurity(_In_ PSAFEUPLOAD_STAGE_WRITER_LEASE Lease,
    _Out_ SAFEUPLOAD_STAGE_WRITER_REFUSAL *Reason);
VOID SafeUploadStagePublicGetWriterBinding(_In_ PSAFEUPLOAD_STAGE_WRITER_LEASE Lease,
    _Out_ PSAFEUPLOAD_STAGE_PUBLIC_BINDING Binding);
/* Local completion only: immutable allocation metadata is never overwritten.
 * No wire layout changes. Durable service confirmation is a separate gate. */
typedef struct _SAFEUPLOAD_STAGE_SEED_COMPLETION {
    GUID ReceiptId, DriverInstanceId, TransferId, SnapshotId, ParentTransferId;
    SAFEUPLOAD_STAGE_IDENTITY_V19 StageIdentity, PredecessorIdentity;
    UINT64 PredecessorGeneration;
    UINT64 Generation, RequestId, ConnectionEpoch, AuthorityRevision;
    UCHAR MetadataDigest[32];
    LONGLONG Length;
    ULONG Origin;
    BOOLEAN Complete;
} SAFEUPLOAD_STAGE_SEED_COMPLETION, *PSAFEUPLOAD_STAGE_SEED_COMPLETION;
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStagePublicWriterMetadataCurrent(_In_ PSAFEUPLOAD_STAGE_WRITER_LEASE Lease,
    _Out_ SAFEUPLOAD_STAGE_WRITER_REFUSAL *Reason);
/* Reuses only the original metadata owner/request/channel for lost replies. */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStagePublicWriterReplayIdentity(_In_ PSAFEUPLOAD_STAGE_WRITER_LEASE Lease,
    _In_ const SAFEUPLOAD_REQUEST *Request, _Out_ PVOID *Cookie, _Out_ PUINT64 Revision);
/* Caller owns the exclusive checked backing and attach transaction. No locks
 * across this call. Failure zeroes Completion; partial output stays private. */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStagePublicSeedWriter(_In_ PSAFEUPLOAD_STAGE_WRITER_LEASE Lease,
    _In_ PFLT_INSTANCE BackingInstance, _In_ PFILE_OBJECT BackingObject,
    _In_ ULONG BackingSectorSize, _In_ const SAFEUPLOAD_STAGE_IDENTITY_V19 *Identity,
    _In_ UINT64 Generation, _In_ PFLT_CALLBACK_DATA Data,
    _Out_ PSAFEUPLOAD_STAGE_SEED_COMPLETION Completion,
    _Out_ SAFEUPLOAD_STAGE_WRITER_REFUSAL *Reason);
VOID SafeUploadStagePublicRecordWriterRefusal(_In_ SAFEUPLOAD_STAGE_WRITER_REFUSAL Reason);
LONG64 SafeUploadStagePublicWriterRefusalCount(_In_ SAFEUPLOAD_STAGE_WRITER_REFUSAL Reason);
PCSTR SafeUploadStagePublicWriterRefusalName(_In_ SAFEUPLOAD_STAGE_WRITER_REFUSAL Reason);

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStagePublicReadMountGuid(_In_ PFLT_INSTANCE Instance, _Out_ GUID *VolumeId);

/* Metadata-only preparation for the ORIGINAL native scheduled CREATE. No
 * child file open, DELETE grant, disposition, or service permit is produced.
 * Subject was captured before queueing; Name is the parsed normalized name.
 * The original NTFS CREATE must independently establish the actual grant. */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStagePublicCaptureNativeName(_In_ PFLT_INSTANCE Instance,
    _In_ PFLT_FILE_NAME_INFORMATION Name, _In_ PSECURITY_CLIENT_CONTEXT Subject,
    _In_ PEPROCESS OriginalRequestorProcess, _In_ ACCESS_MASK OriginalDesiredAccess,
    _In_ ULONG OriginalShareAccess, _In_ ULONG OriginalCreateOptions,
    _Out_ PSAFEUPLOAD_STAGE_PUBLIC_BINDING Binding);

/* Runs on an unimpersonated system worker, outside namespace/stream/spin
 * locks. Capture Subject in the original CREATE before queueing. NTFS checks
 * the full original path with that subject before metadata anchors are opened;
 * relative metadata opens cannot bypass the caller's traversal checks. */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStagePublicOpenBackend(_In_ PFLT_INSTANCE Instance,
    _In_ PUNICODE_STRING PublicName, _In_ PSECURITY_CLIENT_CONTEXT Subject,
    _In_ PEPROCESS OriginalRequestorProcess,
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
BOOLEAN SafeUploadStagePublicTryCloseAdmission(VOID);
VOID SafeUploadStagePublicReopenAdmission(VOID);
VOID SafeUploadStagePublicInitialize(VOID);
_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadStagePublicCloseAllBackends(VOID);
_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadStagePublicDrainBackends(VOID);
#endif
#endif
