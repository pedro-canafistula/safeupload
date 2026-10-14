#ifndef SAFEUPLOAD_STAGE_WRITER_METADATA_H
#define SAFEUPLOAD_STAGE_WRITER_METADATA_H
#include "StagePublic.h"
#include "StageBoundAllocation.h"
#if SAFEUPLOAD_STAGING_PROTOTYPE
#define SAFEUPLOAD_WRITER_METADATA_VERSION 27UL
#define SAFEUPLOAD_WRITER_METADATA_PAGE_BYTES 4096UL
#define SAFEUPLOAD_WRITER_METADATA_MAX_BYTES (1024UL + 2UL * 131228UL)
#define SAFEUPLOAD_WRITER_METADATA_DISCOVER 1UL
#define SAFEUPLOAD_WRITER_METADATA_READ 2UL
#define SAFEUPLOAD_WRITER_METADATA_CONFIRM 3UL
#define SAFEUPLOAD_WRITER_METADATA_CAPTURED 1UL
#define SAFEUPLOAD_WRITER_METADATA_UNAVAILABLE 2UL
#define SAFEUPLOAD_WRITER_METADATA_STALE 3UL
#define SAFEUPLOAD_WRITER_METADATA_NOT_READY 4UL
#define SAFEUPLOAD_WRITER_METADATA_CONSTRUCTION 1UL
#define SAFEUPLOAD_WRITER_METADATA_STORED 2UL
#define SAFEUPLOAD_WRITER_METADATA_ANCESTORS 4UL
#define SAFEUPLOAD_WRITER_METADATA_IDENTITY 8UL
#define SAFEUPLOAD_WRITER_METADATA_ASSIGNED 16UL
#pragma pack(push, 4)
typedef struct _SAFEUPLOAD_WRITER_METADATA_REQUEST {
    SAFEUPLOAD_CONTROL Control;
    UINT32 ExtensionVersion, Phase;
    GUID DriverInstanceId, ReservationId;
    UINT64 RequestId, ConnectionEpoch, AuthorityRevision;
    GUID SnapshotId;
    UINT32 Offset, Reserved;
    UCHAR Digest[32];
} SAFEUPLOAD_WRITER_METADATA_REQUEST, *PSAFEUPLOAD_WRITER_METADATA_REQUEST;
typedef struct _SAFEUPLOAD_WRITER_METADATA_HEADER {
    UINT32 ExtensionVersion, StructSize, Phase, Result;
    GUID DriverInstanceId, ReservationId;
    UINT64 RequestId, ConnectionEpoch, AuthorityRevision;
    GUID SnapshotId;
    UINT32 Offset, TotalBytes, Count, Flags;
    UCHAR Digest[32];
} SAFEUPLOAD_WRITER_METADATA_HEADER, *PSAFEUPLOAD_WRITER_METADATA_HEADER;
typedef struct _SAFEUPLOAD_WRITER_METADATA_PAGE {
    SAFEUPLOAD_WRITER_METADATA_HEADER Header;
    UCHAR Bytes[SAFEUPLOAD_WRITER_METADATA_PAGE_BYTES];
} SAFEUPLOAD_WRITER_METADATA_PAGE, *PSAFEUPLOAD_WRITER_METADATA_PAGE;
typedef struct _SAFEUPLOAD_WRITER_METADATA_FACTS {
    UINT32 Format, HeaderBytes;
    SAFEUPLOAD_STAGE_ALLOCATE_V23 Binding;
    WCHAR CanonicalLeaf[256];
    UINT32 ProcessId, SessionId;
    INT64 ProcessCreationTime;
    UINT32 ProcessSidBytes;
    UCHAR ProcessSid[68];
    UINT32 SubjectSidBytes;
    UCHAR SubjectSid[68];
    UINT32 DesiredAccess, OriginalDesiredAccess, RemainingDesiredAccess, PreviouslyGrantedAccess;
    UINT32 NativeGrantedAccess, StagedGrantedAccess, Options, Attributes, ShareAccess;
    UINT32 OperationFlags, RequestorMode, OriginalInformation;
    INT64 AllocationSize;
    UINT32 AncestorCount;
    UCHAR AncestorDigest[32];
    UINT32 AssignmentRevision, SecurityInformation, ConstructionBytes, StoredBytes;
    UINT32 SeedOrigin, ReadAuthority, ExportAuthority;
    INT32 ReadStatus, ExportStatus;
    GUID EffectiveSubjectId;
    UCHAR Reserved[76];
} SAFEUPLOAD_WRITER_METADATA_FACTS, *PSAFEUPLOAD_WRITER_METADATA_FACTS;
#pragma pack(pop)
C_ASSERT(sizeof(SAFEUPLOAD_WRITER_METADATA_REQUEST) == 136);
C_ASSERT(sizeof(SAFEUPLOAD_WRITER_METADATA_HEADER) == 136);
C_ASSERT(sizeof(SAFEUPLOAD_WRITER_METADATA_PAGE) == 4232);
C_ASSERT(sizeof(SAFEUPLOAD_WRITER_METADATA_FACTS) == 1024);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_WRITER_METADATA_REQUEST, SnapshotId) == 80);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_WRITER_METADATA_HEADER, Digest) == 104);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_WRITER_METADATA_FACTS, CanonicalLeaf) == 132);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_WRITER_METADATA_FACTS, AncestorDigest) == 864);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_WRITER_METADATA_FACTS, EffectiveSubjectId) == 932);

/* One immutable preparation per lease. No live caller until increment 4. */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStageWriterMetadataPrepare(_In_ PSAFEUPLOAD_STAGE_WRITER_LEASE Lease,
    _In_ const SAFEUPLOAD_STAGE_ALLOCATE_V23 *Binding, _In_ const GUID *DriverInstanceId,
    _In_ UINT64 RequestId, _Out_ PVOID *Cookie, _Out_ PUINT64 Revision,
    _Out_ SAFEUPLOAD_STAGE_WRITER_REFUSAL *Reason);
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStageWriterMetadataControl(_In_ PVOID PortCookie,
    _In_reads_bytes_(InputLength) PVOID Input, _In_ ULONG InputLength,
    _Out_writes_bytes_to_(OutputLength, *Returned) PVOID Output, _In_ ULONG OutputLength,
    _Out_ PULONG Returned);
#endif
#endif
