#ifndef SAFEUPLOAD_STAGE_NATIVE_WIRE_H
#define SAFEUPLOAD_STAGE_NATIVE_WIRE_H
#include "Protocol.h"

#if defined(SAFEUPLOAD_STAGING_PROTOTYPE) && SAFEUPLOAD_STAGING_PROTOTYPE
/* Separate feature-only ABI. Existing v18 controls and v20 stage layouts
 * remain unchanged; this new payload has its own checked version. */
#define SAFEUPLOAD_CONTROL_NATIVE_RECORD_REPLAY ((UINT32) 30)
#define SAFEUPLOAD_CONTROL_NATIVE_NAME_OBSERVATION ((UINT32) 31)
#define SAFEUPLOAD_NATIVE_REPLAY_VERSION ((UINT32) 22) /* v21 lacked exact Mount Manager identity; never infer it. */
#define SAFEUPLOAD_NATIVE_REPLAY_PAGE_ROWS ((UINT32) 16)
#define SAFEUPLOAD_NATIVE_REPLAY_MAX_RECORDS ((UINT32) 1024)
#define SAFEUPLOAD_NATIVE_REPLAY_SID_BYTES ((UINT32) 68)
#define SAFEUPLOAD_NATIVE_REPLAY_LEAF_CHARS ((UINT32) 256)

#define SAFEUPLOAD_NATIVE_FORWARDED ((UINT32) 0x01)
#define SAFEUPLOAD_NATIVE_CREATE_KNOWN ((UINT32) 0x02)
#define SAFEUPLOAD_NATIVE_CREATE_ACCEPTED ((UINT32) 0x04)
#define SAFEUPLOAD_NATIVE_IDENTITY_CHECKED ((UINT32) 0x08)
#define SAFEUPLOAD_NATIVE_LAST_CLEANUP ((UINT32) 0x10)
#define SAFEUPLOAD_NATIVE_CANCEL_BEFORE_HANDLE ((UINT32) 0x20)
#define SAFEUPLOAD_NATIVE_CANCEL_CLOSE ((UINT32) 0x40)
#define SAFEUPLOAD_NATIVE_COVERAGE_LOST ((UINT32) 0x80)

/* Kernel -> service lifecycle requests. No path, token, handle or mutation
 * authority is carried: the service reads the exact authenticated map. */
#define SAFEUPLOAD_OPERATION_NATIVE_LIFECYCLE ((UINT32) 20)
#define SAFEUPLOAD_NATIVE_LIFECYCLE_VERSION ((UINT32) 24)
#define SAFEUPLOAD_NATIVE_PREPARE ((UINT32) 1)
#define SAFEUPLOAD_NATIVE_FACTS_CHANGED ((UINT32) 2)
#define SAFEUPLOAD_NATIVE_PREPARED ((UINT32) 1)
#define SAFEUPLOAD_NATIVE_PROGRESS ((UINT32) 2)
#define SAFEUPLOAD_NATIVE_TERMINAL ((UINT32) 3)
#pragma pack(push, 4)
typedef struct _SAFEUPLOAD_NATIVE_LIFECYCLE {
    UINT32 Version;
    UINT32 StructSize;
    UINT32 Phase;
    UINT32 Reserved;
    GUID TransferId;
    GUID RequestNonce;
    GUID OperationId;
    UINT64 NativeMapRevision;
} SAFEUPLOAD_NATIVE_LIFECYCLE, *PSAFEUPLOAD_NATIVE_LIFECYCLE;
typedef struct _SAFEUPLOAD_NATIVE_LIFECYCLE_REPLY {
    SAFEUPLOAD_NATIVE_LIFECYCLE Request;
    UINT64 JournalGeneration;
    UINT32 Result;
    UINT32 Reserved;
} SAFEUPLOAD_NATIVE_LIFECYCLE_REPLY, *PSAFEUPLOAD_NATIVE_LIFECYCLE_REPLY;
#pragma pack(pop)
C_ASSERT(sizeof(SAFEUPLOAD_NATIVE_LIFECYCLE) == 72);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_NATIVE_LIFECYCLE, TransferId) == 16);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_NATIVE_LIFECYCLE, NativeMapRevision) == 64);
C_ASSERT(sizeof(SAFEUPLOAD_NATIVE_LIFECYCLE_REPLY) == 88);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_NATIVE_LIFECYCLE_REPLY, JournalGeneration) == 72);

typedef struct _SAFEUPLOAD_NATIVE_REPLAY_REQUEST {
    SAFEUPLOAD_CONTROL Control;
    UINT32 ExtensionVersion;
    UINT32 StartIndex;
    GUID ExpectedDriverInstanceId;
    UINT64 ExpectedConnectionEpoch;
    UINT64 ExpectedRevision;
    UINT64 Reserved;
} SAFEUPLOAD_NATIVE_REPLAY_REQUEST, *PSAFEUPLOAD_NATIVE_REPLAY_REQUEST;

/* Explicit-width facts only. No kernel addresses, BOOLEANs, implicit
 * padding, handles, access tokens or deletion authority cross this ABI. */
typedef struct _SAFEUPLOAD_NATIVE_REPLAY_ROW {
    GUID DriverInstanceId;
    GUID TransferId;
    GUID RequestNonce;
    GUID OperationId;
    UINT64 OriginalConnectionEpoch;
    UINT64 JournalGeneration;
    INT64 CallerProcessCreationTime;
    SAFEUPLOAD_STAGE_IDENTITY_V19 VolumeRootIdentity;
    SAFEUPLOAD_STAGE_IDENTITY_V19 ParentIdentity;
    SAFEUPLOAD_STAGE_IDENTITY_V19 PublicIdentity;
    UINT32 OsBootSequence;
    UINT32 CreateOptions;
    UINT32 OriginalDesiredAccess;
    UINT32 OriginalShareAccess;
    UINT32 CallerProcessId;
    UINT32 CallerSessionId;
    UINT32 CallerSidBytes;
    UINT32 ParentCaseSensitive;
    UINT32 CanonicalLeafBytes;
    UINT32 Flags;
    INT32 CreateStatus;
    INT32 IdentityStatus;
    UINT32 TeardownReason;
    UINT32 Reserved;
    UCHAR CallerSid[SAFEUPLOAD_NATIVE_REPLAY_SID_BYTES];
    WCHAR CanonicalLeaf[SAFEUPLOAD_NATIVE_REPLAY_LEAF_CHARS];
    UINT32 ReservedEnd;
    GUID MountManagerVolumeId;
} SAFEUPLOAD_NATIVE_REPLAY_ROW, *PSAFEUPLOAD_NATIVE_REPLAY_ROW;

typedef struct _SAFEUPLOAD_NATIVE_REPLAY_PAGE {
    UINT32 ExtensionVersion;
    UINT32 StructSize;
    GUID DriverInstanceId;
    UINT64 ConnectionEpoch;
    UINT64 Revision;
    UINT32 OsBootSequence;
    UINT32 StartIndex;
    UINT32 Count;
    UINT32 Complete;
    UINT64 Reserved;
    SAFEUPLOAD_NATIVE_REPLAY_ROW Rows[SAFEUPLOAD_NATIVE_REPLAY_PAGE_ROWS];
} SAFEUPLOAD_NATIVE_REPLAY_PAGE, *PSAFEUPLOAD_NATIVE_REPLAY_PAGE;

C_ASSERT(sizeof(SAFEUPLOAD_NATIVE_REPLAY_REQUEST) == 64);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_NATIVE_REPLAY_REQUEST, ExpectedConnectionEpoch) == 40);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_NATIVE_REPLAY_REQUEST, ExpectedRevision) == 48);
C_ASSERT(sizeof(SAFEUPLOAD_NATIVE_REPLAY_ROW) == 816);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_NATIVE_REPLAY_ROW, VolumeRootIdentity) == 88);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_NATIVE_REPLAY_ROW, Flags) == 196);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_NATIVE_REPLAY_ROW, CallerSid) == 216);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_NATIVE_REPLAY_ROW, CanonicalLeaf) == 284);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_NATIVE_REPLAY_ROW, ReservedEnd) == 796);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_NATIVE_REPLAY_ROW, MountManagerVolumeId) == 800);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_NATIVE_REPLAY_PAGE, Rows) == 64);
C_ASSERT(sizeof(SAFEUPLOAD_NATIVE_REPLAY_PAGE) == 13120);

/* Read-only, momentary name mapping. Two complete scans are not an unlink
 * receipt, a DELETE grant, or permission to release a durable hold. */
typedef struct _SAFEUPLOAD_NATIVE_NAME_REQUEST {
    SAFEUPLOAD_CONTROL Control;
    UINT32 ExtensionVersion;
    UINT32 OsBootSequence;
    GUID ExpectedDriverInstanceId;
    UINT64 ExpectedConnectionEpoch;
    UINT64 ExpectedRevision;
    GUID MountManagerVolumeId;
    SAFEUPLOAD_STAGE_IDENTITY_V19 VolumeRootIdentity;
    SAFEUPLOAD_STAGE_IDENTITY_V19 ParentIdentity;
    UINT32 ParentCaseSensitive;
    UINT32 CanonicalLeafBytes;
    WCHAR CanonicalLeaf[SAFEUPLOAD_NATIVE_REPLAY_LEAF_CHARS];
} SAFEUPLOAD_NATIVE_NAME_REQUEST, *PSAFEUPLOAD_NATIVE_NAME_REQUEST;

typedef struct _SAFEUPLOAD_NATIVE_NAME_REPLY {
    UINT32 ExtensionVersion;
    UINT32 StructSize;
    GUID DriverInstanceId;
    UINT64 ConnectionEpoch;
    UINT64 Revision;
    UINT32 OsBootSequence;
    UINT32 CompleteScans;
    GUID MountManagerVolumeId;
    SAFEUPLOAD_STAGE_IDENTITY_V19 VolumeRootIdentity;
    SAFEUPLOAD_STAGE_IDENTITY_V19 ParentIdentity;
    UINT32 ParentCaseSensitive;
    UINT32 CanonicalLeafBytes;
    WCHAR CanonicalLeaf[SAFEUPLOAD_NATIVE_REPLAY_LEAF_CHARS];
    UINT32 Present;
    UINT32 Reserved;
    SAFEUPLOAD_STAGE_IDENTITY_V19 ChildIdentity;
} SAFEUPLOAD_NATIVE_NAME_REPLY, *PSAFEUPLOAD_NATIVE_NAME_REPLY;

C_ASSERT(sizeof(SAFEUPLOAD_NATIVE_NAME_REQUEST) == 640);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_NATIVE_NAME_REQUEST, CanonicalLeaf) == 128);
C_ASSERT(sizeof(SAFEUPLOAD_NATIVE_NAME_REPLY) == 664);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_NATIVE_NAME_REPLY, CanonicalLeaf) == 120);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_NATIVE_NAME_REPLY, ChildIdentity) == 640);

#endif
#endif
