#ifndef SAFEUPLOAD_STAGE_PUBLIC_RELAY_H
#define SAFEUPLOAD_STAGE_PUBLIC_RELAY_H
#include "StageNativeWire.h"

#if SAFEUPLOAD_STAGING_PROTOTYPE
/* A separate ABI for ordinary opens/dispositions. V22/V24 scheduled-CREATE
 * parsing remains strict and cannot interpret an ordinary open as a delete. */
#define SAFEUPLOAD_CONTROL_PUBLIC_OPEN_REPLAY ((UINT32)32)
#define SAFEUPLOAD_OPERATION_PUBLIC_DISPOSITION ((UINT32)21)
#define SAFEUPLOAD_PUBLIC_RELAY_VERSION ((UINT32)25)
#define SAFEUPLOAD_PUBLIC_OPEN_PREPARE ((UINT32)1)
#define SAFEUPLOAD_PUBLIC_OPEN_FACTS ((UINT32)2)
#define SAFEUPLOAD_PUBLIC_DISPOSITION_PREPARE ((UINT32)3)
#define SAFEUPLOAD_PUBLIC_DISPOSITION_FACTS ((UINT32)4)
#define SAFEUPLOAD_PUBLIC_RELAY_PREPARED ((UINT32)1)
#define SAFEUPLOAD_PUBLIC_RELAY_PROGRESS ((UINT32)2)
#define SAFEUPLOAD_PUBLIC_RELAY_RECORDED ((UINT32)3)
#define SAFEUPLOAD_PUBLIC_RELAY_PREPARED_NO_NAME_EFFECT ((UINT32)4)

/* Observed local I/O facts, not additional persisted journal states. */
#define SAFEUPLOAD_PUBLIC_OPERATION_CAPTURED ((UINT32)1)
#define SAFEUPLOAD_PUBLIC_OPERATION_FORWARDED ((UINT32)2)
#define SAFEUPLOAD_PUBLIC_OPERATION_RESULT_KNOWN ((UINT32)4)
#define SAFEUPLOAD_PUBLIC_OPERATION_NOT_FORWARDED ((UINT32)8)
#define SAFEUPLOAD_PUBLIC_OPERATION_COVERAGE_LOST ((UINT32)16)
#define SAFEUPLOAD_PUBLIC_CLEANUP_OUTSTANDING ((UINT32)32) /* independent of the current operation slot */

#pragma pack(push, 4)
typedef struct _SAFEUPLOAD_PUBLIC_RELAY_REQUEST {
    UINT32 Version, StructSize, Phase, Reserved;
    GUID OpenNonce, MutationNonce, OperationId;
    UINT64 NativeMapRevision, OperationSequence;
} SAFEUPLOAD_PUBLIC_RELAY_REQUEST, *PSAFEUPLOAD_PUBLIC_RELAY_REQUEST;

typedef struct _SAFEUPLOAD_PUBLIC_RELAY_REPLY {
    SAFEUPLOAD_PUBLIC_RELAY_REQUEST Request;
    UINT64 PublishedGeneration;
    SAFEUPLOAD_STAGE_IDENTITY_V19 PublishedIdentity;
    UINT64 MutationGeneration;
    UINT32 Result, Reserved;
} SAFEUPLOAD_PUBLIC_RELAY_REPLY, *PSAFEUPLOAD_PUBLIC_RELAY_REPLY;

/* Base fields describe the original FILE_OPEN, never another process's
 * handle or a service reopen. JournalGeneration in this distinct V25 row is
 * zero: Published-generation binding is the separate field below. */
typedef struct _SAFEUPLOAD_PUBLIC_OPEN_REPLAY_ROW {
    SAFEUPLOAD_NATIVE_REPLAY_ROW Open;
    UINT64 PublishedGeneration;
    SAFEUPLOAD_STAGE_IDENTITY_V19 PublishedIdentity;
    UINT64 OperationSequence;
    GUID MutationTransferId, MutationNonce, MutationOperationId;
    UINT32 GrantedAccess, InformationClass, DispositionFlags, RequestorMode;
    UINT32 OperationFacts;
    INT32 OperationStatus;
    UINT64 MutationGeneration;
    INT64 ActorProcessCreationTime;
    UINT32 ActorProcessId, ActorSessionId, ActorSidBytes;
    UCHAR ActorSid[SAFEUPLOAD_NATIVE_REPLAY_SID_BYTES];
} SAFEUPLOAD_PUBLIC_OPEN_REPLAY_ROW, *PSAFEUPLOAD_PUBLIC_OPEN_REPLAY_ROW;

typedef struct _SAFEUPLOAD_PUBLIC_OPEN_REPLAY_PAGE {
    UINT32 ExtensionVersion, StructSize;
    GUID DriverInstanceId;
    UINT64 ConnectionEpoch, Revision;
    UINT32 OsBootSequence, StartIndex, Count, Complete;
    UINT64 Reserved;
    SAFEUPLOAD_PUBLIC_OPEN_REPLAY_ROW Rows[SAFEUPLOAD_NATIVE_REPLAY_PAGE_ROWS];
} SAFEUPLOAD_PUBLIC_OPEN_REPLAY_PAGE, *PSAFEUPLOAD_PUBLIC_OPEN_REPLAY_PAGE;
#pragma pack(pop)

C_ASSERT(sizeof(SAFEUPLOAD_PUBLIC_RELAY_REQUEST) == 80);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_PUBLIC_RELAY_REQUEST, NativeMapRevision) == 64);
C_ASSERT(sizeof(SAFEUPLOAD_PUBLIC_RELAY_REPLY) == 128);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_PUBLIC_RELAY_REPLY, MutationGeneration) == 112);
C_ASSERT(sizeof(SAFEUPLOAD_PUBLIC_OPEN_REPLAY_ROW) == 1024);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_PUBLIC_OPEN_REPLAY_ROW, OperationSequence) == 848);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_PUBLIC_OPEN_REPLAY_ROW, OperationFacts) == 920);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_PUBLIC_OPEN_REPLAY_ROW, ActorSid) == 956);
C_ASSERT(sizeof(SAFEUPLOAD_PUBLIC_OPEN_REPLAY_PAGE) == 16448);
#endif
#endif
