#ifndef _SAFEUPLOAD_STAGE_RESOURCE_WIRE_H_
#define _SAFEUPLOAD_STAGE_RESOURCE_WIRE_H_

/* Passive v32 ABI. No producer, negotiation success, worker or growth consumer.
 * Protocol.h supplies fixed-width types and the existing complete identities. */
#define SAFEUPLOAD_RESOURCE_VERSION ((UINT32)32)
#define SAFEUPLOAD_OPERATION_RESOURCE_GROW ((UINT32)23)
#define SAFEUPLOAD_OPERATION_RESOURCE_RETIRE ((UINT32)24)
#define SAFEUPLOAD_CONTROL_RESOURCE ((UINT32)36)
#define SAFEUPLOAD_RESOURCE_ALLOCATION_WAIT_TICKS ((UINT64)1200000000)

#pragma pack(push, 4)
typedef struct _SAFEUPLOAD_RESOURCE_BINDING_V32 {
    UINT32 Version, StructSize, Kind, Reserved;
    UINT64 RequestId, ConnectionCookie;
    GUID DriverInstanceId, TransferId;
    UINT64 AllocationGeneration;
    SAFEUPLOAD_STAGE_IDENTITY_V19 StageIdentity;
    UINT64 DestinationGeneration, Sequence;
} SAFEUPLOAD_RESOURCE_BINDING_V32;

typedef struct _SAFEUPLOAD_RESOURCE_ALLOCATION_V32 {
    SAFEUPLOAD_STAGE_ALLOCATE_V20 Intent;
    UINT64 ConnectionCookie, Issued, Deadline;
    UINT32 Mode, Reserved;
} SAFEUPLOAD_RESOURCE_ALLOCATION_V32;

typedef struct _SAFEUPLOAD_RESOURCE_GROWTH_V32 {
    SAFEUPLOAD_RESOURCE_BINDING_V32 Binding;
    UINT64 ObservedCapacity, RequiredExtent, Issued, Deadline;
    UCHAR Tail[16];
} SAFEUPLOAD_RESOURCE_GROWTH_V32;

typedef struct _SAFEUPLOAD_RESOURCE_RETIREMENT_V32 {
    SAFEUPLOAD_RESOURCE_BINDING_V32 Binding;
    UINT64 EndOfFile, AllocationSize, AuthorizedCapacity;
    UCHAR Tail[24];
} SAFEUPLOAD_RESOURCE_RETIREMENT_V32;

typedef struct _SAFEUPLOAD_RESOURCE_RESULT_V32 {
    UINT32 Version, StructSize, Kind, Result;
    UINT64 RequestId, ConnectionCookie;
    GUID DriverInstanceId, TransferId;
    UINT64 AllocationGeneration;
    SAFEUPLOAD_STAGE_IDENTITY_V19 StageIdentity;
    UINT64 DestinationGeneration, Sequence, ObservedCapacity, RequiredExtent, Issued, Deadline;
    UINT64 Capacity, LedgerRevision, RetirementEndOfFile, RetirementAllocationSize;
    UINT32 Flags, Reserved, StageNameBytes, NameReserved;
    WCHAR StageName[64];
    UCHAR Tail[32];
} SAFEUPLOAD_RESOURCE_RESULT_V32;

typedef struct _SAFEUPLOAD_RESOURCE_REPLY_V32 {
    UINT32 Version, StructSize;
    UINT64 RequestId;
    UINT32 Verdict, StageNameLength;
    SAFEUPLOAD_RESOURCE_RESULT_V32 Body;
} SAFEUPLOAD_RESOURCE_REPLY_V32;
#pragma pack(pop)

C_ASSERT(sizeof(SAFEUPLOAD_RESOURCE_BINDING_V32) == 112);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_RESOURCE_BINDING_V32, StageIdentity) == 72);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_RESOURCE_BINDING_V32, Sequence) == 104);
C_ASSERT(sizeof(SAFEUPLOAD_RESOURCE_ALLOCATION_V32) == 104);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_RESOURCE_ALLOCATION_V32, ConnectionCookie) == 72);
C_ASSERT(sizeof(SAFEUPLOAD_RESOURCE_GROWTH_V32) == 160);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_RESOURCE_GROWTH_V32, Deadline) == 136);
C_ASSERT(sizeof(SAFEUPLOAD_RESOURCE_RETIREMENT_V32) == 160);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_RESOURCE_RETIREMENT_V32, AuthorizedCapacity) == 128);
C_ASSERT(sizeof(SAFEUPLOAD_RESOURCE_RESULT_V32) == 352);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_RESOURCE_RESULT_V32, StageName) == 192);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_RESOURCE_RESULT_V32, Tail) == 320);
C_ASSERT(sizeof(SAFEUPLOAD_RESOURCE_REPLY_V32) == 376);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_RESOURCE_REPLY_V32, Body) == 24);

#endif
