#ifndef SAFEUPLOAD_STAGE_BOUND_ALLOCATION_H
#define SAFEUPLOAD_STAGE_BOUND_ALLOCATION_H
#include "Protocol.h"

#if defined(SAFEUPLOAD_STAGING_PROTOTYPE) && SAFEUPLOAD_STAGING_PROTOTYPE
/* Reserved for the integrated identity-keyed pipeline. Defining its wire
 * contract does not advertise this capability or enable a CREATE producer. */
#define SAFEUPLOAD_STAGE_BOUND_ALLOCATION_VERSION ((UINT32) 23)
#define SAFEUPLOAD_STAGE_CAPABILITY_BOUND_DESTINATION_HEAD ((UINT32) 0x00000040)

#pragma pack(push, 4)
typedef struct _SAFEUPLOAD_STAGE_ALLOCATE_V23 {
    UINT32 Version;
    UINT32 StructSize;
    GUID AllocationReservationId;
    GUID ParentTransferId;
    UINT32 Disposition;
    UINT32 ReferenceKind;
    FILE_ID_128 PublicTargetId; /* All-zero only for proven public absence. */
    GUID MountManagerVolumeId;
    FILE_ID_128 VolumeRootId; /* Serial is the checked ParentIdentity serial. */
    SAFEUPLOAD_STAGE_IDENTITY_V19 ParentIdentity;
    UINT16 ParentCaseSensitive;
    UINT16 CanonicalLeafBytes; /* Checked final component in Request.Path. */
} SAFEUPLOAD_STAGE_ALLOCATE_V23, *PSAFEUPLOAD_STAGE_ALLOCATE_V23;
#pragma pack(pop)

C_ASSERT(sizeof(SAFEUPLOAD_STAGE_ALLOCATE_V23) == 124);
C_ASSERT(sizeof(SAFEUPLOAD_STAGE_ALLOCATE_V23) <= SAFEUPLOAD_MAX_IMAGE_NAME_BYTES);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_STAGE_ALLOCATE_V23, AllocationReservationId) == 8);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_STAGE_ALLOCATE_V23, ParentTransferId) == 24);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_STAGE_ALLOCATE_V23, Disposition) == 40);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_STAGE_ALLOCATE_V23, ReferenceKind) == 44);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_STAGE_ALLOCATE_V23, PublicTargetId) == 48);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_STAGE_ALLOCATE_V23, MountManagerVolumeId) == 64);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_STAGE_ALLOCATE_V23, VolumeRootId) == 80);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_STAGE_ALLOCATE_V23, ParentIdentity) == 96);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_STAGE_ALLOCATE_V23, ParentCaseSensitive) == 120);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_STAGE_ALLOCATE_V23, CanonicalLeafBytes) == 122);
#endif
#endif
