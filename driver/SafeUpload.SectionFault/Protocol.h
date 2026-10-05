#pragma once
/* Private qualification protocol. This driver is excluded from the product build and installer. */
#define SECTION_FAULT_VERSION 1u
#define SECTION_FAULT_WRITE_VERSION 2u
#define SECTION_FAULT_STATUS 0u
#define SECTION_FAULT_ARM_FAILURE 1u
#define SECTION_FAULT_ARM_HOLD 2u
#define SECTION_FAULT_RELEASE 3u
#define SECTION_FAULT_DISARM 4u
#define SECTION_FAULT_WRITE_ARM 5u
#define SECTION_FAULT_WRITE_RELEASE 6u
#define SECTION_FAULT_WRITE_DISARM 7u
#define SECTION_FAULT_WRITE_STATUS 8u
#define SECTION_FAULT_WRITE_SYNTHETIC_FAILURE 9u
#define SECTION_FAULT_PORT L"\\SafeUploadSectionFaultPort"
typedef struct _SECTION_FAULT_REQUEST {
    ULONG Version;
    ULONG Command;
    UINT64 FileHandle; /* Caller-owned user handle; resolved in UserMode, never a kernel pointer. */
} SECTION_FAULT_REQUEST;
typedef struct _SECTION_FAULT_REPLY {
    ULONG Version;
    ULONG Mode;
    UINT64 Matched;
    UINT64 Failed;
    UINT64 Held;
    UINT64 TimedOut;
    UINT64 InvalidIrql;
    UINT64 ArmedFileObject;
    ULONG CurrentHeld;
    ULONG Reserved;
    UINT64 ArmGeneration;
} SECTION_FAULT_REPLY;
C_ASSERT(sizeof(SECTION_FAULT_REQUEST) == 16);
C_ASSERT(sizeof(SECTION_FAULT_REPLY) == 72);

/* Additive W01 control schema. The v1 section fault request/reply and commands
 * remain unchanged so the existing SectionFault client keeps its wire contract. */
typedef struct _SECTION_FAULT_WRITE_REQUEST {
    ULONG Version;
    ULONG Command;
    UINT64 FileHandle; /* User handle resolved in UserMode. */
    UINT64 Reserved;
} SECTION_FAULT_WRITE_REQUEST;
typedef struct _SECTION_FAULT_WRITE_REPLY {
    ULONG Version;
    ULONG Mode;
    ULONG CurrentHeld;
    ULONG PostFlags;
    UINT64 ArmGeneration;
    UINT64 Matched;
    UINT64 Held;
    UINT64 Released;
    UINT64 LowerPosts;
    UINT64 Canceled;
    UINT64 TimedOut;
    UINT64 ArmedFileObject;
    INT32 LowerStatus;
    UINT32 Reserved;
    UINT64 LowerInformation;
    UINT64 LowerCallbackData;
    UINT64 SyntheticFailures;
    UINT64 WriteOffset;
    UINT32 WriteLength;
    UINT32 IrpFlags;
} SECTION_FAULT_WRITE_REPLY;
C_ASSERT(sizeof(SECTION_FAULT_WRITE_REQUEST) == 24);
C_ASSERT(sizeof(SECTION_FAULT_WRITE_REPLY) == 128);
