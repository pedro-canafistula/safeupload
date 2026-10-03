#pragma once
/* Private qualification protocol. This driver is excluded from the product build and installer. */
#define SECTION_FAULT_VERSION 1u
#define SECTION_FAULT_STATUS 0u
#define SECTION_FAULT_ARM_FAILURE 1u
#define SECTION_FAULT_ARM_HOLD 2u
#define SECTION_FAULT_RELEASE 3u
#define SECTION_FAULT_DISARM 4u
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
