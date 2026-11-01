/*
 * Messages between the SafeUpload agent and the gate minifilter.
 * The agent's copy of this layout is agente/SafeUpload.Agent.Service/Gate/GateClient.cs; keep both in step.
 */
#pragma once

#define SAFEUPLOAD_GATE_PORT_NAME       L"\\SafeUploadGatePort"
#define SAFEUPLOAD_GATE_VERSION         1
#define SAFEUPLOAD_GATE_MAX_PATHS       16
#define SAFEUPLOAD_GATE_MAX_PATH_CHARS  512

/* Policy flags: refuse other processes' writes on these whole volume kinds. */
#define SAFEUPLOAD_GATE_FLAG_REMOVABLE  0x00000001
#define SAFEUPLOAD_GATE_FLAG_NETWORK    0x00000002

typedef enum _SAFEUPLOAD_GATE_COMMAND {
    SafeUploadGateSetPolicy = 1,
    SafeUploadGateGetCounters = 2
} SAFEUPLOAD_GATE_COMMAND;

typedef struct _SAFEUPLOAD_GATE_HEADER {
    ULONG Command;      /* SAFEUPLOAD_GATE_COMMAND */
    ULONG Version;      /* SAFEUPLOAD_GATE_VERSION */
} SAFEUPLOAD_GATE_HEADER;

/* Protected folders as NT paths (\Device\HarddiskVolume3\Folder), NUL-terminated, no trailing backslash. */
typedef struct _SAFEUPLOAD_GATE_POLICY {
    SAFEUPLOAD_GATE_HEADER Header;
    ULONG Flags;
    ULONG PathCount;
    WCHAR Paths[SAFEUPLOAD_GATE_MAX_PATHS][SAFEUPLOAD_GATE_MAX_PATH_CHARS];
} SAFEUPLOAD_GATE_POLICY;

typedef struct _SAFEUPLOAD_GATE_COUNTERS {
    ULONGLONG Refused;          /* opens refused */
    ULONGLONG RenamesRefused;   /* renames and hard links into a protected place refused */
} SAFEUPLOAD_GATE_COUNTERS;

C_ASSERT(sizeof(SAFEUPLOAD_GATE_HEADER) == 8);
C_ASSERT(sizeof(SAFEUPLOAD_GATE_POLICY) == 16 + SAFEUPLOAD_GATE_MAX_PATHS * SAFEUPLOAD_GATE_MAX_PATH_CHARS * 2);
C_ASSERT(sizeof(SAFEUPLOAD_GATE_COUNTERS) == 16);
