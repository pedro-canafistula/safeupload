/*++

Module Name:

    Filter.h

Abstract:

    Kernel-only declarations for the SafeUpload minifilter: the global
    driver state and the prototypes of the FltMgr callbacks.

    Nothing in this header is shared with user mode. The user/kernel
    contract lives in Protocol.h.

Environment:

    Kernel mode

--*/

#ifndef _SAFEUPLOAD_FILTER_H_
#define _SAFEUPLOAD_FILTER_H_

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#include "Protocol.h"

//
//  Pool tag used for every allocation this driver makes. The constant is
//  written back-to-front ('lfUS') because x86/x64 are little endian, so
//  the bytes land in memory as "SUfl" (SafeUpload filter) and that is how
//  !poolused and !poolfind will display them.
//

#define SAFEUPLOAD_POOL_TAG 'lfUS'

//
//  The System process is always PID 4 and the Idle process is PID 0.
//  Both are ignored: they drive paging, cache and boot I/O that the
//  inspector has no business arbitrating, and stalling them is a good way
//  to deadlock the machine.
//

#define SAFEUPLOAD_IDLE_PROCESS_ID   ((ULONG) 0)
#define SAFEUPLOAD_SYSTEM_PROCESS_ID ((ULONG) 4)

//
//  Debugger tracing. The first variadic argument is always a string
//  literal, so it is concatenated with the prefix at compile time and the
//  macro works with or without further arguments.
//
//  These go out at DPFLTR_INFO_LEVEL, which the kernel suppresses by
//  default. To see them, raise the component mask in the debugger:
//
//      ed nt!Kd_IHVDRIVER_Mask 0xF
//
//  See DEPLOY.md for the persistent (registry) equivalent.
//

#define SafeUploadTrace(...) \
    DbgPrintEx( DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "SafeUpload: " __VA_ARGS__ )

//
//  How long the kernel is willing to wait for a verdict from user mode.
//
//  RN-013: when this expires - or the port is closed, or the inspector
//  answers garbage, or we cannot allocate - the operation is ALLOWED and
//  the event is reported as "Permitido sem inspecao". A failure to inspect
//  must never block a user and must never wedge the file system, so this
//  timeout is the hard ceiling on how long any single file operation can
//  be delayed by this driver.
//

#define SAFEUPLOAD_VERDICT_TIMEOUT_MS ((LONGLONG) 500)

//
//  Relative timeouts are expressed as a negative count of 100-nanosecond
//  intervals.
//

#define SAFEUPLOAD_VERDICT_TIMEOUT_INTERVALS \
    (-(SAFEUPLOAD_VERDICT_TIMEOUT_MS * 10 * 1000))

//
//  Global driver state. There is exactly one instance of this structure,
//  defined in Filter.c.
//

typedef struct _SAFEUPLOAD_DATA {

    //
    //  The driver object handed to us by the I/O manager in DriverEntry.
    //

    PDRIVER_OBJECT DriverObject;

    //
    //  Our registration handle with the filter manager. Valid from a
    //  successful FltRegisterFilter until FltUnregisterFilter.
    //

    PFLT_FILTER Filter;

    //
    //  Server port the inspector connects to. Created in DriverEntry,
    //  closed on unload; closing it stops new connections.
    //

    PFLT_PORT ServerPort;

    //
    //  Port of the connected inspector, or NULL when nobody is listening.
    //  Only one connection is accepted at a time.
    //
    //  The filter manager synchronizes FltCloseClientPort against
    //  FltSendMessage's use of this field, so it is safe to hand its
    //  address to FltSendMessage without a lock of our own.
    //

    PFLT_PORT ClientPort;

    //
    //  PID of the process that owns ClientPort, or 0 when disconnected.
    //  Read on every operation to keep the inspector's own I/O out of the
    //  filter: sending the inspector a message about the inspector's own
    //  file access would deadlock it against its own reply.
    //

    volatile ULONG InspectorProcessId;

    //
    //  Guards the user-mode channel against teardown. Every caller of
    //  FltSendMessage holds rundown protection for the duration of the
    //  call; unload waits for all of them to drain and blocks any new
    //  acquisition before unregistering the filter.
    //

    EX_RUNDOWN_REF ChannelRundown;

    //
    //  Source of SAFEUPLOAD_REQUEST.RequestId.
    //

    volatile LONG64 NextRequestId;

} SAFEUPLOAD_DATA, *PSAFEUPLOAD_DATA;

extern SAFEUPLOAD_DATA SafeUploadData;

///////////////////////////////////////////////////////////////////////////
//
//  Contexts. Implemented in Context.c.
//
//  These exist so the hot path can answer without talking to user mode.
//  The instance context turns a per-operation question ("what kind of
//  volume is this?") into a one-off computed at attach time, and the
//  stream context turns "is this file sensitive?" into one user-mode round
//  trip per file version instead of one per operation.
//
///////////////////////////////////////////////////////////////////////////

//
//  What kind of volume an instance is attached to. Computed once, in
//  InstanceSetup, and never again.
//

typedef enum _SAFEUPLOAD_VOLUME_KIND {

    //
    //  Could not be determined. Treated as out of scope: a volume we
    //  cannot classify is a volume we cannot make correct decisions about.
    //

    SafeUploadVolumeUnknown = 0,

    //
    //  Ordinary local disk. In scope only when the path falls under one of
    //  the monitored prefixes - this is where cloud sync folders live.
    //

    SafeUploadVolumeFixed,

    //
    //  Removable media: pen drive, external disk, memory card.
    //

    SafeUploadVolumeRemovable,

    //
    //  Network redirector.
    //

    SafeUploadVolumeNetwork

} SAFEUPLOAD_VOLUME_KIND, *PSAFEUPLOAD_VOLUME_KIND;

typedef struct _SAFEUPLOAD_INSTANCE_CONTEXT {

    SAFEUPLOAD_VOLUME_KIND VolumeKind;

} SAFEUPLOAD_INSTANCE_CONTEXT, *PSAFEUPLOAD_INSTANCE_CONTEXT;

//
//  Per-handle marker. Its only job is to remember, at cleanup time, that
//  this particular handle was opened for write - which is when the cached
//  verdict for the file has to be thrown away.
//

typedef struct _SAFEUPLOAD_STREAMHANDLE_CONTEXT {

    BOOLEAN OpenedForWrite;

} SAFEUPLOAD_STREAMHANDLE_CONTEXT, *PSAFEUPLOAD_STREAMHANDLE_CONTEXT;

//
//  Per-file cache of the last inspection.
//
//  This context belongs to the file, not to a handle: it outlives the
//  handle that created it and serves every process that opens the same
//  file afterwards. That is what makes the second open of a document cost
//  nothing.
//
//  The verdict is only trusted while the stamp still matches the file and
//  Dirty is clear. Dirty is set when a handle that was opened for write is
//  closed, because the content may have changed underneath us.
//

typedef struct _SAFEUPLOAD_STREAM_CONTEXT {

    //
    //  Guards every field below. A push lock rather than a mutex because
    //  reads dominate by orders of magnitude: the common case is several
    //  threads checking a verdict nobody is writing.
    //

    EX_PUSH_LOCK Lock;

    //
    //  Whether this file has already been judged to be in or out of scope.
    //
    //  Cached separately from the verdict because deciding scope costs a
    //  name resolution, and a file that is out of scope is never asked
    //  about again - which is the common case for most of what a machine
    //  opens.
    //

    BOOLEAN ScopeEvaluated;

    //
    //  SAFEUPLOAD_REQUEST_FLAG_SCOPE_*, or zero when out of scope.
    //

    UINT32 ScopeFlags;

    //
    //  Whether Verdict and Categories mean anything yet.
    //

    BOOLEAN VerdictValid;

    //
    //  Set when the file may have changed since the verdict was recorded.
    //

    BOOLEAN Dirty;

    //
    //  SAFEUPLOAD_VERDICT_*, as answered by user mode.
    //

    UINT32 Verdict;

    //
    //  Categories found, for the process taint table to consume later.
    //

    UINT32 Categories;

    //
    //  Stamp the verdict was computed against. A mismatch invalidates it
    //  just as Dirty does, and catches changes made through paths this
    //  driver never saw.
    //

    LARGE_INTEGER FileSize;
    LARGE_INTEGER LastWriteTime;

} SAFEUPLOAD_STREAM_CONTEXT, *PSAFEUPLOAD_STREAM_CONTEXT;

extern CONST FLT_CONTEXT_REGISTRATION SafeUploadContextRegistration[];

SAFEUPLOAD_VOLUME_KIND
SafeUploadClassifyVolume (
    _In_ PFLT_VOLUME Volume,
    _In_ DEVICE_TYPE VolumeDeviceType
    );

NTSTATUS
SafeUploadSetInstanceContext (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _Out_ PSAFEUPLOAD_VOLUME_KIND VolumeKind
    );

NTSTATUS
SafeUploadMarkHandleForWrite (
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

BOOLEAN
SafeUploadHandleWasOpenedForWrite (
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

NTSTATUS
SafeUploadGetOrCreateStreamContext (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFILE_OBJECT FileObject,
    _Outptr_result_nullonfailure_ PSAFEUPLOAD_STREAM_CONTEXT *StreamContext
    );

//
//  One request and its response in a single pool block. Keeping them in
//  one allocation means every callback has exactly one thing to free, so
//  the error paths are trivial to audit. Neither structure fits comfortably
//  on a kernel stack.
//

typedef struct _SAFEUPLOAD_EXCHANGE {

    SAFEUPLOAD_REQUEST Request;
    SAFEUPLOAD_RESPONSE Response;

} SAFEUPLOAD_EXCHANGE, *PSAFEUPLOAD_EXCHANGE;

///////////////////////////////////////////////////////////////////////////
//
//  Startup, teardown and operation callbacks. Implemented in Filter.c.
//
///////////////////////////////////////////////////////////////////////////

DRIVER_INITIALIZE DriverEntry;

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
SafeUploadUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
SafeUploadInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

NTSTATUS
SafeUploadInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
SafeUploadPreCreate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
SafeUploadPostCreate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
SafeUploadPreCleanup (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );


///////////////////////////////////////////////////////////////////////////
//
//  Process taint. Implemented in Taint.c.
//
//  Records which processes have obtained access to sensitive content, so
//  that a later write to a monitored destination can be refused in
//  pre-create - where refusing costs nothing and leaves nothing behind.
//
///////////////////////////////////////////////////////////////////////////

//
//  How long a taint survives without further contact with sensitive
//  content. Without a limit, a long-lived process would be barred from
//  writing to removable media until the machine reboots.
//

#define SAFEUPLOAD_TAINT_TTL_SECONDS ((ULONGLONG) 300)

#define SAFEUPLOAD_TAINT_TTL_INTERVALS \
    (SAFEUPLOAD_TAINT_TTL_SECONDS * 10ULL * 1000ULL * 1000ULL)

VOID
SafeUploadInitializeTaint (
    VOID
    );

VOID
SafeUploadFreeTaint (
    VOID
    );

VOID
SafeUploadTaintProcess (
    _In_ ULONG ProcessId,
    _In_ UINT32 Categories
    );

VOID
SafeUploadClearProcessTaint (
    _In_ ULONG ProcessId
    );

BOOLEAN
SafeUploadIsProcessTainted (
    _In_ ULONG ProcessId
    );

///////////////////////////////////////////////////////////////////////////
//
//  Scope policy. Implemented in Policy.c.
//
//  An immutable snapshot behind a push lock: readers take it shared and
//  never allocate, a write builds a whole new snapshot and swaps it. The
//  character storage lives inside the snapshot and the string tables point
//  into it, so one allocation holds everything.
//
///////////////////////////////////////////////////////////////////////////

typedef struct _SAFEUPLOAD_POLICY {

    UINT32 ExtensionCount;
    UINT32 PrefixCount;
    UINT32 SourcePrefixCount;
    UINT32 ImageCount;
    UINT32 Flags;

    //
    //  Measured once, when the snapshot is built. A prefix can be 260
    //  characters, and measuring it on every operation would put a string
    //  walk in the hot path for nothing.
    //

    UNICODE_STRING Extensions[SAFEUPLOAD_MAX_EXTENSIONS];
    UNICODE_STRING Prefixes[SAFEUPLOAD_MAX_PREFIXES];
    UNICODE_STRING SourcePrefixes[SAFEUPLOAD_MAX_SOURCE_PREFIXES];
    UNICODE_STRING Images[SAFEUPLOAD_MAX_IMAGES];

    //
    //  The snapshot's own copy of the message. Everything above points in
    //  here, never at the buffer user mode supplied.
    //

    SAFEUPLOAD_POLICY_MESSAGE Data;

} SAFEUPLOAD_POLICY, *PSAFEUPLOAD_POLICY;

VOID
SafeUploadInitializePolicy (
    VOID
    );

VOID
SafeUploadFreePolicy (
    VOID
    );

NTSTATUS
SafeUploadSetPolicy (
    _In_ CONST SAFEUPLOAD_POLICY_MESSAGE *Message
    );

BOOLEAN
SafeUploadPolicyMatchesExtension (
    _In_ PCUNICODE_STRING FileName
    );

BOOLEAN
SafeUploadPolicyMatchesDestination (
    _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind,
    _In_opt_ PCUNICODE_STRING NormalizedPath
    );

BOOLEAN
SafeUploadPolicyMatchesSource (
    _In_ PCUNICODE_STRING NormalizedPath
    );

BOOLEAN
SafeUploadPolicyExcludesImage (
    _In_ PCUNICODE_STRING ImageName
    );

///////////////////////////////////////////////////////////////////////////
//
//  User-mode channel. Implemented in Communication.c.
//
///////////////////////////////////////////////////////////////////////////

NTSTATUS
SafeUploadCreateCommunicationPort (
    VOID
    );

VOID
SafeUploadCloseCommunicationPort (
    VOID
    );

NTSTATUS
SafeUploadRequestVerdict (
    _Inout_ PSAFEUPLOAD_EXCHANGE Exchange,
    _Out_ PUINT32 Verdict
    );

#endif // _SAFEUPLOAD_FILTER_H_
