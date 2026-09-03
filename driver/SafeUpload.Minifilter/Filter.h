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

} SAFEUPLOAD_DATA, *PSAFEUPLOAD_DATA;

extern SAFEUPLOAD_DATA SafeUploadData;

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

FLT_PREOP_CALLBACK_STATUS
SafeUploadPreRead (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

#endif // _SAFEUPLOAD_FILTER_H_
