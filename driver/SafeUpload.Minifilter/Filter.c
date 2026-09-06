/*++

Module Name:

    Filter.c

Abstract:

    Main module of the SafeUpload minifilter.

    The driver registers a pre-operation callback for IRP_MJ_CREATE,
    discards the traffic it has no business arbitrating, and asks a
    user-mode inspector for a verdict before letting the operation through.

    Deliberately, there is NO detection logic in this file. Business rules
    RN-001..RN-004 (CPF, CNPJ, Luhn, password heuristics) live in user
    mode. The kernel only transports.

Environment:

    Kernel mode

--*/

#include "Filter.h"

//
//  Single instance of the global driver state.
//

SAFEUPLOAD_DATA SafeUploadData;

//
//  Local helpers.
//

static
BOOLEAN
SafeUploadIsIgnoredProcess (
    _In_ ULONG ProcessId
    );

static
BOOLEAN
SafeUploadMayBeInScope (
    _In_ PCUNICODE_STRING FileName
    );

//
//  Extensions the policy monitors.
//
//  TODO: this table is a stand-in. The real list belongs to the policy and
//  will be pushed down from user mode over the communication port, together
//  with the monitored path prefixes already in NT form. Until then it
//  mirrors the defaults in LocalPolicyStore so that kernel and user mode
//  agree on scope.
//

static CONST UNICODE_STRING SafeUploadMonitoredExtensions[] = {
    RTL_CONSTANT_STRING( L".txt" ),
    RTL_CONSTANT_STRING( L".csv" ),
    RTL_CONSTANT_STRING( L".docx" ),
    RTL_CONSTANT_STRING( L".xlsx" )
};

static
NTSTATUS
SafeUploadCopyRequestPath (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _Inout_ PSAFEUPLOAD_REQUEST Request
    );

static
VOID
SafeUploadCopyRequestImageName (
    _In_ PFLT_CALLBACK_DATA Data,
    _Inout_ PSAFEUPLOAD_REQUEST Request
    );

static
FLT_PREOP_CALLBACK_STATUS
SafeUploadInspectOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ UINT32 Operation
    );

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(INIT, DriverEntry)
    #pragma alloc_text(PAGE, SafeUploadUnload)
    #pragma alloc_text(PAGE, SafeUploadInstanceSetup)
    #pragma alloc_text(PAGE, SafeUploadInstanceQueryTeardown)
    #pragma alloc_text(PAGE, SafeUploadPreCreate)
    #pragma alloc_text(PAGE, SafeUploadCopyRequestPath)
    #pragma alloc_text(PAGE, SafeUploadCopyRequestImageName)
    #pragma alloc_text(PAGE, SafeUploadInspectOperation)
#endif

///////////////////////////////////////////////////////////////////////////
//
//  Registration data handed to the filter manager.
//
///////////////////////////////////////////////////////////////////////////

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

    //
    //  IRP_MJ_CREATE carries no flags: a create is never paging I/O, so
    //  FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO would be a no-op here.
    //

    { IRP_MJ_CREATE,
      0,
      SafeUploadPreCreate,
      NULL },

    //
    //  IRP_MJ_READ is deliberately NOT registered.
    //
    //  It was, and it was the single largest cost in the driver: one
    //  user-mode round trip per read, of every file, of every process. With
    //  a synchronous inspector that is not merely slow, it is a feedback
    //  loop - anything the inspector does that touches a file waits on the
    //  inspector.
    //
    //  Nothing is lost. A create asking for FILE_READ_DATA is already the
    //  declaration of intent to read, it happens once per open instead of
    //  once per block, and it covers two cases a read hook never sees:
    //  memory-mapped files, whose reads arrive as paging I/O, and handles
    //  opened long before the data is touched.
    //
    //  See ARQUITETURA.md for the evidence under which a read hook would
    //  come back, and in what form.
    //

    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags
    SafeUploadContextRegistration,      //  Context registration
    Callbacks,                          //  Operation callbacks
    SafeUploadUnload,                   //  FilterUnload
    SafeUploadInstanceSetup,            //  InstanceSetup
    SafeUploadInstanceQueryTeardown,    //  InstanceQueryTeardown
    NULL,                               //  InstanceTeardownStart
    NULL,                               //  InstanceTeardownComplete
    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent
};

///////////////////////////////////////////////////////////////////////////
//
//  Initialization and teardown.
//
///////////////////////////////////////////////////////////////////////////

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    Initialization routine for the driver. Registers with the filter
    manager and starts filtering.

    IRQL: PASSIVE_LEVEL. Called by the I/O manager in the context of the
    System process while the service is being started.

Arguments:

    DriverObject - Driver object created by the system for this driver.

    RegistryPath - Where this driver's service parameters live. Unused in
        v1: every tunable is a compile-time constant.

Return Value:

    STATUS_SUCCESS once the filter is registered and filtering, otherwise
    the failing status. On any failure nothing stays registered.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( RegistryPath );

    //
    //  Opt in to non-paged, non-executable pool for every allocation that
    //  does not name a pool type explicitly. Required for the driver to be
    //  loadable on Windows builds that enforce NX pool.
    //

    ExInitializeDriverRuntime( DrvRtPoolNxOptIn );

    //
    //  Has to be initialized before the port exists, because the first
    //  thing any user of the channel does is acquire it.
    //

    ExInitializeRundownProtection( &SafeUploadData.ChannelRundown );

    SafeUploadData.DriverObject = DriverObject;

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &SafeUploadData.Filter );

    if (!NT_SUCCESS( status )) {

        SafeUploadTrace( "FltRegisterFilter failed, status 0x%08X\n", status );
        return status;
    }

    //
    //  From here on the filter manager may call our callbacks, so every
    //  failure path below has to unregister before returning.
    //

    status = SafeUploadCreateCommunicationPort();

    if (!NT_SUCCESS( status )) {

        FltUnregisterFilter( SafeUploadData.Filter );
        SafeUploadData.Filter = NULL;

        return status;
    }

    status = FltStartFiltering( SafeUploadData.Filter );

    if (!NT_SUCCESS( status )) {

        SafeUploadTrace( "FltStartFiltering failed, status 0x%08X\n", status );

        SafeUploadCloseCommunicationPort();

        FltUnregisterFilter( SafeUploadData.Filter );
        SafeUploadData.Filter = NULL;

        return status;
    }

    SafeUploadTrace( "loaded and filtering\n" );

    return STATUS_SUCCESS;
}


NTSTATUS
SafeUploadUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    Filter unload callback.

    Two cases have to be told apart:

    - Mandatory unload (FLTFL_FILTER_UNLOAD_MANDATORY): the filter manager
      is not asking, it is telling. A failure status is ignored and the
      driver is torn down regardless, so the only correct behaviour is to
      release everything and return success.

    - Non-mandatory unload: an operator ran "fltmc unload". Here the filter
      is allowed to decline by returning STATUS_FLT_DO_NOT_DETACH.

    IRQL: PASSIVE_LEVEL.

Arguments:

    Flags - FLTFL_FILTER_UNLOAD_MANDATORY when the unload cannot be refused.

Return Value:

    STATUS_SUCCESS to let the unload proceed.

--*/
{
    PAGED_CODE();

    SafeUploadTrace( "unload requested (mandatory=%u)\n",
                     BooleanFlagOn( Flags, FLTFL_FILTER_UNLOAD_MANDATORY ) );

    //
    //  A voluntary unload with the inspector still attached is declined.
    //  Tearing the channel down under a live client is legal but pointless
    //  guesswork for the operator: stopping the inspector first makes the
    //  order of events deterministic. A mandatory unload gets no say.
    //

    if (!FlagOn( Flags, FLTFL_FILTER_UNLOAD_MANDATORY ) &&
        SafeUploadData.ClientPort != NULL) {

        SafeUploadTrace( "declining voluntary unload: inspector still connected\n" );

        return STATUS_FLT_DO_NOT_DETACH;
    }

    //
    //  Order matters here.
    //
    //  1. Close the ports. No new connection can be made, and any thread
    //     already blocked inside FltSendMessage is released immediately
    //     instead of waiting out its verdict timeout.
    //

    SafeUploadCloseCommunicationPort();

    //
    //  2. Drain. Every later attempt to acquire rundown protection fails
    //     from here on, and this call returns once the last in-flight
    //     FltSendMessage has released it. Without this, an operation could
    //     still be touching the channel while it is being destroyed.
    //

    ExWaitForRundownProtectionRelease( &SafeUploadData.ChannelRundown );

    //
    //  3. Unregister. FltUnregisterFilter waits for every in-flight
    //     callback to return, so once it completes no code of ours can run.
    //

    FltUnregisterFilter( SafeUploadData.Filter );
    SafeUploadData.Filter = NULL;

    SafeUploadTrace( "unloaded\n" );

    return STATUS_SUCCESS;
}


NTSTATUS
SafeUploadInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    Called by the filter manager whenever it considers attaching an
    instance of this filter to a volume.

    IRQL: PASSIVE_LEVEL.

Arguments:

    FltObjects - The instance and volume being offered.

    Flags - Kind of attachment being made.

    VolumeDeviceType - DEVICE_TYPE of the volume.

    VolumeFilesystemType - File system formatted on the volume.

Return Value:

    STATUS_SUCCESS to attach, STATUS_FLT_DO_NOT_ATTACH to decline.

--*/
{
    SAFEUPLOAD_VOLUME_KIND volumeKind;
    NTSTATUS status;

    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    //
    //  Network volumes are attached to, not refused. A network share is one
    //  of the destinations the policy monitors, so declining here would be
    //  a hole rather than an optimization.
    //

    status = SafeUploadSetInstanceContext( FltObjects, VolumeDeviceType, &volumeKind );

    if (!NT_SUCCESS( status ) || volumeKind == SafeUploadVolumeUnknown) {

        //
        //  Attach anyway.
        //
        //  An earlier version declined the attachment here, on the reasoning
        //  that a volume we cannot classify is a volume we cannot decide
        //  about. That reasoning was wrong in practice: it turns a
        //  recoverable, per-volume problem into a filter that is loaded,
        //  visible in "fltmc filters", and attached to nothing at all - the
        //  worst possible failure mode, because it looks like it is working.
        //
        //  Staying attached with an unknown classification is safe. Nothing
        //  is treated as a monitored destination unless it was positively
        //  identified as one, so an unclassified volume behaves as out of
        //  scope. That is the same fail-open outcome, without the cliff.
        //

        SafeUploadTrace( "volume not classified (status 0x%08X), attaching as unknown\n",
                         status );
    }
    else {

        SafeUploadTrace( "attached to volume, kind %u\n", (ULONG) volumeKind );
    }

    return STATUS_SUCCESS;
}


NTSTATUS
SafeUploadInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    Called when someone requests a manual detach of one of our instances
    ("fltmc detach"). We hold no per-instance state, so detaching is always
    safe.

    IRQL: PASSIVE_LEVEL.

Arguments:

    FltObjects - Instance and volume being detached.

    Flags - Unused.

Return Value:

    STATUS_SUCCESS - the detach may proceed.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    return STATUS_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////
//
//  Operation callbacks.
//
///////////////////////////////////////////////////////////////////////////

static
BOOLEAN
SafeUploadIsIgnoredProcess (
    _In_ ULONG ProcessId
    )
/*++

Routine Description:

    Decides whether I/O issued by a given process bypasses inspection
    entirely.

    IRQL: any. Touches no pageable data.

Arguments:

    ProcessId - PID of the process that issued the operation.

Return Value:

    TRUE if the operation must be allowed without asking user mode.

--*/
{
    //
    //  Idle and System drive paging, cache flushes and boot I/O. Blocking
    //  them - or merely making them wait on a user-mode process - is a
    //  reliable way to hang the machine.
    //

    if (ProcessId == SAFEUPLOAD_IDLE_PROCESS_ID ||
        ProcessId == SAFEUPLOAD_SYSTEM_PROCESS_ID) {

        return TRUE;
    }

    //
    //  The inspector's own I/O must never be sent to the inspector. It
    //  would be asked to arbitrate a file operation it is itself performing
    //  while it is blocked waiting to answer, which deadlocks the thread
    //  until the verdict timeout expires - on every single file it touches.
    //
    //  InspectorProcessId is 0 while nobody is connected, and PID 0 is
    //  already excluded above, so no extra guard is needed here.
    //

    if (ProcessId == SafeUploadData.InspectorProcessId) {

        return TRUE;
    }

    return FALSE;
}


static
BOOLEAN
SafeUploadMayBeInScope (
    _In_ PCUNICODE_STRING FileName
    )
/*++

Routine Description:

    Cheap extension gate.

    This deliberately reads the name the caller passed rather than asking
    the filter manager to resolve one. Resolving a name may issue I/O and
    allocate; reading Parameters.Create.TargetFileObject->FileName costs
    nothing. As a gate that is the right trade: it rejects the overwhelming
    majority of operations - every .dll, .exe, .log, .dat the system touches
    - before anything expensive happens, and the few it lets through are
    resolved properly further down.

    The name here may be relative, or a short name, or absent entirely. That
    is fine for a gate, as long as an undetermined answer errs towards
    letting the operation through to the slow path rather than skipping it.

    IRQL: any. Touches no pageable data and issues no I/O.

Arguments:

    FileName - Name as supplied by the caller. May be empty.

Return Value:

    FALSE when the operation certainly falls outside the monitored
    extensions and can be skipped. TRUE when it matches, or when the name is
    not conclusive enough to decide here.

--*/
{
    UNICODE_STRING extension;
    USHORT index;
    USHORT charCount;
    USHORT dotIndex;
    ULONG entry;

    if (FileName == NULL || FileName->Length == 0 || FileName->Buffer == NULL) {

        //
        //  Nothing to judge - an open by file ID, for instance. Let it reach
        //  the slow path, which resolves the real name.
        //

        return TRUE;
    }

    charCount = (USHORT) (FileName->Length / sizeof( WCHAR ));
    dotIndex = 0;

    //
    //  Walk back to the last dot of the final component. A separator ends
    //  the search: a dot in a directory name is not an extension.
    //

    for (index = charCount; index > 0; index -= 1) {

        WCHAR current = FileName->Buffer[index - 1];

        if (current == L'\\' || current == L':') {

            break;
        }

        if (current == L'.') {

            dotIndex = index - 1;
            break;
        }
    }

    if (dotIndex == 0) {

        //
        //  Final component carries no extension. The policy only monitors
        //  named extensions, so this is out of scope by the same rule user
        //  mode would apply.
        //

        return FALSE;
    }

    extension.Buffer = &FileName->Buffer[dotIndex];
    extension.Length = (USHORT) ((charCount - dotIndex) * sizeof( WCHAR ));
    extension.MaximumLength = extension.Length;

    for (entry = 0; entry < RTL_NUMBER_OF( SafeUploadMonitoredExtensions ); entry += 1) {

        if (RtlCompareUnicodeString( &extension,
                                     &SafeUploadMonitoredExtensions[entry],
                                     TRUE ) == 0) {

            return TRUE;
        }
    }

    return FALSE;
}


static
NTSTATUS
SafeUploadCopyRequestPath (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _Inout_ PSAFEUPLOAD_REQUEST Request
    )
/*++

Routine Description:

    Resolves the target file name and copies it into the request.

    FltMgr contract worth spelling out: the normalized name is the one form
    a filter can compare against without short-name or relative-open
    ambiguity, but it is not always available. In pre-create the file is not
    open yet, so producing it may require the file system to be queried, and
    the query is allowed to fail - a volume that is being dismounted, a name
    provider that is not ready, a create that will end in STATUS_REPARSE.
    When that happens the opened name is used instead: it is whatever the
    caller literally passed, which is still enough for the inspector to work
    with, and the request is flagged so user mode knows it is looking at a
    lower-quality name.

    IRQL: PASSIVE_LEVEL. FltGetFileNameInformation may issue I/O.

Arguments:

    Data - Parameters of the operation being inspected.

    Request - Request being built. Its Path, PathLength and Flags fields are
        filled in. The buffer is already zeroed by the caller, so the string
        is left NUL-terminated by construction.

Return Value:

    STATUS_SUCCESS when a name was obtained, otherwise the failing status.

--*/
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    ULONG copyLength;

    PAGED_CODE();

    status = FltGetFileNameInformation( Data,
                                        FLT_FILE_NAME_NORMALIZED |
                                            FLT_FILE_NAME_QUERY_DEFAULT,
                                        &nameInfo );

    if (!NT_SUCCESS( status )) {

        status = FltGetFileNameInformation( Data,
                                            FLT_FILE_NAME_OPENED |
                                                FLT_FILE_NAME_QUERY_DEFAULT,
                                            &nameInfo );

        if (!NT_SUCCESS( status )) {

            return status;
        }

        SetFlag( Request->Flags, SAFEUPLOAD_REQUEST_FLAG_PATH_NOT_NORMALIZED );
    }

    copyLength = nameInfo->Name.Length;

    if (copyLength > SAFEUPLOAD_MAX_PATH_BYTES) {

        copyLength = SAFEUPLOAD_MAX_PATH_BYTES;
        SetFlag( Request->Flags, SAFEUPLOAD_REQUEST_FLAG_PATH_TRUNCATED );
    }

    if (copyLength != 0) {

        RtlCopyMemory( Request->Path, nameInfo->Name.Buffer, copyLength );
    }

    Request->PathLength = copyLength;

    //
    //  The reference taken by FltGetFileNameInformation is released on
    //  every path out of this routine, including the truncated one.
    //

    FltReleaseFileNameInformation( nameInfo );

    return STATUS_SUCCESS;
}


static
VOID
SafeUploadCopyRequestImageName (
    _In_ PFLT_CALLBACK_DATA Data,
    _Inout_ PSAFEUPLOAD_REQUEST Request
    )
/*++

Routine Description:

    Copies the file name of the requesting process image into the request,
    for example "notepad.exe".

    Best effort by design: this is context for the operator, not something
    a verdict depends on. Every failure leaves ImageName empty and the
    operation continues.

    IRQL: PASSIVE_LEVEL. SeLocateProcessImageName allocates and may block.

Arguments:

    Data - Parameters of the operation being inspected.

    Request - Request being built. ImageName, ImageNameLength and Flags may
        be updated.

Return Value:

    None.

--*/
{
    PEPROCESS process;
    PUNICODE_STRING imagePath = NULL;
    NTSTATUS status;
    ULONG charCount;
    ULONG index;
    ULONG firstChar;
    ULONG copyLength;

    PAGED_CODE();

    //
    //  FltGetRequestorProcess returns a pointer without taking a reference,
    //  which is safe here because the requesting process cannot go away
    //  while one of its threads is blocked inside this callback.
    //

    process = FltGetRequestorProcess( Data );

    if (process == NULL) {

        return;
    }

    //
    //  SeLocateProcessImageName allocates the string and transfers
    //  ownership to us; it has to be released with ExFreePool. It resolves
    //  the name from the process image section and issues no create of its
    //  own, so it cannot re-enter this filter.
    //

    status = SeLocateProcessImageName( process, &imagePath );

    if (!NT_SUCCESS( status ) || imagePath == NULL) {

        return;
    }

    //
    //  Keep only the last path component.
    //

    charCount = imagePath->Length / sizeof( WCHAR );
    firstChar = 0;

    for (index = 0; index < charCount; index += 1) {

        if (imagePath->Buffer[index] == L'\\') {

            firstChar = index + 1;
        }
    }

    copyLength = (charCount - firstChar) * sizeof( WCHAR );

    if (copyLength > SAFEUPLOAD_MAX_IMAGE_NAME_BYTES) {

        copyLength = SAFEUPLOAD_MAX_IMAGE_NAME_BYTES;
        SetFlag( Request->Flags, SAFEUPLOAD_REQUEST_FLAG_IMAGE_NAME_TRUNCATED );
    }

    if (copyLength != 0) {

        RtlCopyMemory( Request->ImageName,
                       &imagePath->Buffer[firstChar],
                       copyLength );

        Request->ImageNameLength = copyLength;
    }

    ExFreePool( imagePath );
}


static
FLT_PREOP_CALLBACK_STATUS
SafeUploadInspectOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ UINT32 Operation
    )
/*++

Routine Description:

    Builds one request, asks user mode for a verdict and turns the answer
    into a filter manager return code.

    This is the only place in the driver that can deny an operation, and it
    denies only on an explicit DENY from the inspector. Every other outcome
    - no inspector, no memory, no name, no answer, malformed answer - lets
    the operation through (RN-013).

    IRQL: PASSIVE_LEVEL. Guaranteed by the callers.

Arguments:

    Data - Parameters of the operation being inspected.

    Operation - SAFEUPLOAD_OPERATION_CREATE or SAFEUPLOAD_OPERATION_READ.

Return Value:

    FLT_PREOP_COMPLETE with STATUS_ACCESS_DENIED to block the operation,
    FLT_PREOP_SUCCESS_NO_CALLBACK to let it proceed.

--*/
{
    PSAFEUPLOAD_EXCHANGE exchange;
    NTSTATUS status;
    UINT32 verdict = SAFEUPLOAD_VERDICT_ALLOW;

    PAGED_CODE();

    //
    //  Cheap way out before anything is allocated: with no inspector
    //  connected there is nobody to ask.
    //

    if (SafeUploadData.ClientPort == NULL) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    //  ExAllocatePool2 zeroes the block, which is what leaves the inline
    //  strings NUL-terminated and every Reserved field at zero.
    //

    exchange = (PSAFEUPLOAD_EXCHANGE) ExAllocatePool2( POOL_FLAG_NON_PAGED,
                                                       sizeof( SAFEUPLOAD_EXCHANGE ),
                                                       SAFEUPLOAD_POOL_TAG );

    if (exchange == NULL) {

        //
        //  Out of pool. Nothing was allocated, nothing to release, and the
        //  operation is allowed rather than blocked.
        //

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    exchange->Request.Version = SAFEUPLOAD_PROTOCOL_VERSION;
    exchange->Request.StructSize = sizeof( SAFEUPLOAD_REQUEST );
    exchange->Request.RequestId =
        (UINT64) InterlockedIncrement64( &SafeUploadData.NextRequestId );
    exchange->Request.Operation = Operation;
    exchange->Request.RequestorProcessId = FltGetRequestorProcessId( Data );

    status = SafeUploadCopyRequestPath( Data, &exchange->Request );

    if (!NT_SUCCESS( status )) {

        //
        //  Without a path the inspector has nothing to decide on. Allow,
        //  and release the block we own.
        //

        SafeUploadTrace( "no file name for pid %lu, status 0x%08X - allowing\n",
                         exchange->Request.RequestorProcessId,
                         status );

        ExFreePoolWithTag( exchange, SAFEUPLOAD_POOL_TAG );

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    SafeUploadCopyRequestImageName( Data, &exchange->Request );

    (VOID) SafeUploadRequestVerdict( exchange, &verdict );

    ExFreePoolWithTag( exchange, SAFEUPLOAD_POOL_TAG );

    if (verdict == SAFEUPLOAD_VERDICT_DENY) {

        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;

        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


FLT_PREOP_CALLBACK_STATUS
SafeUploadPreCreate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    Pre-operation callback for IRP_MJ_CREATE.

    IRQL: PASSIVE_LEVEL. The filter manager guarantees IRP_MJ_CREATE is
    delivered at PASSIVE_LEVEL in the context of the requesting thread,
    which is why this routine may live in a pageable section and may block
    on a user-mode round trip.

    Note that FltObjects->FileObject is NULL here: in pre-create the file
    object is not yet associated with the instance, so the target has to be
    read from Data->Iopb->TargetFileObject.

Arguments:

    Data - Parameters of the operation.

    FltObjects - Objects affected by the operation.

    CompletionContext - Unused: no post-operation callback is registered.

Return Value:

    FLT_PREOP_SUCCESS_NO_CALLBACK to let the create proceed.

--*/
{
    PFILE_OBJECT targetFileObject;
    PIO_SECURITY_CONTEXT securityContext;

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext = NULL );

    PAGED_CODE();

    targetFileObject = Data->Iopb->TargetFileObject;

    if (targetFileObject == NULL) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    //  Volume opens (opening \Device\HarddiskVolumeN itself). They carry an
    //  empty name and no related file object. There is no file path to hand
    //  to the inspector, and denying one breaks volume management.
    //

    if (targetFileObject->FileName.Length == 0 &&
        targetFileObject->RelatedFileObject == NULL) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    //  Directory opens. FILE_DIRECTORY_FILE lives in the low 24 bits of
    //  Options; the top byte holds the create disposition.
    //

    if (FlagOn( Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE )) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    //  The single most effective gate in the driver.
    //
    //  An operation that does not ask for the file's data cannot leak it,
    //  and the overwhelming majority of creates on a running Windows ask
    //  for nothing more than attributes or metadata - stat calls, directory
    //  enumeration follow-ups, delete checks, sharing probes. All of them
    //  end here, in two bit tests, before any context lookup, any name
    //  resolution and any allocation.
    //

    securityContext = Data->Iopb->Parameters.Create.SecurityContext;

    if (securityContext == NULL ||
        !FlagOn( securityContext->DesiredAccess,
                 FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA )) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (SafeUploadIsIgnoredProcess( FltGetRequestorProcessId( Data ) )) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!SafeUploadMayBeInScope( &targetFileObject->FileName )) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return SafeUploadInspectOperation( Data, SAFEUPLOAD_OPERATION_CREATE );
}
