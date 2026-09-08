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
//  Cumulative since load, never reset. A reader that wants a rate takes two
//  samples and subtracts.
//

SAFEUPLOAD_COUNTERS SafeUploadCounters;

//
//  Local helpers.
//

static
BOOLEAN
SafeUploadIsIgnoredProcess (
    _In_ ULONG ProcessId
    );

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
NTSTATUS
SafeUploadEvaluate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind,
    _Out_ PUINT32 ScopeFlags,
    _Out_ PUINT32 Verdict
    );

static
VOID
SafeUploadReadFileStamp (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PLARGE_INTEGER FileSize,
    _Out_ PLARGE_INTEGER LastWriteTime
    );

static
BOOLEAN
SafeUploadIsMonitoredDestination (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind
    );

static
BOOLEAN
SafeUploadOverrideCovers (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ ULONG ProcessId
    );

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(INIT, DriverEntry)
    #pragma alloc_text(PAGE, SafeUploadUnload)
    #pragma alloc_text(PAGE, SafeUploadInstanceSetup)
    #pragma alloc_text(PAGE, SafeUploadInstanceQueryTeardown)
    #pragma alloc_text(PAGE, SafeUploadPreCreate)
    #pragma alloc_text(PAGE, SafeUploadCopyRequestPath)
    #pragma alloc_text(PAGE, SafeUploadCopyRequestImageName)
    #pragma alloc_text(PAGE, SafeUploadEvaluate)
    #pragma alloc_text(PAGE, SafeUploadReadFileStamp)
    #pragma alloc_text(PAGE, SafeUploadIsMonitoredDestination)
    #pragma alloc_text(PAGE, SafeUploadOverrideCovers)
    #pragma alloc_text(PAGE, SafeUploadPostCreate)
    #pragma alloc_text(PAGE, SafeUploadPreCleanup)
    #pragma alloc_text(PAGE, SafeUploadPreSetInformation)
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

    //
    //  Pre-create runs the cheap gates; post-create is where the verdict is
    //  obtained and cached, because the stream context that holds the cache
    //  does not exist until the create has completed.
    //

    { IRP_MJ_CREATE,
      0,
      SafeUploadPreCreate,
      SafeUploadPostCreate },

    //
    //  Cleanup exists only to invalidate the cached verdict when a handle
    //  that was opened for write closes. Hooking writes instead would cost
    //  a callback per block to learn the same thing.
    //

    { IRP_MJ_CLEANUP,
      0,
      SafeUploadPreCleanup,
      NULL },

    //
    //  Rename and hard link can put content somewhere the create path never
    //  saw it go: write to an ordinary folder, then rename into the
    //  monitored one. Without this the zero-byte refusal has a door beside
    //  it.
    //

    { IRP_MJ_SET_INFORMATION,
      0,
      SafeUploadPreSetInformation,
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

    //
    //  Also before the port: the first thing a client does after connecting
    //  is push a policy.
    //

    SafeUploadInitializePolicy();
    SafeUploadInitializeTaint();
    SafeUploadInitializeOverrides();

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

    //
    //  4. Release the policy. Last, because it can only be freed once no
    //     callback of ours can still be holding the snapshot - which is
    //     exactly what FltUnregisterFilter returning guarantees.
    //

    SafeUploadFreePolicy();
    SafeUploadFreeTaint();
    SafeUploadFreeOverrides();

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

        SafeUploadTrace( "attached to volume, kind %s\n",
                         volumeKind == SafeUploadVolumeRemovable ? "removable" :
                         volumeKind == SafeUploadVolumeNetwork ? "network" : "fixed" );
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
NTSTATUS
SafeUploadEvaluate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind,
    _Out_ PUINT32 ScopeFlags,
    _Out_ PUINT32 Verdict
    )
/*++

Routine Description:

    Works out whether an operation is in scope and, if it is, asks user mode
    for a verdict.

    This is the expensive path: it resolves a name, may resolve a process
    image, and may block on a round trip. Everything above it exists to keep
    operations from reaching it, and the stream context exists to keep the
    same file from reaching it twice.

    IRQL: PASSIVE_LEVEL.

Arguments:

    Data - Parameters of the operation.

    VolumeKind - Classification of the volume, from the instance context.

    ScopeFlags - Receives SAFEUPLOAD_REQUEST_FLAG_SCOPE_*, or zero when the
        operation is out of scope. Zero is a useful answer worth caching: it
        means this file never has to be evaluated again.

    Verdict - Receives SAFEUPLOAD_VERDICT_*. Always set to ALLOW before
        anything can fail, so no error path leaves it undefined (RN-013).

Return Value:

    STATUS_SUCCESS when an answer was obtained, otherwise the failing
    status. Either way Verdict is meaningful.

--*/
{
    PSAFEUPLOAD_EXCHANGE exchange;
    UNICODE_STRING normalizedPath;
    UNICODE_STRING imageName;
    NTSTATUS status;

    PAGED_CODE();

    *ScopeFlags = 0;
    *Verdict = SAFEUPLOAD_VERDICT_ALLOW;

    exchange = (PSAFEUPLOAD_EXCHANGE) ExAllocatePool2( POOL_FLAG_NON_PAGED,
                                                       sizeof( SAFEUPLOAD_EXCHANGE ),
                                                       SAFEUPLOAD_POOL_TAG );

    if (exchange == NULL) {

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    exchange->Request.Version = SAFEUPLOAD_PROTOCOL_VERSION;
    exchange->Request.StructSize = sizeof( SAFEUPLOAD_REQUEST );
    exchange->Request.RequestId =
        (UINT64) InterlockedIncrement64( &SafeUploadData.NextRequestId );
    exchange->Request.Operation = SAFEUPLOAD_OPERATION_CREATE;
    exchange->Request.RequestorProcessId = FltGetRequestorProcessId( Data );

    status = SafeUploadCopyRequestPath( Data, &exchange->Request );

    if (!NT_SUCCESS( status )) {

        ExFreePoolWithTag( exchange, SAFEUPLOAD_POOL_TAG );
        return status;
    }

    SafeUploadCount( ScopeEvaluations );

    normalizedPath.Buffer = exchange->Request.Path;
    normalizedPath.Length = (USHORT) exchange->Request.PathLength;
    normalizedPath.MaximumLength = normalizedPath.Length;

    if (SafeUploadPolicyMatchesDestination( VolumeKind, &normalizedPath )) {

        SetFlag( exchange->Request.Flags, SAFEUPLOAD_REQUEST_FLAG_SCOPE_DESTINATION );
    }

    if (SafeUploadPolicyMatchesSource( &normalizedPath )) {

        SetFlag( exchange->Request.Flags, SAFEUPLOAD_REQUEST_FLAG_SCOPE_SOURCE );
    }

    *ScopeFlags = exchange->Request.Flags &
                  (SAFEUPLOAD_REQUEST_FLAG_SCOPE_DESTINATION |
                   SAFEUPLOAD_REQUEST_FLAG_SCOPE_SOURCE);

    if (*ScopeFlags == 0) {

        ExFreePoolWithTag( exchange, SAFEUPLOAD_POOL_TAG );
        return STATUS_SUCCESS;
    }

    SafeUploadCopyRequestImageName( Data, &exchange->Request );

    //
    //  RN-014. Checked here rather than earlier because the image name is
    //  only known once it has been resolved.
    //

    if (exchange->Request.ImageNameLength != 0) {

        imageName.Buffer = exchange->Request.ImageName;
        imageName.Length = (USHORT) exchange->Request.ImageNameLength;
        imageName.MaximumLength = imageName.Length;

        if (SafeUploadPolicyExcludesImage( &imageName )) {

            *ScopeFlags = 0;
            ExFreePoolWithTag( exchange, SAFEUPLOAD_POOL_TAG );
            return STATUS_SUCCESS;
        }
    }

    SafeUploadCount( UserModeRoundTrips );

    status = SafeUploadRequestVerdict( exchange, Verdict );

    if (!NT_SUCCESS( status )) {

        SafeUploadCount( AllowedWithoutInspection );
    }

    ExFreePoolWithTag( exchange, SAFEUPLOAD_POOL_TAG );

    return status;
}


static
VOID
SafeUploadReadFileStamp (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PLARGE_INTEGER FileSize,
    _Out_ PLARGE_INTEGER LastWriteTime
    )
/*++

Routine Description:

    Reads the size and last write time of the file behind a completed
    create, to stamp a cached verdict with.

    The stamp is what makes the cache safe against changes this driver never
    observed - a volume modified while the filter was unloaded, for
    instance. The Dirty flag covers the changes it did observe.

    IRQL: PASSIVE_LEVEL.

Arguments:

    FltObjects - Objects for the create that just completed.

    FileSize, LastWriteTime - Receive the stamp, or zero when it could not
        be read. Zero simply means the cached entry will never match, which
        costs an inspection and is never wrong.

Return Value:

    None.

--*/
{
    FILE_NETWORK_OPEN_INFORMATION information;
    NTSTATUS status;

    PAGED_CODE();

    FileSize->QuadPart = 0;
    LastWriteTime->QuadPart = 0;

    status = FltQueryInformationFile( FltObjects->Instance,
                                      FltObjects->FileObject,
                                      &information,
                                      sizeof( information ),
                                      FileNetworkOpenInformation,
                                      NULL );

    if (NT_SUCCESS( status )) {

        *FileSize = information.EndOfFile;
        *LastWriteTime = information.LastWriteTime;
    }
}


static
BOOLEAN
SafeUploadOverrideCovers (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ ULONG ProcessId
    )
/*++

Routine Description:

    Whether a user-granted exception covers this create.

    Resolves the opened name a second time, and that is deliberate: this
    runs only on the path that is about to refuse, which is rare. Threading
    the name through the cheap gates would put the cost on every operation
    to save it on almost none.

    IRQL: PASSIVE_LEVEL.

Return Value:

    TRUE when an exception covered the operation - and it is consumed.

--*/
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    BOOLEAN covered;
    NTSTATUS status;

    PAGED_CODE();

    if (!SafeUploadPolicyAllowsOverride()) {

        return FALSE;
    }

    status = FltGetFileNameInformation( Data,
                                        FLT_FILE_NAME_OPENED |
                                            FLT_FILE_NAME_QUERY_DEFAULT,
                                        &nameInfo );

    if (!NT_SUCCESS( status )) {

        return FALSE;
    }

    covered = SafeUploadConsumeOverride( ProcessId, &nameInfo->Name );

    FltReleaseFileNameInformation( nameInfo );

    return covered;
}


static
BOOLEAN
SafeUploadIsMonitoredDestination (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind
    )
/*++

Routine Description:

    Whether a create is heading for a monitored destination, answered as
    cheaply as the policy allows.

    Removable media and network shares are settled by the volume kind alone,
    with no name at all - which is the case that matters most, because a pen
    drive is where a refusal has to leave nothing behind.

    Only a fixed volume needs a name, and only then is one resolved. The
    caller checks process taint first precisely so that this cost is paid
    for tainted processes, which are rare, rather than for every write.

    The opened name is used rather than the normalized one: normalization
    can fail in pre-create, and the filter manager returns opened names in
    device form (\Device\HarddiskVolumeN\...), which is what the policy
    prefixes are written in. A short name that fails to match means an
    operation goes uninspected, never wrongly refused.

    IRQL: PASSIVE_LEVEL.

Arguments:

    Data - Parameters of the create.

    VolumeKind - Classification from the instance context.

Return Value:

    TRUE when the destination is monitored.

--*/
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    BOOLEAN monitored;
    NTSTATUS status;

    PAGED_CODE();

    if (SafeUploadPolicyMatchesDestination( VolumeKind, NULL )) {

        return TRUE;
    }

    status = FltGetFileNameInformation( Data,
                                        FLT_FILE_NAME_OPENED |
                                            FLT_FILE_NAME_QUERY_DEFAULT,
                                        &nameInfo );

    if (!NT_SUCCESS( status )) {

        return FALSE;
    }

    monitored = SafeUploadPolicyMatchesDestination( VolumeKind, &nameInfo->Name );

    FltReleaseFileNameInformation( nameInfo );

    return monitored;
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

    This routine no longer decides anything. It runs the gates that cost
    nothing but comparisons and, for what survives them, asks for a
    post-operation callback - because the stream context that caches
    verdicts does not exist until the create has completed, and a cache that
    cannot be consulted is not a cache.

    IRQL: PASSIVE_LEVEL, guaranteed by the filter manager for IRP_MJ_CREATE,
    which is why this may live in a pageable section.

    FltObjects->FileObject is NULL here: in pre-create the file object is
    not yet associated with the instance, so the target has to be read from
    Data->Iopb->TargetFileObject.

Arguments:

    Data - Parameters of the operation.

    FltObjects - Objects affected by the operation.

    CompletionContext - Receives the volume classification, so post-create
        does not have to look the instance context up again.

Return Value:

    FLT_PREOP_SUCCESS_WITH_CALLBACK when the operation deserves a closer
    look, FLT_PREOP_SUCCESS_NO_CALLBACK otherwise.

--*/
{
    PFILE_OBJECT targetFileObject;
    PIO_SECURITY_CONTEXT securityContext;
    PSAFEUPLOAD_INSTANCE_CONTEXT instanceContext = NULL;
    SAFEUPLOAD_VOLUME_KIND volumeKind;
    NTSTATUS status;

    *CompletionContext = NULL;

    PAGED_CODE();

    SafeUploadCount( CreatesSeen );

    //
    //  With no inspector connected there is nobody to ask, and no answer to
    //  cache.
    //

    if (SafeUploadData.ClientPort == NULL) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

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
    //  and the overwhelming majority of creates on a running Windows ask for
    //  nothing more than attributes or metadata - stat calls, directory
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

    if (!SafeUploadPolicyMatchesExtension( &targetFileObject->FileName )) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    //  The volume kind was worked out once, when this instance attached.
    //  Reading it back is a context lookup; recomputing it would be a
    //  FltGetVolumeProperties call on every create.
    //

    status = FltGetInstanceContext( FltObjects->Instance,
                                    (PFLT_CONTEXT *) &instanceContext );

    if (!NT_SUCCESS( status )) {

        //
        //  Without the classification there is no way to tell a pen drive
        //  from a system disk, and guessing is worse than not inspecting.
        //

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    volumeKind = instanceContext->VolumeKind;
    FltReleaseContext( instanceContext );

    SafeUploadCount( CreatesPastCheapGates );

    //
    //  The zero-byte refusal.
    //
    //  A process that has handled sensitive content may not open a
    //  monitored destination for writing. This is decided here, in
    //  pre-create, and it asks user mode nothing: the expensive question
    //  was answered when the source was opened, and its answer is a hash
    //  lookup away. Refusing here means the create never happens - no file
    //  created, nothing truncated, nothing left behind.
    //
    //  Taint is checked before the destination, and the order is the point:
    //  the taint lookup costs nothing, while deciding whether a fixed
    //  volume path is monitored may cost a name resolution. Paying that
    //  only for tainted processes keeps it off the common path.
    //

    if (FlagOn( securityContext->DesiredAccess,
                FILE_WRITE_DATA | FILE_APPEND_DATA ) &&
        SafeUploadIsProcessTainted( FltGetRequestorProcessId( Data ) ) &&
        SafeUploadIsMonitoredDestination( Data, volumeKind )) {

        //
        //  Em modo auditoria a escrita segue, contada como o que teria
        //  sido negado. E o unico jeito de conhecer o custo do bloqueio
        //  antes de liga-lo, que e como todo DLP de mercado e implantado.
        //

        //
        //  Excecao antes de negar, e so aqui: este e o caminho frio, o unico
        //  que ja decidiu recusar.
        //

        if (SafeUploadOverrideCovers( Data, FltGetRequestorProcessId( Data ) )) {

            *CompletionContext = (PVOID) (ULONG_PTR) volumeKind;

            return FLT_PREOP_SUCCESS_WITH_CALLBACK;
        }

        if (SafeUploadPolicyAuditOnly()) {

            SafeUploadCount( WouldHaveDenied );

            SafeUploadTrace( "AUDITORIA: escrita seria negada, processo %lu marcado\n",
                             FltGetRequestorProcessId( Data ) );

        } else {

            SafeUploadCount( DeniedPreCreate );

            SafeUploadTrace( "escrita negada: processo %lu marcado\n",
                             FltGetRequestorProcessId( Data ) );

            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;

            return FLT_PREOP_COMPLETE;
        }
    }

    *CompletionContext = (PVOID) (ULONG_PTR) volumeKind;

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}


FLT_POSTOP_CALLBACK_STATUS
SafeUploadPostCreate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
/*++

Routine Description:

    Post-operation callback for IRP_MJ_CREATE, and the only place that asks
    user mode anything.

    Here the file exists, the stream context is available, and a verdict can
    be cached against the file rather than recomputed per open. That cache is
    the property the whole design rests on: one round trip per file version,
    not one per operation and not one per handle.

    Denial here is FltCancelFileOpen rather than a failed pre-operation. The
    create has already succeeded, so undoing it is the only way to refuse -
    which is what the WDK scanner sample does, for the same reason.

    IRQL: PASSIVE_LEVEL for IRP_MJ_CREATE.

Arguments:

    Data - Parameters of the operation.

    FltObjects - Objects affected by the operation.

    CompletionContext - The volume classification, from pre-create.

    Flags - FLTFL_POST_OPERATION_DRAINING when the filter is being torn
        down.

Return Value:

    FLT_POSTOP_FINISHED_PROCESSING.

--*/
{
    PSAFEUPLOAD_STREAM_CONTEXT streamContext = NULL;
    SAFEUPLOAD_VOLUME_KIND volumeKind;
    LARGE_INTEGER fileSize;
    LARGE_INTEGER lastWriteTime;
    UINT32 scopeFlags = 0;
    UINT32 verdict = SAFEUPLOAD_VERDICT_ALLOW;
    BOOLEAN answered = FALSE;
    NTSTATUS status;

    PAGED_CODE();

    volumeKind = (SAFEUPLOAD_VOLUME_KIND) (ULONG_PTR) CompletionContext;

    //
    //  Draining means the filter is going away, and no callback of ours
    //  should start new work.
    //

    if (FlagOn( Flags, FLTFL_POST_OPERATION_DRAINING )) {

        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    //  A create that failed anyway has nothing to arbitrate, and a reparse
    //  comes back around as another create.
    //

    if (!NT_SUCCESS( Data->IoStatus.Status ) ||
        Data->IoStatus.Status == STATUS_REPARSE) {

        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    SafeUploadReadFileStamp( FltObjects, &fileSize, &lastWriteTime );

    status = SafeUploadGetOrCreateStreamContext( FltObjects,
                                                 FltObjects->FileObject,
                                                 &streamContext );

    if (NT_SUCCESS( status )) {

        FltAcquirePushLockShared( &streamContext->Lock );

        if (streamContext->ScopeEvaluated) {

            if (streamContext->ScopeFlags == 0) {

                //
                //  Known to be out of scope. This is the entry that pays for
                //  itself the most: it skips a name resolution on every
                //  later open of a file the policy does not care about.
                //

                scopeFlags = 0;
                answered = TRUE;
                SafeUploadCount( CacheHits );

            } else if (streamContext->VerdictValid &&
                       !streamContext->Dirty &&
                       streamContext->FileSize.QuadPart == fileSize.QuadPart &&
                       streamContext->LastWriteTime.QuadPart == lastWriteTime.QuadPart) {

                scopeFlags = streamContext->ScopeFlags;
                verdict = streamContext->Verdict;
                answered = TRUE;
                SafeUploadCount( CacheHits );
            }
        }

        FltReleasePushLock( &streamContext->Lock );
    }

    if (!answered) {

        (VOID) SafeUploadEvaluate( Data, volumeKind, &scopeFlags, &verdict );

        if (streamContext != NULL) {

            FltAcquirePushLockExclusive( &streamContext->Lock );

            streamContext->ScopeEvaluated = TRUE;
            streamContext->ScopeFlags = scopeFlags;
            streamContext->Verdict = verdict;
            streamContext->VerdictValid = (BOOLEAN) (scopeFlags != 0);
            streamContext->Dirty = FALSE;
            streamContext->FileSize = fileSize;
            streamContext->LastWriteTime = lastWriteTime;

            FltReleasePushLock( &streamContext->Lock );
        }
    }

    if (streamContext != NULL) {

        FltReleaseContext( streamContext );
    }

    if (scopeFlags == 0) {

        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    //  A handle opened for write invalidates the cached verdict when it
    //  closes, because the content may have changed underneath us.
    //

    if (FltObjects->FileObject->WriteAccess) {

        (VOID) SafeUploadMarkHandleForWrite( FltObjects );
    }

    if (verdict == SAFEUPLOAD_VERDICT_DENY) {

        //
        //  Sensitive content reached this process. The read itself is
        //  allowed - the user has every right to open their own document -
        //  and what is recorded is that this process now carries it.
        //

        if (FlagOn( scopeFlags, SAFEUPLOAD_REQUEST_FLAG_SCOPE_SOURCE )) {

            SafeUploadTaintProcess( FltGetRequestorProcessId( Data ), 1 );
        }

        //
        //  A file already on its way out is refused outright. This is the
        //  weaker refusal of the two: FltCancelFileOpen undoes the open, so
        //  no content is ever readable, but it does not undo whatever the
        //  create itself did - a file may have been created or truncated
        //  before this callback ran. The strong refusal is the pre-create
        //  one above.
        //

        if (FlagOn( scopeFlags, SAFEUPLOAD_REQUEST_FLAG_SCOPE_DESTINATION )) {

            //
            //  Excecao antes de cancelar, pelo mesmo motivo do pre-create:
            //  este e o caminho que ja decidiu recusar.
            //

            if (SafeUploadOverrideCovers( Data, FltGetRequestorProcessId( Data ) )) {

                return FLT_POSTOP_FINISHED_PROCESSING;
            }

            if (SafeUploadPolicyAuditOnly()) {

                SafeUploadCount( WouldHaveDenied );

            } else {

                SafeUploadCount( DeniedPostCreate );

                FltCancelFileOpen( FltObjects->Instance, FltObjects->FileObject );

                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                Data->IoStatus.Information = 0;
            }
        }
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
SafeUploadPreCleanup (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    Pre-operation callback for IRP_MJ_CLEANUP: the last handle to a file
    object is being closed.

    Its only job is to throw away the cached verdict when the handle that is
    closing was opened for write. Cleanup is the right moment because it is
    when the writing is finished; a write callback would fire once per block
    to learn the same thing.

    Cleanup cannot be failed - the filter manager ignores the return value -
    so nothing here tries to.

    IRQL: PASSIVE_LEVEL.

Arguments:

    Data - Parameters of the operation.

    FltObjects - Objects affected by the operation.

    CompletionContext - Unused.

Return Value:

    FLT_PREOP_SUCCESS_NO_CALLBACK.

--*/
{
    PSAFEUPLOAD_STREAM_CONTEXT streamContext = NULL;
    NTSTATUS status;

    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( CompletionContext = NULL );

    PAGED_CODE();

    if (!SafeUploadHandleWasOpenedForWrite( FltObjects )) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetStreamContext( FltObjects->Instance,
                                  FltObjects->FileObject,
                                  (PFLT_CONTEXT *) &streamContext );

    if (!NT_SUCCESS( status )) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FltAcquirePushLockExclusive( &streamContext->Lock );

    streamContext->Dirty = TRUE;

    FltReleasePushLock( &streamContext->Lock );

    FltReleaseContext( streamContext );

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


FLT_PREOP_CALLBACK_STATUS
SafeUploadPreSetInformation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    Pre-operation callback for IRP_MJ_SET_INFORMATION, registered for one
    reason: rename and hard link can put a file somewhere the create path
    never saw it go.

    The bypass this closes is concrete. A tainted process cannot create a
    file for writing inside a monitored cloud folder - pre-create refuses
    it. But it can write the same content to an ordinary folder on the same
    volume, which nothing objects to, and then rename it into the monitored
    folder. The file arrives complete, and without this callback nothing
    would have been asked.

    A hard link is the same bypass wearing a different name: it makes the
    content reachable through a path inside the monitored destination
    without moving or copying anything.

    Deletion is deliberately not intercepted. Removing a file is not a way
    to get data out of the machine, and refusing deletes would break far
    more than it protects.

    IRQL: PASSIVE_LEVEL.

Arguments:

    Data - Parameters of the operation.

    FltObjects - Objects affected by the operation.

    CompletionContext - Unused: no post-operation callback is registered.

Return Value:

    FLT_PREOP_COMPLETE with STATUS_ACCESS_DENIED when a tainted process is
    moving content into a monitored destination, FLT_PREOP_SUCCESS_NO_CALLBACK
    otherwise.

--*/
{
    FILE_INFORMATION_CLASS informationClass;
    PFILE_RENAME_INFORMATION renameInformation;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PSAFEUPLOAD_INSTANCE_CONTEXT instanceContext = NULL;
    SAFEUPLOAD_VOLUME_KIND volumeKind;
    ULONG processId;
    BOOLEAN monitored = FALSE;
    BOOLEAN isLink;
    NTSTATUS status;

    UNREFERENCED_PARAMETER( CompletionContext = NULL );

    PAGED_CODE();

    SafeUploadCount( SetInformationSeen );

    informationClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    //
    //  Record the class before any gate rejects it. Which classes arrive
    //  is exactly what cannot be deduced from the outside, and guessing it
    //  has already cost two deploy-and-test cycles.
    //

    if ((ULONG) informationClass < 64) {

        InterlockedOr64( (volatile LONG64 *) &SafeUploadCounters.ClassesSeenLow,
                         1ULL << (ULONG) informationClass );

    } else if ((ULONG) informationClass < 128) {

        InterlockedOr64( (volatile LONG64 *) &SafeUploadCounters.ClassesSeenHigh,
                         1ULL << ((ULONG) informationClass - 64) );
    }

    //
    //  The cheapest gate available: IRP_MJ_SET_INFORMATION carries dozens of
    //  classes - timestamps, attributes, allocation size, end of file - and
    //  only these four move content to a new path. One comparison rejects
    //  everything else.
    //

    if (informationClass != FileRenameInformation &&
        informationClass != FileRenameInformationEx &&
        informationClass != FileLinkInformation &&
        informationClass != FileLinkInformationEx) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (SafeUploadData.ClientPort == NULL) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    isLink = (BOOLEAN) (informationClass == FileLinkInformation ||
                        informationClass == FileLinkInformationEx);

    if (isLink) {
        SafeUploadCount( LinksSeen );
    } else {
        SafeUploadCount( RenamesSeen );
    }

    processId = FltGetRequestorProcessId( Data );

    if (SafeUploadIsIgnoredProcess( processId )) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    //  Taint before destination, for the same reason as in pre-create:
    //  resolving the destination name is the expensive part, and only a
    //  tainted process can be refused, so only a tainted process should pay
    //  for it.
    //

    if (!SafeUploadIsProcessTainted( processId )) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (isLink) {
        SafeUploadCount( LinksFromTainted );
    } else {
        SafeUploadCount( RenamesFromTainted );
    }

    status = FltGetInstanceContext( FltObjects->Instance,
                                    (PFLT_CONTEXT *) &instanceContext );

    if (!NT_SUCCESS( status )) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    volumeKind = instanceContext->VolumeKind;
    FltReleaseContext( instanceContext );

    //
    //  FILE_LINK_INFORMATION shares its leading layout with
    //  FILE_RENAME_INFORMATION - root directory, name length, name - so one
    //  cast serves both.
    //
    //  The name that matters is the DESTINATION, not the file being
    //  renamed, and it may be relative to a root directory handle.
    //  FltGetDestinationFileNameInformation exists precisely to resolve
    //  that pair into a full path.
    //

    renameInformation =
        (PFILE_RENAME_INFORMATION) Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

    if (renameInformation == NULL) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetDestinationFileNameInformation( FltObjects->Instance,
                                                   FltObjects->FileObject,
                                                   renameInformation->RootDirectory,
                                                   renameInformation->FileName,
                                                   renameInformation->FileNameLength,
                                                   FLT_FILE_NAME_OPENED |
                                                       FLT_FILE_NAME_QUERY_DEFAULT,
                                                   &nameInfo );

    if (NT_SUCCESS( status )) {

        monitored = SafeUploadPolicyMatchesDestination( volumeKind, &nameInfo->Name );

        FltReleaseFileNameInformation( nameInfo );
    }

    if (!monitored) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (SafeUploadPolicyAuditOnly()) {

        SafeUploadCount( WouldHaveDenied );

        SafeUploadTrace( "AUDITORIA: rename seria negado, processo %lu marcado\n", processId );

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    SafeUploadCount( DeniedRename );

    SafeUploadTrace( "rename negado: processo %lu marcado\n", processId );

    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;

    return FLT_PREOP_COMPLETE;
}
