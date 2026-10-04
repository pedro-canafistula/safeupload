/*++

Module Name:

    Context.c

Abstract:

    Filter manager contexts used by the SafeUpload minifilter.

    Both contexts exist for the same reason: to keep the hot path out of
    user mode. A minifilter sees thousands of operations per second on an
    idle machine, so any question that can be answered once and remembered
    must be.

    - The instance context answers "what kind of volume is this?" once, at
      attach time, instead of once per operation.

    - The stream context answers "is this file sensitive?" once per file
      version, instead of once per operation or even once per handle. It
      belongs to the file, so it outlives the handle that created it and
      serves every process that opens the same file afterwards.

Environment:

    Kernel mode

--*/

#include "Filter.h"

C_ASSERT(FLTFL_INSTANCE_SETUP_NEWLY_MOUNTED_VOLUME ==
    SAFEUPLOAD_SETUP_FLAG_NEWLY_MOUNTED_VOLUME);
#if SAFEUPLOAD_STAGING_PROTOTYPE
#include "Stage.h"
#endif

static
VOID
SafeUploadStreamContextCleanup (
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
    );

#if SAFEUPLOAD_STAGING_PROTOTYPE
#define SAFEUPLOAD_TEARDOWN_TOKEN_POOL_TAG 'tUAS'

static VOID SafeUploadReleaseTeardownToken(
    _Inout_opt_ PSAFEUPLOAD_INSTANCE_TEARDOWN_TOKEN Token)
{
    if (Token != NULL && InterlockedDecrement(&Token->ReferenceCount) == 0) {
        ExFreePoolWithTag(Token, SAFEUPLOAD_TEARDOWN_TOKEN_POOL_TAG);
    }
}

static VOID SafeUploadInstanceContextCleanup(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType)
{
    PSAFEUPLOAD_INSTANCE_CONTEXT instanceContext = (PSAFEUPLOAD_INSTANCE_CONTEXT)Context;

    UNREFERENCED_PARAMETER(ContextType);
    FLT_ASSERT(ContextType == FLT_INSTANCE_CONTEXT);

    if (instanceContext->TeardownToken != NULL) {
        SafeUploadStageWritersInstanceContextFreed(
            instanceContext->TeardownToken,
            (BOOLEAN)(InterlockedCompareExchange(&instanceContext->TeardownToken->Published, 0, 0) != 0));
        SafeUploadReleaseTeardownToken(instanceContext->TeardownToken);
        instanceContext->TeardownToken = NULL;
    }
}
#endif

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(PAGE, SafeUploadClassifyVolume)
    #pragma alloc_text(PAGE, SafeUploadSetInstanceContext)
    #pragma alloc_text(PAGE, SafeUploadInstanceIsTrusted)
    #pragma alloc_text(PAGE, SafeUploadInstanceTrustGateSatisfied)
    #pragma alloc_text(PAGE, SafeUploadGetOrCreateStreamContext)
    #pragma alloc_text(PAGE, SafeUploadMarkHandleForWrite)
#endif

///////////////////////////////////////////////////////////////////////////
//
//  Registration.
//
///////////////////////////////////////////////////////////////////////////

#if SAFEUPLOAD_STAGING_PROTOTYPE
static VOID SafeUploadHandleContextCleanup(_In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType)
{
    PSAFEUPLOAD_STREAMHANDLE_CONTEXT handle = (PSAFEUPLOAD_STREAMHANDLE_CONTEXT) Context;
    UNREFERENCED_PARAMETER( ContextType );
    SafeUploadFreeDirectoryView( handle->DirectoryView );
    FltDeletePushLock( &handle->DirectoryLock );
}
#endif

CONST FLT_CONTEXT_REGISTRATION SafeUploadContextRegistration[] = {

    //
    //  The prototype instance context owns a reference to its teardown token.
    //

    { FLT_INSTANCE_CONTEXT,
      0,
#if SAFEUPLOAD_STAGING_PROTOTYPE
      SafeUploadInstanceContextCleanup,
#else
      NULL,
#endif
      sizeof( SAFEUPLOAD_INSTANCE_CONTEXT ),
      SAFEUPLOAD_POOL_TAG },

    //
    //  The stream context owns a push lock, which has to be torn down
    //  before the filter manager releases the memory.
    //

    { FLT_STREAM_CONTEXT,
      0,
      SafeUploadStreamContextCleanup,
      sizeof( SAFEUPLOAD_STREAM_CONTEXT ),
      SAFEUPLOAD_POOL_TAG },

    //
    //  Per handle, and owning nothing: no cleanup callback needed.
    //

    { FLT_STREAMHANDLE_CONTEXT,
      0,
#if SAFEUPLOAD_STAGING_PROTOTYPE
      SafeUploadHandleContextCleanup,
#else
      NULL,
#endif
      sizeof( SAFEUPLOAD_STREAMHANDLE_CONTEXT ),
      SAFEUPLOAD_POOL_TAG },

    { FLT_CONTEXT_END }
};


static
VOID
SafeUploadStreamContextCleanup (
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType
    )
/*++

Routine Description:

    Called by the filter manager when the last reference to a stream
    context goes away, before the memory is released.

    IRQL: <= APC_LEVEL. Deliberately does nothing that could block.

Arguments:

    Context - The context being torn down.

    ContextType - Which kind of context it is.

Return Value:

    None.

--*/
{
    PSAFEUPLOAD_STREAM_CONTEXT streamContext = (PSAFEUPLOAD_STREAM_CONTEXT) Context;

    UNREFERENCED_PARAMETER( ContextType );

    FLT_ASSERT( ContextType == FLT_STREAM_CONTEXT );

#if SAFEUPLOAD_STAGING_PROTOTYPE
    SafeUploadStageWritersFreeContext( streamContext );
    SafeUploadReleaseTeardownToken(streamContext->TeardownToken);
    streamContext->TeardownToken = NULL;
#endif

    FltDeletePushLock( &streamContext->Lock );
}

///////////////////////////////////////////////////////////////////////////
//
//  Instance context.
//
///////////////////////////////////////////////////////////////////////////

SAFEUPLOAD_VOLUME_KIND
SafeUploadClassifyVolume (
    _In_ PFLT_VOLUME Volume,
    _In_ DEVICE_TYPE VolumeDeviceType
    )
/*++

Routine Description:

    Works out what kind of volume an instance is attaching to.

    This is the whole reason the instance context exists. Asking the same
    question on every create would mean a FltGetVolumeProperties call in
    the hot path; asking it once at attach time makes the answer a field
    read.

    IRQL: PASSIVE_LEVEL. FltGetVolumeProperties may issue I/O.

Arguments:

    Volume - The volume being classified.

    VolumeDeviceType - DEVICE_TYPE reported for the volume, as handed to
        InstanceSetup.

Return Value:

    The classification. SafeUploadVolumeUnknown when it could not be
    determined.

--*/
{
    FLT_VOLUME_PROPERTIES properties;
    ULONG returnedLength;
    NTSTATUS status;

    PAGED_CODE();

    //
    //  Network redirectors announce themselves through the device type and
    //  have no meaningful removable-media characteristic.
    //

    if (VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM) {

        return SafeUploadVolumeNetwork;
    }

    status = FltGetVolumeProperties( Volume,
                                     &properties,
                                     sizeof( properties ),
                                     &returnedLength );

    //
    //  STATUS_BUFFER_OVERFLOW is the normal outcome here: the properties
    //  structure is followed by name buffers we did not provide room for
    //  and do not want. The fixed part is filled in either way, so this
    //  tests for NT_ERROR rather than !NT_SUCCESS - the latter would
    //  discard a perfectly good answer.
    //

    if (NT_ERROR( status )) {

        SafeUploadTrace( "FltGetVolumeProperties failed, status 0x%08X\n", status );
        return SafeUploadVolumeUnknown;
    }

    if (FlagOn( properties.DeviceCharacteristics, FILE_REMOVABLE_MEDIA )) {

        return SafeUploadVolumeRemovable;
    }

    return SafeUploadVolumeFixed;
}


NTSTATUS
SafeUploadSetInstanceContext (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_INSTANCE_SETUP_FLAGS SetupFlags,
    _Out_ PSAFEUPLOAD_VOLUME_KIND VolumeKind
    )
/*++

Routine Description:

    Classifies the volume and attaches the result to the instance.

    IRQL: PASSIVE_LEVEL. Called from InstanceSetup.

Arguments:

    FltObjects - The instance and volume being set up.

    VolumeDeviceType - DEVICE_TYPE reported for the volume.

    VolumeKind - Receives the classification, so the caller can trace it
        without reading the context back.

Return Value:

    STATUS_SUCCESS when the context is in place. On failure nothing is left
    allocated. The feature build may retain attachment and use its conservative
    Unknown-volume fallback; the normal build retains its prior behavior.

--*/
{
    PSAFEUPLOAD_INSTANCE_CONTEXT instanceContext = NULL;
    NTSTATUS status;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    PSAFEUPLOAD_INSTANCE_TEARDOWN_TOKEN teardownToken = NULL;
    UNICODE_STRING volumeGuid;
#endif

    PAGED_CODE();

    *VolumeKind = SafeUploadVolumeUnknown;

    status = FltAllocateContext( FltObjects->Filter,
                                 FLT_INSTANCE_CONTEXT,
                                 sizeof( SAFEUPLOAD_INSTANCE_CONTEXT ),
                                 NonPagedPool,
                                 (PFLT_CONTEXT *) &instanceContext );

    if (!NT_SUCCESS( status )) {

        return status;
    }

    //
    //  FltAllocateContext does not zero what it hands back.
    //

    RtlZeroMemory( instanceContext, sizeof( *instanceContext ) );
    instanceContext->SetupFlags = SetupFlags;
    instanceContext->TrustState = FlagOn(SetupFlags, FLTFL_INSTANCE_SETUP_NEWLY_MOUNTED_VOLUME) ?
        SAFEUPLOAD_VOLUME_TRUST_NEWLY_MOUNTED : SAFEUPLOAD_VOLUME_TRUST_UNTRUSTED_FLAGS;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    teardownToken = (PSAFEUPLOAD_INSTANCE_TEARDOWN_TOKEN)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(*teardownToken), SAFEUPLOAD_TEARDOWN_TOKEN_POOL_TAG);
    if (teardownToken == NULL) {
        FltReleaseContext(instanceContext);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(teardownToken, sizeof(*teardownToken));
    teardownToken->ReferenceCount = 1; /* Owned by this instance context. */
    teardownToken->State = SAFEUPLOAD_INSTANCE_STATE_ACTIVE;
    instanceContext->TeardownToken = teardownToken;
#endif
    instanceContext->VolumeKind = SafeUploadClassifyVolume( FltObjects->Volume,
                                                            VolumeDeviceType );
#if SAFEUPLOAD_STAGING_PROTOTYPE
    instanceContext->CanaryStatus = STATUS_PENDING;
    instanceContext->CanaryCleanupStatus = STATUS_PENDING;
    instanceContext->FileSystemStatus = FltGetFileSystemType(FltObjects->Instance,
        &instanceContext->FileSystemType);
    volumeGuid.Buffer = instanceContext->VolumeGuid;
    volumeGuid.Length = 0;
    volumeGuid.MaximumLength = sizeof(instanceContext->VolumeGuid) - sizeof(WCHAR);
    /* On supported Windows versions this is safe in InstanceSetup, after mount processing.
     * Keep the GUID rather than a drive letter or transient HarddiskVolume number. */
    instanceContext->VolumeGuidStatus = FltGetVolumeGuidName(FltObjects->Volume, &volumeGuid, NULL);
    if (instanceContext->VolumeGuidStatus == STATUS_SUCCESS) {
        if (volumeGuid.Length == 0 || volumeGuid.Length > volumeGuid.MaximumLength ||
            (volumeGuid.Length % sizeof(WCHAR)) != 0) {
            instanceContext->VolumeGuidStatus = STATUS_INVALID_BUFFER_SIZE;
        } else {
            instanceContext->VolumeGuidChars = volumeGuid.Length / sizeof(WCHAR);
        }
    }
    if (instanceContext->VolumeGuidStatus != STATUS_SUCCESS)
        RtlZeroMemory(instanceContext->VolumeGuid, sizeof(instanceContext->VolumeGuid));
#endif

    status = FltSetInstanceContext( FltObjects->Instance,
                                    FLT_SET_CONTEXT_KEEP_IF_EXISTS,
                                    instanceContext,
                                    NULL );

    if (NT_SUCCESS( status )) {

        *VolumeKind = instanceContext->VolumeKind;
#if SAFEUPLOAD_STAGING_PROTOTYPE
        InterlockedExchange(&teardownToken->Published, 1);
#endif
    }

    //
    //  Released on both paths: on success the instance holds its own
    //  reference, and on failure this was the only one.
    //

    FltReleaseContext( instanceContext );

    return status;
}

BOOLEAN SafeUploadInstanceIsTrusted(_In_ PFLT_INSTANCE Instance)
{
    PSAFEUPLOAD_INSTANCE_CONTEXT context = NULL;
    BOOLEAN trusted = FALSE;
    PAGED_CODE();
    if (NT_SUCCESS(FltGetInstanceContext(Instance, (PFLT_CONTEXT *)&context))) {
        trusted = context->TrustState == SAFEUPLOAD_VOLUME_TRUST_NEWLY_MOUNTED;
        FltReleaseContext(context);
    }
    return trusted;
}

BOOLEAN SafeUploadInstanceTrustGateSatisfied(_In_ PFLT_INSTANCE Instance)
{
#if SAFEUPLOAD_STAGING_PROTOTYPE
    /* Keep the demand-start Phase 1 corpus runnable with its authenticated
     * diagnostic service. The instance remains reported Untrusted; agent-down
     * creates still fail closed, and boot-start prototype/production builds
     * always require the newly-mounted flag. */
    if (!SafeUploadData.BootStartMode) return TRUE;
#endif
    return SafeUploadInstanceIsTrusted(Instance);
}

///////////////////////////////////////////////////////////////////////////
//
//  Stream context.
//
///////////////////////////////////////////////////////////////////////////

NTSTATUS
SafeUploadGetOrCreateStreamContext (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFILE_OBJECT FileObject,
    _Outptr_result_nullonfailure_ PSAFEUPLOAD_STREAM_CONTEXT *StreamContext
    )
/*++

Routine Description:

    Returns the stream context for a file, creating it if this is the first
    time the driver has seen the file.

    On success the caller owns a reference and must release it with
    FltReleaseContext.

    IRQL: PASSIVE_LEVEL.

Arguments:

    FltObjects - Objects for the operation in progress.

    FileObject - The file whose context is wanted. Passed separately
        because in pre-create FltObjects->FileObject is NULL and the target
        has to come from the operation parameters.

    StreamContext - Receives the referenced context, or NULL on failure.

Return Value:

    STATUS_SUCCESS, STATUS_NOT_SUPPORTED when the file system does not
    support stream contexts, or the failing status. Every failure leaves
    nothing allocated.

--*/
{
    PSAFEUPLOAD_STREAM_CONTEXT created = NULL;
    PSAFEUPLOAD_STREAM_CONTEXT existing = NULL;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    PSAFEUPLOAD_INSTANCE_CONTEXT instanceContext = NULL;
    PSAFEUPLOAD_INSTANCE_TEARDOWN_TOKEN teardownToken = NULL;
#endif
    NTSTATUS status;

    PAGED_CODE();

    *StreamContext = NULL;

    //
    //  Not every file system supports stream contexts. Where they are not
    //  available there is no cache, which costs performance and changes
    //  nothing about correctness.
    //

    if (!FltSupportsStreamContexts( FileObject )) {

        return STATUS_NOT_SUPPORTED;
    }

    status = FltGetStreamContext( FltObjects->Instance,
                                  FileObject,
                                  (PFLT_CONTEXT *) &existing );

    if (NT_SUCCESS( status )) {

        *StreamContext = existing;
        return STATUS_SUCCESS;
    }

    if (status != STATUS_NOT_FOUND) {

        return status;
    }

    status = FltAllocateContext( FltObjects->Filter,
                                 FLT_STREAM_CONTEXT,
                                 sizeof( SAFEUPLOAD_STREAM_CONTEXT ),
                                 NonPagedPool,
                                 (PFLT_CONTEXT *) &created );

    if (!NT_SUCCESS( status )) {

        return status;
    }

    RtlZeroMemory( created, sizeof( SAFEUPLOAD_STREAM_CONTEXT ) );
    FltInitializePushLock( &created->Lock );
#if SAFEUPLOAD_STAGING_PROTOTYPE
    KeInitializeSpinLock( &created->WriterLock );
    InitializeListHead( &created->WriterObjects );

    /*
     *  Hold the instance context while taking a token reference. A stream context
     *  without a token is deliberately retained as ambiguous; a later dropped
     *  writer then poisons machine-wide state instead of guessing.
     */
    if (NT_SUCCESS(FltGetInstanceContext(FltObjects->Instance,
            (PFLT_CONTEXT *)&instanceContext))) {
        teardownToken = instanceContext->TeardownToken;
        if (teardownToken != NULL) InterlockedIncrement(&teardownToken->ReferenceCount);
        FltReleaseContext(instanceContext);
    }
    created->TeardownToken = teardownToken;
#endif

    //
    //  KEEP_IF_EXISTS rather than REPLACE: another thread may have created
    //  the context for this same file between our lookup and now, and its
    //  verdict is as good as ours would be. Losing that race is normal, not
    //  an error.
    //

    status = FltSetStreamContext( FltObjects->Instance,
                                  FileObject,
                                  FLT_SET_CONTEXT_KEEP_IF_EXISTS,
                                  created,
                                  (PFLT_CONTEXT *) &existing );

    if (NT_SUCCESS( status )) {

        //
        //  Ours went in. The reference taken by FltAllocateContext is the
        //  one handed to the caller.
        //

        *StreamContext = created;
        return STATUS_SUCCESS;
    }

    //
    //  Ours did not go in, so release it. This runs the cleanup callback
    //  and tears down the push lock we just initialized.
    //

    FltReleaseContext( created );

    if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {

        //
        //  We lost the race. FltSetStreamContext handed back the winner
        //  with a reference already taken, which becomes the caller's.
        //

        *StreamContext = existing;
        return STATUS_SUCCESS;
    }

    return status;
}


NTSTATUS
SafeUploadMarkHandleForWrite (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ BOOLEAN OverrideGranted
    )
/*++

Routine Description:

    Marks the handle as opened for write, so that cleanup knows to
    invalidate the file's cached verdict.

    This flag is for cache invalidation at cleanup. The write callback has a
    separate purpose: it prevents a handle opened before process taint from
    becoming an egress bypass. OverrideGranted makes a justified create's
    one-use exception apply to subsequent writes through that handle.

    IRQL: PASSIVE_LEVEL. Called from post-create.

Arguments:

    FltObjects - Objects for the create that just completed.

Return Value:

    STATUS_SUCCESS, or the failing status. Failure to mark a justified handle
    may cause the following write to be denied; the grant is not broadened.

--*/
{
    PSAFEUPLOAD_STREAMHANDLE_CONTEXT handleContext = NULL;
    NTSTATUS status;

    PAGED_CODE();

    if (!FltSupportsStreamHandleContexts( FltObjects->FileObject )) {

        return STATUS_NOT_SUPPORTED;
    }

    status = FltAllocateContext( FltObjects->Filter,
                                 FLT_STREAMHANDLE_CONTEXT,
                                 sizeof( SAFEUPLOAD_STREAMHANDLE_CONTEXT ),
                                 NonPagedPool,
                                 (PFLT_CONTEXT *) &handleContext );

    if (!NT_SUCCESS( status )) {

        return status;
    }

    RtlZeroMemory( handleContext, sizeof( *handleContext ) );
#if SAFEUPLOAD_STAGING_PROTOTYPE
    FltInitializePushLock( &handleContext->DirectoryLock );
#endif
    handleContext->OpenedForWrite = TRUE;
    handleContext->OverrideGranted = OverrideGranted;

    status = FltSetStreamHandleContext( FltObjects->Instance,
                                        FltObjects->FileObject,
                                        FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
                                        handleContext,
                                        NULL );

    //
    //  Released on both paths: on success the handle holds its own
    //  reference, and on failure this was the only one.
    //

    FltReleaseContext( handleContext );

    return status;
}


BOOLEAN
SafeUploadHandleWasOpenedForWrite (
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
/*++

Routine Description:

    Whether this handle carries the write marker set at open time.

    IRQL: <= APC_LEVEL.

Arguments:

    FltObjects - Objects for the operation in progress.

Return Value:

    TRUE when the handle was opened for write.

--*/
{
    PSAFEUPLOAD_STREAMHANDLE_CONTEXT handleContext = NULL;
    BOOLEAN openedForWrite = FALSE;
    NTSTATUS status;

    status = FltGetStreamHandleContext( FltObjects->Instance,
                                        FltObjects->FileObject,
                                        (PFLT_CONTEXT *) &handleContext );

    if (NT_SUCCESS( status )) {

        openedForWrite = handleContext->OpenedForWrite;
        FltReleaseContext( handleContext );
    }

    return openedForWrite;
}


BOOLEAN
SafeUploadHandleHasOverride (
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    PSAFEUPLOAD_STREAMHANDLE_CONTEXT handleContext = NULL;
    BOOLEAN granted = FALSE;
    NTSTATUS status;

    status = FltGetStreamHandleContext( FltObjects->Instance,
                                        FltObjects->FileObject,
                                        (PFLT_CONTEXT *) &handleContext );

    if (NT_SUCCESS( status )) {
        granted = handleContext->OverrideGranted;
        FltReleaseContext( handleContext );
    }

    return granted;
}
