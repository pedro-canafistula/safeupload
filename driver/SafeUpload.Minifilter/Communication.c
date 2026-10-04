/*++

Module Name:

    Communication.c

Abstract:

    Filter communication port used by the SafeUpload minifilter to ask a
    user-mode inspector whether a file operation may proceed.

    Existing inspection exchanges retain RN-013: failure to obtain a verdict
    does not wedge unrelated I/O. Phase 2 separately denies new writes and
    writable sections inside identified protected scopes while unauthorized.

Environment:

    Kernel mode

--*/

#include "Filter.h"
#if SAFEUPLOAD_STAGING_PROTOTYPE
#include "Stage.h"
#endif

//
//  Port callbacks.
//

static
NTSTATUS
SafeUploadPortConnect (
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionCookie
    );

static
VOID
SafeUploadPortDisconnect (
    _In_opt_ PVOID ConnectionCookie
    );

static
NTSTATUS
SafeUploadPortMessage (
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(PAGE, SafeUploadCreateCommunicationPort)
    #pragma alloc_text(PAGE, SafeUploadCloseCommunicationPort)
    #pragma alloc_text(PAGE, SafeUploadPortConnect)
    #pragma alloc_text(PAGE, SafeUploadPortDisconnect)
    #pragma alloc_text(PAGE, SafeUploadPortMessage)
    #pragma alloc_text(PAGE, SafeUploadRequestVerdict)
#endif


NTSTATUS
SafeUploadCreateCommunicationPort (
    VOID
    )
/*++

Routine Description:

    Creates the server port the inspector connects to.

    The port is secured with the filter manager's default descriptor, which
    grants access to SYSTEM and to Administrators only. Anyone who can open
    this port can decide whether file operations succeed, so it must not be
    reachable by an unprivileged process.

    IRQL: PASSIVE_LEVEL. Called from DriverEntry.

Arguments:

    None. Operates on the global SafeUploadData.

Return Value:

    STATUS_SUCCESS, or the failure status. On failure no port is left open
    and no memory is left allocated.

--*/
{
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING portName;
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;
    NTSTATUS status;

    PAGED_CODE();

    RtlInitUnicodeString( &portName, SAFEUPLOAD_PORT_NAME );

    status = FltBuildDefaultSecurityDescriptor( &securityDescriptor,
                                                FLT_PORT_ALL_ACCESS );

    if (!NT_SUCCESS( status )) {

        SafeUploadTrace( "FltBuildDefaultSecurityDescriptor failed, status 0x%08X\n",
                         status );
        return status;
    }

    InitializeObjectAttributes( &objectAttributes,
                                &portName,
                                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                NULL,
                                securityDescriptor );

    //
    //  MaxConnections is 1: a second inspector would race the first one for
    //  every verdict, and there is no sensible way to merge two answers.
    //

    status = FltCreateCommunicationPort( SafeUploadData.Filter,
                                         &SafeUploadData.ServerPort,
                                         &objectAttributes,
                                         NULL,
                                         SafeUploadPortConnect,
                                         SafeUploadPortDisconnect,
                                         SafeUploadPortMessage,
                                         1 );

    //
    //  The descriptor is only needed for the duration of the call above,
    //  and has to be released on both the success and the failure path.
    //

    FltFreeSecurityDescriptor( securityDescriptor );

    if (!NT_SUCCESS( status )) {

        SafeUploadTrace( "FltCreateCommunicationPort failed, status 0x%08X\n",
                         status );
    }

    return status;
}


VOID
SafeUploadCloseCommunicationPort (
    VOID
    )
/*++

Routine Description:

    Tears the channel down: first the server port, so that no new inspector
    can connect, then the client port if one is still open.

    Closing the client port also releases any thread currently blocked
    inside FltSendMessage, which is what lets a mandatory unload make
    progress instead of waiting out the full verdict timeout.

    IRQL: PASSIVE_LEVEL. Called from DriverEntry's failure path and from
    the unload callback.

Arguments:

    None.

Return Value:

    None.

--*/
{
    PAGED_CODE();

    /* A connected port is not an accepted policy. Drop authorization before
     * either endpoint is closed, including DriverEntry failure cleanup. */
    InterlockedExchange(&SafeUploadData.AuthenticatedClient, 0);

    if (SafeUploadData.ServerPort != NULL) {

        FltCloseCommunicationPort( SafeUploadData.ServerPort );
        SafeUploadData.ServerPort = NULL;
    }

    if (SafeUploadData.ClientPort != NULL) {

        FltCloseClientPort( SafeUploadData.Filter, &SafeUploadData.ClientPort );
        SafeUploadData.InspectorProcessId = 0;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    SafeUploadClearPublicationPermits();
#endif
    }
}


static
NTSTATUS
SafeUploadPortConnect (
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionCookie
    )
/*++

Routine Description:

    Called when the inspector connects to the server port.

    IRQL: PASSIVE_LEVEL, in the context of the connecting process, which is
    why PsGetCurrentProcessId identifies the inspector here.

Arguments:

    ClientPort - The new client port to send messages on.

    ServerPortCookie - Unused.

    ConnectionContext - Unused: the inspector sends no connection payload.

    SizeOfContext - Unused.

    ConnectionCookie - Unused, set to NULL.

Return Value:

    STATUS_SUCCESS to accept the connection.

--*/
{
    UNREFERENCED_PARAMETER( ServerPortCookie );
    UNREFERENCED_PARAMETER( ConnectionContext );
    UNREFERENCED_PARAMETER( SizeOfContext );

    PAGED_CODE();

    *ConnectionCookie = NULL;

    //
    //  MaxConnections is 1 and the filter manager does not call connect
    //  again until disconnect has returned, so no previous client can be
    //  in place here.
    //

    {
        PACCESS_TOKEN token = PsReferencePrimaryToken( PsGetCurrentProcess() );
        PTOKEN_USER user = NULL;
        NTSTATUS identityStatus = SeQueryInformationToken( token, TokenUser, (PVOID *) &user );
        BOOLEAN system = NT_SUCCESS( identityStatus ) && user != NULL &&
            user->User.Sid != NULL && RtlValidSid( user->User.Sid ) &&
            RtlEqualSid( user->User.Sid, SeExports->SeLocalSystemSid );
        if (user != NULL) ExFreePool( user );
        PsDereferencePrimaryToken( token );
        if (!system) return STATUS_ACCESS_DENIED;
    }

    FLT_ASSERT( SafeUploadData.ClientPort == NULL );

    InterlockedExchange(&SafeUploadData.AuthenticatedClient, 0);
    SafeUploadData.InspectorProcessId = HandleToULong( PsGetCurrentProcessId() );
    SafeUploadData.ClientPort = ClientPort;

    SafeUploadTrace( "inspector connected, pid %lu\n",
                     SafeUploadData.InspectorProcessId );

    return STATUS_SUCCESS;
}


static
VOID
SafeUploadPortDisconnect (
    _In_opt_ PVOID ConnectionCookie
    )
/*++

Routine Description:

    Called when the inspector closes its handle or exits.

    From the moment the authenticated client disconnects, protected-scope
    create and writable-section gates fail closed. Reads and operations
    outside those scopes retain the existing no-inspection behavior.

    IRQL: PASSIVE_LEVEL.

Arguments:

    ConnectionCookie - Unused.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( ConnectionCookie );

    PAGED_CODE();

    SafeUploadTrace( "inspector disconnected, pid %lu\n",
                     SafeUploadData.InspectorProcessId );

    //
    //  Clear authorization before closing the port. An already-dispatched
    //  callback may still see ClientPort while teardown is in progress, but
    //  it can no longer authorize a protected create or writable section.
    //

    InterlockedExchange(&SafeUploadData.AuthenticatedClient, 0);
    FltCloseClientPort( SafeUploadData.Filter, &SafeUploadData.ClientPort );

    SafeUploadData.InspectorProcessId = 0;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    SafeUploadClearPublicationPermits();
#endif
}


NTSTATUS
SafeUploadRequestVerdict (
    _Inout_ PSAFEUPLOAD_EXCHANGE Exchange,
    _Out_ PUINT32 Verdict,
    _Out_ PBOOLEAN Answered
    )
/*++

Routine Description:

    Sends one request to the inspector and waits, at most
    the deadline the policy sets, for its answer.

    IRQL: PASSIVE_LEVEL. FltSendMessage blocks the calling thread, so this
    routine may only be reached from a callback that has established it is
    running at PASSIVE_LEVEL.

Arguments:

    Exchange - Request to send, already filled in. Its Response member is
        overwritten by this routine. The block is owned by the caller and
        must stay valid until this routine returns.

    Verdict - Receives SAFEUPLOAD_VERDICT_ALLOW or SAFEUPLOAD_VERDICT_DENY.
        Set to ALLOW before anything else can fail, so that no error path
        can leave it undefined.

    Answered - Receives TRUE only when a well-formed reply for this exact
        request was actually read from the inspector. FALSE on every
        fail-open path (no port, allocation failure, timeout, malformed or
        stale reply) - in every one of those, Verdict is ALLOW, but it was
        never checked: the caller must not cache it as a verdict, and must
        count it as AllowedWithoutInspection.

Return Value:

    The status of the exchange, for tracing only. The caller decides based
    on Verdict and Answered, never on this status - STATUS_TIMEOUT in
    particular is a success-class status (NT_SUCCESS(STATUS_TIMEOUT) is
    TRUE) despite meaning no answer was obtained.

--*/
{
    LARGE_INTEGER timeout;
    ULONG replyLength;
    NTSTATUS status;

    PAGED_CODE();

    //
    //  RN-013 in one line: the answer is "allow" unless user mode actively
    //  says otherwise. Answered defaults to FALSE and is only ever set to
    //  TRUE once a validated reply is in hand - every early exit below
    //  leaves it FALSE, which is what makes those exits fail-open without
    //  being mistaken for a checked verdict.
    //

    *Verdict = SAFEUPLOAD_VERDICT_ALLOW;
    *Answered = FALSE;

    //
    //  Take rundown protection for the whole call. If unload has already
    //  started this fails immediately and the operation goes through
    //  uninspected, which is exactly what we want: no operation may block
    //  waiting on a channel that is being torn down.
    //

    if (!ExAcquireRundownProtection( &SafeUploadData.ChannelRundown )) {

        return STATUS_FLT_DELETING_OBJECT;
    }

    if (SafeUploadData.ClientPort == NULL) {

        status = STATUS_PORT_DISCONNECTED;
        goto Exit;
    }

    RtlZeroMemory( &Exchange->Response, sizeof( SAFEUPLOAD_RESPONSE ) );

    //
    //  From the policy, not from a constant: the deadline belongs to the
    //  inspection (RN-012), and user mode is what knows how long its own
    //  engine needs. The driver clamps whatever it is told.
    //

    timeout.QuadPart = SafeUploadPolicyVerdictTimeout();
    replyLength = sizeof( SAFEUPLOAD_RESPONSE );

    //
    //  FltSendMessage returns only after the reply has been copied into
    //  Exchange->Response or the wait has been abandoned, so the caller's
    //  block stays valid for exactly as long as the filter manager needs
    //  it.
    //
    //  A non-NULL timeout means this can come back as STATUS_TIMEOUT, which
    //  is a success-class status: NT_SUCCESS(STATUS_TIMEOUT) is TRUE. The
    //  comparison below is therefore against STATUS_SUCCESS and not an
    //  NT_SUCCESS test, or a timed-out request would be read as an answer.
    //

    status = FltSendMessage( SafeUploadData.Filter,
                             &SafeUploadData.ClientPort,
                             &Exchange->Request,
                             sizeof( SAFEUPLOAD_REQUEST ),
                             &Exchange->Response,
                             &replyLength,
                             &timeout );

    if (status != STATUS_SUCCESS) {

        SafeUploadTrace( "no verdict for request %llu, status 0x%08X - allowing\n",
                         Exchange->Request.RequestId,
                         status );
        goto Exit;
    }

    //
    //  The reply came back. Validate it before trusting it: a short, stale
    //  or mismatched reply is treated as no reply at all.
    //

    if (replyLength < sizeof( SAFEUPLOAD_RESPONSE ) ||
        Exchange->Response.Version != SAFEUPLOAD_PROTOCOL_VERSION ||
        Exchange->Response.StructSize != sizeof( SAFEUPLOAD_RESPONSE ) ||
        Exchange->Response.RequestId != Exchange->Request.RequestId) {

        SafeUploadTrace( "malformed reply for request %llu - allowing\n",
                         Exchange->Request.RequestId );

        status = STATUS_INVALID_BUFFER_SIZE;
        goto Exit;
    }

    //
    //  A validated reply is in hand: whatever Verdict ends up being, it was
    //  actually checked by user mode.
    //

    *Answered = TRUE;

    //
    //  Only an explicit DENY blocks. Any other value is an allow.
    //

    if (Exchange->Response.Verdict == SAFEUPLOAD_VERDICT_DENY) {

        *Verdict = SAFEUPLOAD_VERDICT_DENY;
    }

Exit:

    ExReleaseRundownProtection( &SafeUploadData.ChannelRundown );

    return status;
}


static
NTSTATUS
SafeUploadPortMessage (
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
/*++

Routine Description:

    Receives a control message from the inspector, sent with
    FilterSendMessage. This is the direction the policy travels.

    IRQL: PASSIVE_LEVEL, in the context of the sending process.

    Everything reachable from InputBuffer is USER MEMORY, supplied by a
    process this driver does not control. It has to be probed and copied
    inside an exception handler before a single field is trusted, and every
    count in it has to be validated afterwards. A driver that reads a
    user-mode pointer directly is one bad pointer away from a bugcheck that
    an unprivileged mistake can trigger.

Arguments:

    PortCookie - Unused.

    InputBuffer - The message, in user memory.

    InputBufferLength - Its size, as claimed by the caller.

    OutputBuffer - Used by GET_COUNTERS and the feature-only trace batch.

    OutputBufferLength - Capacity of the optional reply payload.

    ReturnOutputBufferLength - Number of reply bytes written.

Return Value:

    STATUS_SUCCESS when the message was understood and applied. The status
    reaches the caller as the return of FilterSendMessage.

--*/
{
    PSAFEUPLOAD_POLICY_MESSAGE policy = NULL;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    SAFEUPLOAD_CONTROL controlHeader;
#endif
    NTSTATUS status = STATUS_SUCCESS;
    UINT32 command = 0;

    UNREFERENCED_PARAMETER( PortCookie );

    PAGED_CODE();

    *ReturnOutputBufferLength = 0;

    if (InputBuffer == NULL || InputBufferLength < sizeof( SAFEUPLOAD_CONTROL )) {

        return STATUS_INVALID_PARAMETER;
    }

    /* A SYSTEM process may duplicate the client-port handle. Bind every
     * request to the process accepted by PortConnect, not only to whoever
     * presents a handle for the connection. */
    if (SafeUploadData.ClientPort == NULL ||
        HandleToULong(PsGetCurrentProcessId()) != SafeUploadData.InspectorProcessId) {
        return STATUS_ACCESS_DENIED;
    }

    //
    //  From pool, never from the stack. A kernel stack is about 12 KB and
    //  SAFEUPLOAD_POLICY_MESSAGE is over 11 KB of it: a local would leave
    //  almost nothing for the routines called from here, and the overflow
    //  would show up as a bugcheck somewhere unrelated.
    //

    policy = (PSAFEUPLOAD_POLICY_MESSAGE) ExAllocatePool2( POOL_FLAG_NON_PAGED,
                                                           sizeof( SAFEUPLOAD_POLICY_MESSAGE ),
                                                           SAFEUPLOAD_POOL_TAG );

    if (policy == NULL) {

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    try {

        //
        //  The alignment requirement is the structure's own: ProbeForRead
        //  rejects a buffer the caller placed on a boundary the structure
        //  cannot legally sit on.
        //

#if SAFEUPLOAD_STAGING_PROTOTYPE
        ProbeForRead( InputBuffer, sizeof( SAFEUPLOAD_CONTROL ), __alignof( SAFEUPLOAD_CONTROL ) );
        RtlCopyMemory( &controlHeader, InputBuffer, sizeof( controlHeader ) );
        command = controlHeader.Command;

        if (command == SAFEUPLOAD_CONTROL_ADMISSION_PROBE) {
            ULONG maximumProbeSize = (ULONG)FIELD_OFFSET( SAFEUPLOAD_ADMISSION_PROBE_REQUEST, Strings ) +
                (2UL * (ULONG)SAFEUPLOAD_ADMISSION_PROBE_MAX_STRING_CHARS * (ULONG)sizeof( WCHAR ));

            if (InputBufferLength > maximumProbeSize || InputBufferLength > sizeof( *policy )) {
                status = STATUS_INVALID_BUFFER_SIZE;
                leave;
            }
            ProbeForRead( InputBuffer,
                          InputBufferLength,
                          __alignof( SAFEUPLOAD_ADMISSION_PROBE_REQUEST ) );
        } else if (command == SAFEUPLOAD_CONTROL_ADMISSION_DELETE_STREAM_CONTEXT) {
            ULONG maximumDeleteSize =
                (ULONG)FIELD_OFFSET(SAFEUPLOAD_ADMISSION_DELETE_STREAM_CONTEXT_REQUEST, Strings) +
                (2UL * (ULONG)SAFEUPLOAD_ADMISSION_PROBE_MAX_STRING_CHARS * (ULONG)sizeof(WCHAR));

            if (InputBufferLength > maximumDeleteSize || InputBufferLength > sizeof(*policy)) {
                status = STATUS_INVALID_BUFFER_SIZE;
                leave;
            }
            ProbeForRead(InputBuffer, InputBufferLength,
                __alignof(SAFEUPLOAD_ADMISSION_DELETE_STREAM_CONTEXT_REQUEST));
        } else
        {
            ProbeForRead( InputBuffer,
                          InputBufferLength,
                          __alignof( SAFEUPLOAD_POLICY_MESSAGE ) );
        }
#else
        ProbeForRead( InputBuffer, InputBufferLength, __alignof( SAFEUPLOAD_POLICY_MESSAGE ) );
        command = ((PSAFEUPLOAD_CONTROL) InputBuffer)->Command;
#endif

#if SAFEUPLOAD_STAGING_PROTOTYPE
        if (command == SAFEUPLOAD_CONTROL_ADMISSION_TRACE_ENABLE ||
            command == SAFEUPLOAD_CONTROL_ADMISSION_TRACE_DISABLE ||
            command == SAFEUPLOAD_CONTROL_ADMISSION_TRACE_CLEAR) {
            SAFEUPLOAD_CONTROL traceControl;

            if (InputBufferLength != sizeof( SAFEUPLOAD_CONTROL )) {
                status = STATUS_INVALID_BUFFER_SIZE;
                leave;
            }
            if (OutputBuffer != NULL || OutputBufferLength != 0) {
                status = STATUS_INVALID_PARAMETER;
                leave;
            }

            RtlCopyMemory( &traceControl, InputBuffer, sizeof( traceControl ) );
            if (traceControl.Version != SAFEUPLOAD_PROTOCOL_VERSION ||
                traceControl.StructSize != sizeof( SAFEUPLOAD_CONTROL ) ||
                traceControl.Command != command ||
                (command != SAFEUPLOAD_CONTROL_ADMISSION_TRACE_ENABLE && traceControl.Reserved != 0) ||
                (command == SAFEUPLOAD_CONTROL_ADMISSION_TRACE_ENABLE &&
                 (traceControl.Reserved & ~(SAFEUPLOAD_ADMISSION_TRACE_OPTION_SECTION_EVENTS |
                                            SAFEUPLOAD_ADMISSION_TRACE_OPTION_FILE_LIFETIME)) != 0)) {
                status = STATUS_REVISION_MISMATCH;
                leave;
            }

            status = SafeUploadStageAdmissionTraceControl( command, traceControl.Reserved );
            leave;
        }

        if (command == SAFEUPLOAD_CONTROL_ADMISSION_TRACE_READ_BATCH) {
            SAFEUPLOAD_ADMISSION_TRACE_REQUEST request;

            //
            //  The reply is about 1.0 KB: built in the pool scratch buffer
            //  already allocated above, never on the stack. Its size is
            //  asserted against that buffer in Protocol.h.
            //

            PSAFEUPLOAD_ADMISSION_TRACE_BATCH batch = (PSAFEUPLOAD_ADMISSION_TRACE_BATCH) policy;

            if (InputBufferLength != sizeof( SAFEUPLOAD_ADMISSION_TRACE_REQUEST )) {
                status = STATUS_INVALID_BUFFER_SIZE;
                leave;
            }
            if (OutputBuffer == NULL || OutputBufferLength != sizeof( SAFEUPLOAD_ADMISSION_TRACE_BATCH )) {
                status = OutputBufferLength < sizeof( SAFEUPLOAD_ADMISSION_TRACE_BATCH ) ?
                    STATUS_BUFFER_TOO_SMALL : STATUS_INVALID_BUFFER_SIZE;
                leave;
            }

            RtlCopyMemory( &request, InputBuffer, sizeof( request ) );
            if (request.Control.Version != SAFEUPLOAD_PROTOCOL_VERSION ||
                request.Control.StructSize != sizeof( SAFEUPLOAD_ADMISSION_TRACE_REQUEST ) ||
                request.Control.Command != SAFEUPLOAD_CONTROL_ADMISSION_TRACE_READ_BATCH ||
                request.Control.Reserved != 0) {
                status = STATUS_REVISION_MISMATCH;
                leave;
            }

#pragma warning( suppress: 6001 )
            ProbeForWrite( OutputBuffer,
                           sizeof( SAFEUPLOAD_ADMISSION_TRACE_BATCH ),
                           __alignof( SAFEUPLOAD_ADMISSION_TRACE_BATCH ) );

            status = SafeUploadStageAdmissionTraceReadBatch( request.Cursor,
                                                              request.SnapshotSequence,
                                                              batch );
            if (NT_SUCCESS( status )) {
                RtlCopyMemory( OutputBuffer, batch, sizeof( *batch ) );
                *ReturnOutputBufferLength = sizeof( *batch );
            }
            leave;
        }

        if (command == SAFEUPLOAD_CONTROL_ADMISSION_PROBE) {
            PSAFEUPLOAD_ADMISSION_PROBE_REQUEST request =
                (PSAFEUPLOAD_ADMISSION_PROBE_REQUEST)policy;
            UNICODE_STRING volumeName;
            UNICODE_STRING relativePath;
            UNICODE_STRING volumePrefix = RTL_CONSTANT_STRING( L"\\Device\\" );
            ULONG volumeChars;
            ULONG relativeChars;
            ULONG volumeBytes;
            ULONG relativeBytes;
            ULONG stringBytes;
            ULONG expectedLength;
            ULONG index;
            ULONG maximumProbeSize = (ULONG)FIELD_OFFSET( SAFEUPLOAD_ADMISSION_PROBE_REQUEST, Strings ) +
                (2UL * (ULONG)SAFEUPLOAD_ADMISSION_PROBE_MAX_STRING_CHARS * (ULONG)sizeof( WCHAR ));

            if (InputBufferLength < (ULONG)FIELD_OFFSET( SAFEUPLOAD_ADMISSION_PROBE_REQUEST, Strings ) ||
                InputBufferLength > maximumProbeSize ||
                OutputBuffer != NULL || OutputBufferLength != 0) {
                status = STATUS_INVALID_BUFFER_SIZE;
                leave;
            }

            // This bounded request is larger than the control header; copy it
            // into the existing pool scratch buffer, never a kernel stack local.
            RtlCopyMemory( request, InputBuffer, InputBufferLength );

            if (request->Control.Version != SAFEUPLOAD_PROTOCOL_VERSION ||
                request->Control.StructSize != InputBufferLength ||
                request->Control.Command != SAFEUPLOAD_CONTROL_ADMISSION_PROBE ||
                request->Control.Reserved != 0 ||
                request->Reserved != 0) {
                status = STATUS_REVISION_MISMATCH;
                leave;
            }

            volumeChars = (ULONG)request->VolumeNameChars;
            relativeChars = (ULONG)request->RelativePathChars;
            if (volumeChars == 0 || relativeChars < 2 ||
                volumeChars > (ULONG)SAFEUPLOAD_ADMISSION_PROBE_MAX_STRING_CHARS ||
                relativeChars > (ULONG)SAFEUPLOAD_ADMISSION_PROBE_MAX_STRING_CHARS ||
                volumeChars > MAXULONG / (ULONG)sizeof( WCHAR ) ||
                relativeChars > MAXULONG / (ULONG)sizeof( WCHAR )) {
                status = STATUS_INVALID_PARAMETER;
                leave;
            }

            volumeBytes = volumeChars * (ULONG)sizeof( WCHAR );
            relativeBytes = relativeChars * (ULONG)sizeof( WCHAR );
            if (relativeBytes > MAXULONG - volumeBytes) {
                status = STATUS_INVALID_PARAMETER;
                leave;
            }
            stringBytes = volumeBytes + relativeBytes;
            if (stringBytes > MAXULONG -
                (ULONG)FIELD_OFFSET( SAFEUPLOAD_ADMISSION_PROBE_REQUEST, Strings )) {
                status = STATUS_INVALID_PARAMETER;
                leave;
            }
            expectedLength = (ULONG)FIELD_OFFSET( SAFEUPLOAD_ADMISSION_PROBE_REQUEST, Strings ) + stringBytes;
            if (InputBufferLength != expectedLength) {
                status = STATUS_INVALID_BUFFER_SIZE;
                leave;
            }

            volumeName.Buffer = request->Strings;
            volumeName.Length = (USHORT)volumeBytes;
            volumeName.MaximumLength = volumeName.Length;
            relativePath.Buffer = request->Strings + volumeChars;
            relativePath.Length = (USHORT)relativeBytes;
            relativePath.MaximumLength = relativePath.Length;

            for (index = 0; index < volumeChars; index += 1) {
                if (volumeName.Buffer[index] == UNICODE_NULL) {
                    status = STATUS_INVALID_PARAMETER;
                    leave;
                }
            }
            for (index = 0; index < relativeChars; index += 1) {

                //
                //  A colon would name an alternate data stream, whose section
                //  pointers need not describe the default stream being probed.
                //

                if (relativePath.Buffer[index] == UNICODE_NULL ||
                    relativePath.Buffer[index] == L':') {
                    status = STATUS_INVALID_PARAMETER;
                    leave;
                }
            }

            if (!RtlPrefixUnicodeString( &volumePrefix, &volumeName, TRUE ) ||
                relativePath.Buffer[0] != L'\\' ||
                relativePath.Buffer[relativeChars - 1] == L'\\') {
                status = STATUS_INVALID_PARAMETER;
                leave;
            }

            status = SafeUploadStageAdmissionProbe( &volumeName, &relativePath );
            leave;
        }

        if (command == SAFEUPLOAD_CONTROL_ADMISSION_DELETE_STREAM_CONTEXT) {
            PSAFEUPLOAD_ADMISSION_DELETE_STREAM_CONTEXT_REQUEST request =
                (PSAFEUPLOAD_ADMISSION_DELETE_STREAM_CONTEXT_REQUEST)policy;
            UNICODE_STRING volumeName;
            UNICODE_STRING relativePath;
            UNICODE_STRING volumePrefix = RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume");
            ULONG volumeChars;
            ULONG relativeChars;
            ULONG volumeBytes;
            ULONG relativeBytes;
            ULONG expectedLength;
            ULONG index;
            ULONG maximumDeleteSize =
                (ULONG)FIELD_OFFSET(SAFEUPLOAD_ADMISSION_DELETE_STREAM_CONTEXT_REQUEST, Strings) +
                (2UL * (ULONG)SAFEUPLOAD_ADMISSION_PROBE_MAX_STRING_CHARS * (ULONG)sizeof(WCHAR));

            if (InputBufferLength < (ULONG)FIELD_OFFSET(
                    SAFEUPLOAD_ADMISSION_DELETE_STREAM_CONTEXT_REQUEST, Strings) ||
                InputBufferLength > maximumDeleteSize || OutputBuffer != NULL || OutputBufferLength != 0) {
                status = STATUS_INVALID_BUFFER_SIZE;
                leave;
            }
            RtlCopyMemory(request, InputBuffer, InputBufferLength);
            if (request->Control.Version != SAFEUPLOAD_PROTOCOL_VERSION ||
                request->Control.StructSize != InputBufferLength ||
                request->Control.Command != command || request->Control.Reserved != 0 ||
                request->Reserved != 0 || request->DriveLetter != L'C' || request->Reserved2 != 0) {
                status = STATUS_REVISION_MISMATCH;
                leave;
            }

            volumeChars = (ULONG)request->VolumeNameChars;
            relativeChars = (ULONG)request->RelativePathChars;
            if (volumeChars < volumePrefix.Length / sizeof(WCHAR) ||
                relativeChars < 2 ||
                volumeChars > (ULONG)SAFEUPLOAD_ADMISSION_PROBE_MAX_STRING_CHARS ||
                relativeChars > (ULONG)SAFEUPLOAD_ADMISSION_PROBE_MAX_STRING_CHARS) {
                status = STATUS_INVALID_PARAMETER;
                leave;
            }
            volumeBytes = volumeChars * (ULONG)sizeof(WCHAR);
            relativeBytes = relativeChars * (ULONG)sizeof(WCHAR);
            expectedLength = (ULONG)FIELD_OFFSET(
                SAFEUPLOAD_ADMISSION_DELETE_STREAM_CONTEXT_REQUEST, Strings) +
                volumeBytes + relativeBytes;
            if (InputBufferLength != expectedLength) {
                status = STATUS_INVALID_BUFFER_SIZE;
                leave;
            }

            volumeName.Buffer = request->Strings;
            volumeName.Length = (USHORT)volumeBytes;
            volumeName.MaximumLength = volumeName.Length;
            relativePath.Buffer = request->Strings + volumeChars;
            relativePath.Length = (USHORT)relativeBytes;
            relativePath.MaximumLength = relativePath.Length;
            if (!RtlPrefixUnicodeString(&volumePrefix, &volumeName, TRUE) ||
                relativePath.Buffer[0] != L'\\' ||
                relativePath.Buffer[relativeChars - 1] == L'\\') {
                status = STATUS_INVALID_PARAMETER;
                leave;
            }
            for (index = 0; index < volumeChars; ++index) {
                if (volumeName.Buffer[index] == UNICODE_NULL) {
                    status = STATUS_INVALID_PARAMETER;
                    leave;
                }
            }
            for (index = 0; index < relativeChars; ++index) {
                if (relativePath.Buffer[index] == UNICODE_NULL || relativePath.Buffer[index] == L':') {
                    status = STATUS_INVALID_PARAMETER;
                    leave;
                }
            }

            status = SafeUploadStageAdmissionDeleteStreamContext(&volumeName, &relativePath);
            leave;
        }

        if (command == SAFEUPLOAD_CONTROL_ADMISSION_VOLUME_STATUS) {
            PSAFEUPLOAD_ADMISSION_VOLUME_STATUS volumeStatus = (PSAFEUPLOAD_ADMISSION_VOLUME_STATUS)policy;
            if (InputBufferLength != sizeof(SAFEUPLOAD_CONTROL) || OutputBuffer == NULL ||
                OutputBufferLength != sizeof(*volumeStatus)) {
                status = STATUS_INVALID_BUFFER_SIZE;
                leave;
            }
            if (controlHeader.Version != SAFEUPLOAD_PROTOCOL_VERSION ||
                controlHeader.StructSize != sizeof(SAFEUPLOAD_CONTROL) || controlHeader.Reserved != 0) {
                status = STATUS_REVISION_MISMATCH;
                leave;
            }
#pragma warning( suppress: 6001 )
            ProbeForWrite(OutputBuffer, sizeof(*volumeStatus), __alignof(SAFEUPLOAD_ADMISSION_VOLUME_STATUS));
            status = SafeUploadStageAdmissionVolumeStatus(volumeStatus);
            if (NT_SUCCESS(status)) {
                RtlCopyMemory(OutputBuffer, volumeStatus, sizeof(*volumeStatus));
                *ReturnOutputBufferLength = sizeof(*volumeStatus);
            }
            leave;
        }

        if (command == SAFEUPLOAD_CONTROL_ADMISSION_CANARY_HOLD) {
            SAFEUPLOAD_ADMISSION_CANARY_HOLD_REQUEST request;
            PSAFEUPLOAD_ADMISSION_CANARY_HOLD_REPLY reply;
            UNICODE_STRING volumeName;
            ULONG index;

            if (InputBufferLength != sizeof(request) || OutputBuffer == NULL ||
                OutputBufferLength != sizeof(*reply)) {
                status = STATUS_INVALID_BUFFER_SIZE;
                leave;
            }
            RtlCopyMemory(&request, InputBuffer, sizeof(request));
            if (request.Control.Version != SAFEUPLOAD_PROTOCOL_VERSION ||
                request.Control.StructSize != sizeof(request) ||
                request.Control.Command != command || request.Control.Reserved != 0 ||
                request.Reserved != 0 || request.VolumeNameChars == 0 ||
                request.VolumeNameChars >= SAFEUPLOAD_CANARY_VOLUME_CHARS ||
                request.VolumeName[request.VolumeNameChars] != UNICODE_NULL ||
                request.HoldMilliseconds == 0 ||
                request.HoldMilliseconds > SAFEUPLOAD_CANARY_MAX_HOLD_MS) {
                status = STATUS_INVALID_PARAMETER;
                leave;
            }
            for (index = 0; index < request.VolumeNameChars; ++index) {
                if (request.VolumeName[index] == UNICODE_NULL) {
                    status = STATUS_INVALID_PARAMETER;
                    leave;
                }
            }
            for (index = request.VolumeNameChars + 1; index < SAFEUPLOAD_CANARY_VOLUME_CHARS; ++index) {
                if (request.VolumeName[index] != UNICODE_NULL) {
                    status = STATUS_INVALID_PARAMETER;
                    leave;
                }
            }
            volumeName.Buffer = request.VolumeName;
            volumeName.Length = (USHORT)(request.VolumeNameChars * sizeof(WCHAR));
            volumeName.MaximumLength = sizeof(request.VolumeName);
#pragma warning( suppress: 6001 )
            ProbeForWrite(OutputBuffer, sizeof(*reply), __alignof(SAFEUPLOAD_ADMISSION_CANARY_HOLD_REPLY));
            /* The 1 KB reply lives in pool, not on this already large dispatch frame. */
            reply = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*reply), SAFEUPLOAD_POOL_TAG);
            if (reply == NULL) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                leave;
            }
            try {
                status = SafeUploadStageAdmissionCanaryHold(&volumeName,
                    request.HoldMilliseconds, reply);
                if (NT_SUCCESS(status)) {
                    RtlCopyMemory(OutputBuffer, reply, sizeof(*reply));
                    *ReturnOutputBufferLength = sizeof(*reply);
                }
            } finally {
                ExFreePoolWithTag(reply, SAFEUPLOAD_POOL_TAG);
            }
            leave;
        }

        if (command == SAFEUPLOAD_CONTROL_ADMISSION_CANARY_HOLD_CANCEL) {
            SAFEUPLOAD_CONTROL cancelControl;
            if (InputBufferLength != sizeof(cancelControl) || OutputBuffer != NULL ||
                OutputBufferLength != 0) {
                status = STATUS_INVALID_BUFFER_SIZE;
                leave;
            }
            RtlCopyMemory(&cancelControl, InputBuffer, sizeof(cancelControl));
            if (cancelControl.Version != SAFEUPLOAD_PROTOCOL_VERSION ||
                cancelControl.StructSize != sizeof(cancelControl) ||
                cancelControl.Command != command || cancelControl.Reserved != 0) {
                status = STATUS_REVISION_MISMATCH;
                leave;
            }
            SafeUploadStageAdmissionCanaryHoldCancel();
            status = STATUS_SUCCESS;
            leave;
        }

        if (command == SAFEUPLOAD_CONTROL_ADMISSION_FENCE_REFRESH ||
            command == SAFEUPLOAD_CONTROL_ADMISSION_FENCE_STATUS) {
            SAFEUPLOAD_CONTROL fenceControl;
            SAFEUPLOAD_FENCE_STATUS fenceStatus;
            BOOLEAN wantStatus = command == SAFEUPLOAD_CONTROL_ADMISSION_FENCE_STATUS;

            if (InputBufferLength != sizeof( SAFEUPLOAD_CONTROL )) {
                status = STATUS_INVALID_BUFFER_SIZE;
                leave;
            }
            if (wantStatus ? (OutputBuffer == NULL || OutputBufferLength != sizeof( fenceStatus )) :
                             (OutputBuffer != NULL || OutputBufferLength != 0)) {
                status = STATUS_INVALID_BUFFER_SIZE;
                leave;
            }

            RtlCopyMemory( &fenceControl, InputBuffer, sizeof( fenceControl ) );
            if (fenceControl.Version != SAFEUPLOAD_PROTOCOL_VERSION ||
                fenceControl.StructSize != sizeof( SAFEUPLOAD_CONTROL ) ||
                fenceControl.Command != command ||
                fenceControl.Reserved != 0) {
                status = STATUS_REVISION_MISMATCH;
                leave;
            }

            if (!wantStatus) {
                if (SafeUploadData.BootStartMode) {
                    status = STATUS_NOT_SUPPORTED;
                    leave;
                }
                status = SafeUploadStageFenceRefresh( NULL );
                leave;
            }

#pragma warning( suppress: 6001 )
            ProbeForWrite( OutputBuffer, sizeof( fenceStatus ), __alignof( SAFEUPLOAD_FENCE_STATUS ) );
            SafeUploadStageFenceGetStatus( &fenceStatus );
            RtlCopyMemory( OutputBuffer, &fenceStatus, sizeof( fenceStatus ) );
            *ReturnOutputBufferLength = sizeof( fenceStatus );
            leave;
        }
#endif

#if SAFEUPLOAD_STAGING_PROTOTYPE
        if (command == SAFEUPLOAD_CONTROL_WRITER_STATE_STATUS) {
            SAFEUPLOAD_CONTROL writerControl;
            SAFEUPLOAD_WRITER_STATE_STATUS writerStatus;

            if (InputBufferLength != sizeof( SAFEUPLOAD_CONTROL ) ||
                OutputBuffer == NULL || OutputBufferLength != sizeof( writerStatus )) {
                status = STATUS_INVALID_BUFFER_SIZE;
                leave;
            }
            RtlCopyMemory( &writerControl, InputBuffer, sizeof( writerControl ) );
            if (writerControl.Version != SAFEUPLOAD_PROTOCOL_VERSION ||
                writerControl.StructSize != sizeof( SAFEUPLOAD_CONTROL ) ||
                writerControl.Command != command ||
                writerControl.Reserved != 0) {
                status = STATUS_REVISION_MISMATCH;
                leave;
            }
#pragma warning( suppress: 6001 )
            ProbeForWrite( OutputBuffer, sizeof( writerStatus ), __alignof( SAFEUPLOAD_WRITER_STATE_STATUS ) );
            SafeUploadStageWritersGetStatus( &writerStatus );
            RtlCopyMemory( OutputBuffer, &writerStatus, sizeof( writerStatus ) );
            *ReturnOutputBufferLength = sizeof( writerStatus );
            leave;
        }
#endif

        if (command == SAFEUPLOAD_CONTROL_GET_COUNTERS) {

            //
            //  The output buffer is user memory too, and has to be probed
            //  for WRITE before a single byte is put into it.
            //

            if (OutputBuffer == NULL ||
                OutputBufferLength < sizeof( SAFEUPLOAD_COUNTERS )) {

                status = STATUS_BUFFER_TOO_SMALL;
                leave;
            }

            //
            //  Code Analysis reads ProbeForWrite as consuming the buffer and
            //  reports C6001. It does not: it validates that the range is
            //  writable user memory and touches no contents. Suppressed
            //  narrowly, at the one call it applies to.
            //

#pragma warning( suppress: 6001 )
            ProbeForWrite( OutputBuffer,
                           sizeof( SAFEUPLOAD_COUNTERS ),
                           __alignof( SAFEUPLOAD_COUNTERS ) );

            SafeUploadCounters.Version = SAFEUPLOAD_PROTOCOL_VERSION;
            SafeUploadCounters.StructSize = sizeof( SAFEUPLOAD_COUNTERS );

            //
            //  Copied without a lock. Each field is written with an
            //  interlocked increment, so no value can be torn; what a reader
            //  can get is a set of fields sampled microseconds apart, which
            //  is fine for counters nobody derives an invariant from.
            //

            RtlCopyMemory( OutputBuffer,
                           &SafeUploadCounters,
                           sizeof( SAFEUPLOAD_COUNTERS ) );

            *ReturnOutputBufferLength = sizeof( SAFEUPLOAD_COUNTERS );

            status = STATUS_SUCCESS;
            leave;
        }

#if SAFEUPLOAD_STAGING_PROTOTYPE
        if (command == SAFEUPLOAD_CONTROL_STAGE_PUBLICATION) {
            if (InputBufferLength != sizeof( SAFEUPLOAD_PUBLICATION_MESSAGE )) {
                status = STATUS_INVALID_BUFFER_SIZE;
                leave;
            }
            RtlCopyMemory( policy, InputBuffer, sizeof( SAFEUPLOAD_PUBLICATION_MESSAGE ) );
            status = SafeUploadSetPublicationPermit( (PSAFEUPLOAD_PUBLICATION_MESSAGE) policy );
            leave;
        }
#endif

        if (command == SAFEUPLOAD_CONTROL_GRANT_OVERRIDE) {

            PSAFEUPLOAD_OVERRIDE_MESSAGE grant = (PSAFEUPLOAD_OVERRIDE_MESSAGE)policy;

            if (InputBufferLength < sizeof( SAFEUPLOAD_OVERRIDE_MESSAGE )) {

                status = STATUS_INVALID_BUFFER_SIZE;
                leave;
            }

            //
            //  Copiado de uma vez e validado depois, pela mesma razao da
            //  politica: validar no lugar deixaria cada campo aberto a ser
            //  trocado por outra thread do processo remetente entre a
            //  verificacao e o uso.
            //

            RtlCopyMemory( grant, InputBuffer, sizeof( SAFEUPLOAD_OVERRIDE_MESSAGE ) );

            if (grant->PathLength == 0 ||
                grant->PathLength > (SAFEUPLOAD_MAX_PATH_CHARS - 1) * sizeof( WCHAR )) {

                status = STATUS_INVALID_PARAMETER;
                leave;
            }

            status = SafeUploadGrantOverride( grant->ProcessId,
                                              grant->Path,
                                              (USHORT) grant->PathLength,
                                              grant->DurationSeconds );
            leave;
        }

        if (command != SAFEUPLOAD_CONTROL_SET_POLICY) {

            status = STATUS_NOT_SUPPORTED;
            leave;
        }

        if (InputBufferLength < sizeof( SAFEUPLOAD_POLICY_MESSAGE )) {

            status = STATUS_INVALID_BUFFER_SIZE;
            leave;
        }

        //
        //  Copied out of user memory in one shot, and validated only after
        //  the copy. Validating in place would leave every field open to
        //  being changed by another thread of the sending process between
        //  the check and the use.
        //

        RtlCopyMemory( policy, InputBuffer, sizeof( SAFEUPLOAD_POLICY_MESSAGE ) );

    } except (EXCEPTION_EXECUTE_HANDLER) {

        status = GetExceptionCode();
    }

    //
    //  Only the policy command has a policy to validate. Testing the status
    //  alone would run this over the untouched, zeroed buffer after a
    //  counters request succeeded, and overwrite its success with a version
    //  mismatch against a version nobody sent.
    //

    if (NT_SUCCESS( status ) && command == SAFEUPLOAD_CONTROL_SET_POLICY) {

        if (policy->Control.Version != SAFEUPLOAD_PROTOCOL_VERSION ||
            policy->Control.StructSize != sizeof( SAFEUPLOAD_POLICY_MESSAGE )) {

            SafeUploadTrace( "policy rejeitada: versao %u tamanho %u\n",
                             policy->Control.Version,
                             policy->Control.StructSize );

            status = STATUS_REVISION_MISMATCH;

        } else if (policy->Control.Reserved == 0) {

            status = SafeUploadSetPolicy( policy );
            if (NT_SUCCESS(status)) {
                InterlockedExchange(&SafeUploadData.AuthenticatedClient, 1);
            }

        } else if (policy->Control.Reserved == SAFEUPLOAD_POLICY_CONTROL_FINALIZE_BOOT_SCOPES) {
            /* The second SET_POLICY arrives only after the service durably
             * commits Scopes and removes PendingScopes. Normalize the header
             * before comparing it with the already-installed live snapshot. */
            policy->Control.Reserved = 0;
            status = SafeUploadFinalizeBootPolicy(policy);

        } else {
            status = STATUS_INVALID_PARAMETER;
        }
    }

    ExFreePoolWithTag( policy, SAFEUPLOAD_POOL_TAG );

    return status;
}
