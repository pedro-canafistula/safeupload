/*++

Module Name:

    Communication.c

Abstract:

    Filter communication port used by the SafeUpload minifilter to ask a
    user-mode inspector whether a file operation may proceed.

    Everything here is transport. No message is interpreted beyond checking
    that it is well formed and answers the question that was asked; the
    policy that produces the verdict lives entirely in user mode.

    The overriding rule of this module is RN-013: every failure mode -
    nobody connected, allocation failure, timeout, malformed reply, driver
    unloading - resolves to "allow". The kernel never blocks a user because
    inspection did not happen.

Environment:

    Kernel mode

--*/

#include "Filter.h"

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

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(PAGE, SafeUploadCreateCommunicationPort)
    #pragma alloc_text(PAGE, SafeUploadCloseCommunicationPort)
    #pragma alloc_text(PAGE, SafeUploadPortConnect)
    #pragma alloc_text(PAGE, SafeUploadPortDisconnect)
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
                                         NULL,
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

    if (SafeUploadData.ServerPort != NULL) {

        FltCloseCommunicationPort( SafeUploadData.ServerPort );
        SafeUploadData.ServerPort = NULL;
    }

    if (SafeUploadData.ClientPort != NULL) {

        FltCloseClientPort( SafeUploadData.Filter, &SafeUploadData.ClientPort );
        SafeUploadData.InspectorProcessId = 0;
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

    FLT_ASSERT( SafeUploadData.ClientPort == NULL );

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

    From the moment ClientPort goes back to NULL, every operation is
    allowed without inspection (RN-013). That is deliberate: an inspector
    that crashed must not take the file system down with it.

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
    //  Close the port before clearing the PID, never the other way round.
    //  Once ClientPort is NULL no message can be sent at all; clearing the
    //  PID first would open a window in which the port is still live and
    //  the departing inspector's own I/O would be sent back to it.
    //

    FltCloseClientPort( SafeUploadData.Filter, &SafeUploadData.ClientPort );

    SafeUploadData.InspectorProcessId = 0;
}


NTSTATUS
SafeUploadRequestVerdict (
    _Inout_ PSAFEUPLOAD_EXCHANGE Exchange,
    _Out_ PUINT32 Verdict
    )
/*++

Routine Description:

    Sends one request to the inspector and waits, at most
    SAFEUPLOAD_VERDICT_TIMEOUT_MS, for its answer.

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

Return Value:

    The status of the exchange, for tracing only. The caller decides based
    on Verdict, never on this status.

--*/
{
    LARGE_INTEGER timeout;
    ULONG replyLength;
    NTSTATUS status;

    PAGED_CODE();

    //
    //  RN-013 in one line: the answer is "allow" unless user mode actively
    //  says otherwise.
    //

    *Verdict = SAFEUPLOAD_VERDICT_ALLOW;

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

    timeout.QuadPart = SAFEUPLOAD_VERDICT_TIMEOUT_INTERVALS;
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
    //  Only an explicit DENY blocks. Any other value is an allow.
    //

    if (Exchange->Response.Verdict == SAFEUPLOAD_VERDICT_DENY) {

        *Verdict = SAFEUPLOAD_VERDICT_DENY;
    }

Exit:

    ExReleaseRundownProtection( &SafeUploadData.ChannelRundown );

    return status;
}
