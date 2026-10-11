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

static NTSTATUS SafeUploadPortConnectInternal (
    _In_ PFLT_PORT ClientPort, _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext, _Outptr_result_maybenull_ PVOID *ConnectionCookie);

static
VOID
SafeUploadPortDisconnect (
    _In_opt_ PVOID ConnectionCookie
    );

/* Connect, disconnect, and unload serialize writes to SafeUploadData.ClientPort.
 * FltSendMessage keeps using that exact slot, so replacement is published only
 * after the prior slot has been closed. ConnectionCookie is a monotonically
 * increasing opaque token; callbacks never dereference it. */
static EX_PUSH_LOCK SafeUploadConnectionTransitionLock;
static KSPIN_LOCK SafeUploadConnectionStateLock;
static KEVENT SafeUploadConnectionUsesDrained;
static KEVENT SafeUploadControlCallbacksDrained;
static KEVENT SafeUploadConnectionRetirementComplete;
static volatile LONG64 SafeUploadConnectionCookieSequence;
static PVOID volatile SafeUploadCurrentConnectionCookie;
/* The channel generation shares the cookie's monotonic serial but is kept as
 * explicit state so permit grants can bind to both the opaque identity and
 * the generation that authenticated them. Protected by the state spin lock. */
static LONG64 SafeUploadCurrentConnectionGeneration;
static PVOID SafeUploadActiveConnectionUseCookie;
static LONG SafeUploadActiveConnectionUseCount;
static LONG64 SafeUploadConnectionCallbackCount;
static LONG64 SafeUploadControlCallbackCount;
static BOOLEAN SafeUploadControlCallbackAdmissionClosed;
#if SAFEUPLOAD_STAGING_PROTOTYPE
/* Denies Connect/Message callback bodies during final stage quiesce while
 * leaving outbound FltSendMessage pins available. Disconnect stays admitted. */
static BOOLEAN SafeUploadStageCallbackAdmissionClosed;
/* Exact process accepted at PortConnect. A PID lookup at a later export is
 * not this identity, even when the numeric PID matches. State lock protects
 * the owned reference; holders acquire their own reference and channel-use
 * pin before leaving that lock. */
static PEPROCESS SafeUploadCurrentConnectionProcess;
#endif
/* Protected by SafeUploadConnectionTransitionLock. Retiring blocks both a
 * replacement publish and a second close while FltCloseClientPort runs with
 * the transition guard dropped so a recursive disconnect callback can exit. */
static BOOLEAN SafeUploadConnectionRetiring;
static PVOID SafeUploadRetiringConnectionCookie;
static BOOLEAN SafeUploadConnectionClosing;

static
BOOLEAN
SafeUploadRetireCurrentConnection (
    _In_opt_ PVOID ConnectionCookie
    );

static VOID SafeUploadConnectionCloseAdmission(VOID);
static BOOLEAN SafeUploadConnectionRetireState(_In_opt_ PVOID ConnectionCookie,
    _Out_ PULONG ProcessId, _Out_ PBOOLEAN CloseClientPort,
    _Out_ PLONG64 ConnectionGeneration);
static VOID SafeUploadConnectionResetInspectorProcessId(VOID);
static BOOLEAN SafeUploadConnectionPublishClientPort(_In_ PFLT_PORT ClientPort,
    _In_ PVOID ConnectionCookie, _In_ LONG64 ConnectionGeneration, _In_ ULONG ProcessId);
static VOID SafeUploadConnectionReadDrainState(_Out_ PBOOLEAN UsesDrained,
    _Out_ PBOOLEAN CallbacksDrained);
static BOOLEAN SafeUploadConnectionCommitAuthentication(_In_opt_ PVOID ConnectionCookie,
    _Out_opt_ PBOOLEAN FirstAuthentication);

static VOID SafeUploadCloseUnpublishedClientPort(VOID);
static NTSTATUS SafeUploadConnectionWaitForUses(VOID);
static NTSTATUS SafeUploadConnectionWaitForRetirement(VOID);

static NTSTATUS SafeUploadRequestVerdictInternal (
    _Inout_ PSAFEUPLOAD_EXCHANGE Exchange,
    _Out_ PUINT32 Verdict,
    _Out_ PBOOLEAN Answered,
    _In_opt_ PVOID ConnectionCookie,
    _In_ BOOLEAN ConnectionUseAlreadyPinned
    );

static BOOLEAN SafeUploadConnectionUseAcquire(_In_opt_ PVOID RequestedCookie,
    _In_ BOOLEAN RequireAuthentication, _Out_ PVOID *PinnedCookie);
static PVOID SafeUploadConnectionGetCurrentCookie(VOID);
static BOOLEAN SafeUploadConnectionUseIsCurrent(_In_opt_ PVOID ConnectionCookie,
    _In_ BOOLEAN RequireAuthentication);
static BOOLEAN SafeUploadConnectionUseIsCurrentForProcess(_In_opt_ PVOID ConnectionCookie,
    _In_ ULONG ProcessId);
static VOID SafeUploadConnectionUseRelease(_In_opt_ PVOID ConnectionCookie);
static BOOLEAN SafeUploadPortMessageAcquire(_In_opt_ PVOID ConnectionCookie);
static VOID SafeUploadPortMessageRelease(_In_opt_ PVOID ConnectionCookie);
static BOOLEAN SafeUploadControlCallbackEnter(_In_ BOOLEAN ConnectionScoped,
    _In_ BOOLEAN NewWorkCallback,
    _Out_ PBOOLEAN Admitted, _Outptr_result_maybenull_ PFLT_FILTER *ReferencedFilter);
static VOID SafeUploadControlCallbackLeave(_In_ BOOLEAN ConnectionScoped,
    _In_opt_ PFLT_FILTER ReferencedFilter);
static NTSTATUS SafeUploadConnectionWaitForControlCallbacks(VOID);
static VOID SafeUploadConnectionOpenAdmission(VOID);
#if SAFEUPLOAD_STAGING_PROTOTYPE
static VOID SafeUploadStageCallbackCloseAdmission(VOID);
static VOID SafeUploadStageCallbackOpenAdmission(VOID);
#endif
static VOID SafeUploadPortDisconnectInternal(_In_opt_ PVOID ConnectionCookie);
static NTSTATUS SafeUploadPortMessage(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength);
static NTSTATUS SafeUploadPortMessageInternal(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength);


#if SAFEUPLOAD_STAGING_PROTOTYPE
/* SAFEUPLOAD_CONTROL_STAGE_DISPOSE, out of line: the message routine's stack is at its analysis budget. The reply lives
 * in the kernel copy buffer after the message. */
static __declspec(noinline) NTSTATUS
SafeUploadStageDisposeControl (
    _In_reads_bytes_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength,
    _Inout_ PSAFEUPLOAD_POLICY_MESSAGE Scratch
    )
{
    PSAFEUPLOAD_STAGE_DISPOSE_MESSAGE dispose = (PSAFEUPLOAD_STAGE_DISPOSE_MESSAGE)Scratch;
    PSAFEUPLOAD_STAGE_DISPOSE_REPLY reply = (PSAFEUPLOAD_STAGE_DISPOSE_REPLY)(dispose + 1);
    NTSTATUS status;

    C_ASSERT( sizeof( SAFEUPLOAD_STAGE_DISPOSE_MESSAGE ) + sizeof( SAFEUPLOAD_STAGE_DISPOSE_REPLY ) <=
              sizeof( SAFEUPLOAD_POLICY_MESSAGE ) );
    *ReturnOutputBufferLength = 0;
    if (InputBufferLength != sizeof( SAFEUPLOAD_STAGE_DISPOSE_MESSAGE ) ||
        OutputBuffer == NULL || OutputBufferLength != sizeof( SAFEUPLOAD_STAGE_DISPOSE_REPLY )) {
        return STATUS_INVALID_BUFFER_SIZE;
    }
    __try {
        RtlCopyMemory( dispose, InputBuffer, sizeof( *dispose ) );
        /* Probe before the disposal takes effect, so a bad reply buffer cannot hide a disposal from the service. */
#pragma warning( suppress: 6001 )
        ProbeForWrite( OutputBuffer, sizeof( *reply ), __alignof( SAFEUPLOAD_STAGE_DISPOSE_REPLY ) );
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    reply->StructSize = sizeof( *reply );
    status = SafeUploadStageDispose( dispose, &reply->Held );
    if (!NT_SUCCESS( status )) return status;
    __try {
        RtlCopyMemory( OutputBuffer, reply, sizeof( *reply ) );
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    *ReturnOutputBufferLength = sizeof( *reply );
    return STATUS_SUCCESS;
}
#endif


BOOLEAN SafeUploadCurrentProcessHasAgentServiceSid(VOID);

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(PAGE, SafeUploadCreateCommunicationPort)
    #pragma alloc_text(PAGE, SafeUploadHasClientConnection)
    #pragma alloc_text(PAGE, SafeUploadCloseCommunicationPort)
    #pragma alloc_text(PAGE, SafeUploadWaitForCommunicationDrain)
    #pragma alloc_text(PAGE, SafeUploadTryCommunicationUnloadPreflight)
#if SAFEUPLOAD_STAGING_PROTOTYPE
    #pragma alloc_text(PAGE, SafeUploadTryStageCallbackUnloadPreflight)
    #pragma alloc_text(PAGE, SafeUploadOpenStageCallbackUnloadAdmission)
#endif
    #pragma alloc_text(PAGE, SafeUploadPortConnect)
    #pragma alloc_text(PAGE, SafeUploadPortConnectInternal)
    #pragma alloc_text(PAGE, SafeUploadPortDisconnect)
    #pragma alloc_text(PAGE, SafeUploadPortDisconnectInternal)
    #pragma alloc_text(PAGE, SafeUploadPortMessage)
    #pragma alloc_text(PAGE, SafeUploadPortMessageInternal)
    #pragma alloc_text(PAGE, SafeUploadRequestVerdict)
#if SAFEUPLOAD_STAGING_PROTOTYPE
    #pragma alloc_text(PAGE, SafeUploadRequestVerdictForPinnedConnection)
#endif
    #pragma alloc_text(PAGE, SafeUploadRequestVerdictInternal)
    #pragma alloc_text(PAGE, SafeUploadCurrentProcessHasAgentServiceSid)
    #pragma alloc_text(PAGE, SafeUploadRetireCurrentConnection)
#endif

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
{
    NTSTATUS status;
    BOOLEAN admitted;
    PFLT_FILTER referencedFilter;

    PAGED_CODE();
    *ReturnOutputBufferLength = 0;
    if (!SafeUploadControlCallbackEnter(TRUE, TRUE, &admitted, &referencedFilter))
        return STATUS_FLT_DELETING_OBJECT;
    if (referencedFilter == NULL) {
        SafeUploadControlCallbackLeave(TRUE, NULL);
        return STATUS_FLT_DELETING_OBJECT;
    }
    if (!admitted) {
        SafeUploadControlCallbackLeave(TRUE, referencedFilter);
        return STATUS_PORT_DISCONNECTED;
    }
    status = SafeUploadPortMessageInternal(PortCookie, InputBuffer,
        InputBufferLength, OutputBuffer, OutputBufferLength,
        ReturnOutputBufferLength);
    SafeUploadControlCallbackLeave(TRUE, referencedFilter);
    return status;
}

/* Documented fallback service SID for NT SERVICE\SafeUploadAgent:
 * SHA-1(uppercase service name as UTF-16LE), split into five little-endian
 * ULONG subauthorities after S-1-5-80. The fixed result is
 * S-1-5-80-2445692249-22211692-2238493510-3749888094-4283558424.
 * Prefer the kernel's RtlCreateServiceSid when exported. Keep the fallback
 * synchronized with Program.ServiceName and the installer. */
static const struct _SAFEUPLOAD_AGENT_SERVICE_SID {
    UCHAR Revision;
    UCHAR SubAuthorityCount;
    SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
    ULONG SubAuthority[6];
} SafeUploadAgentServiceSid = {
    SID_REVISION,
    6,
    {{0, 0, 0, 0, 0, 5}},
    {80, 2445692249, 22211692, 2238493510, 3749888094, 4283558424}
};

BOOLEAN SafeUploadCurrentProcessHasAgentServiceSid(VOID)
{
    typedef NTSTATUS (NTAPI *PSAFEUPLOAD_RTL_CREATE_SERVICE_SID)(
        PUNICODE_STRING ServiceName, PSID ServiceSid, PULONG ServiceSidLength);
    PACCESS_TOKEN token;
    PTOKEN_GROUPS groups = NULL;
    UCHAR serviceSidStorage[68];
    PSID serviceSid = (PSID)&SafeUploadAgentServiceSid;
    UNICODE_STRING serviceName, routineName;
    PSAFEUPLOAD_RTL_CREATE_SERVICE_SID createServiceSid;
    ULONG serviceSidLength;
    ULONG index;
    BOOLEAN found = FALSE;
    NTSTATUS status;

    PAGED_CODE();
    RtlInitUnicodeString(&serviceName, L"SafeUploadAgent");
    RtlInitUnicodeString(&routineName, L"RtlCreateServiceSid");
    createServiceSid = (PSAFEUPLOAD_RTL_CREATE_SERVICE_SID)MmGetSystemRoutineAddress(&routineName);
    if (createServiceSid != NULL) {
        RtlZeroMemory(serviceSidStorage, sizeof(serviceSidStorage));
        serviceSidLength = sizeof(serviceSidStorage);
        status = createServiceSid(&serviceName, (PSID)serviceSidStorage, &serviceSidLength);
        if (!NT_SUCCESS(status) || serviceSidLength < (ULONG)FIELD_OFFSET(SID, SubAuthority) ||
            serviceSidLength > sizeof(serviceSidStorage)) return FALSE;
        serviceSid = (PSID)serviceSidStorage;
    }
    token = PsReferencePrimaryToken(PsGetCurrentProcess());
    status = SeQueryInformationToken(token, TokenGroups, (PVOID *)&groups);
    if (NT_SUCCESS(status) && groups != NULL) {
        for (index = 0; index < groups->GroupCount; ++index) {
            if (RtlEqualSid(groups->Groups[index].Sid, serviceSid)) {
                found = TRUE;
                break;
            }
        }
    }
    if (groups != NULL) ExFreePool(groups);
    PsDereferencePrimaryToken(token);
    return found;
}


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

    FltInitializePushLock(&SafeUploadConnectionTransitionLock);
    KeInitializeSpinLock(&SafeUploadConnectionStateLock);
    KeInitializeEvent(&SafeUploadConnectionUsesDrained, NotificationEvent, TRUE);
    KeInitializeEvent(&SafeUploadControlCallbacksDrained, NotificationEvent, TRUE);
    KeInitializeEvent(&SafeUploadConnectionRetirementComplete, NotificationEvent, TRUE);
    InterlockedExchange64(&SafeUploadConnectionCookieSequence, 0);
    InterlockedExchangePointer(&SafeUploadCurrentConnectionCookie, NULL);
    InterlockedExchange64(&SafeUploadCurrentConnectionGeneration, 0);
    SafeUploadActiveConnectionUseCookie = NULL;
    SafeUploadActiveConnectionUseCount = 0;
    SafeUploadConnectionCallbackCount = 0;
    SafeUploadControlCallbackCount = 0;
    SafeUploadControlCallbackAdmissionClosed = FALSE;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    SafeUploadStageCallbackAdmissionClosed = FALSE;
    SafeUploadCurrentConnectionProcess = NULL;
#endif
    SafeUploadConnectionRetiring = FALSE;
    SafeUploadRetiringConnectionCookie = NULL;
    SafeUploadConnectionClosing = FALSE;

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


NTSTATUS
SafeUploadCloseCommunicationPort (
    VOID
    )
/*++

Routine Description:

    Permanently rejects new connections and retires the current client slot.
    It closes the server listener, then drains entered callbacks and channel
    uses for a bounded interval. The transition guard is dropped around
    FltCloseClientPort so a synchronous disconnect callback for the retired
    cookie can return.

    Closing the client port also releases any thread currently blocked
    inside FltSendMessage, which is what lets a mandatory unload make
    progress instead of waiting out the full verdict timeout.

    IRQL: PASSIVE_LEVEL. Called from DriverEntry's failure path and from
    the unload callback.

Arguments:

    STATUS_SUCCESS after accepted sends/callbacks drain, or
    STATUS_DEVICE_BUSY with the old slot revoked and replacement/publication
    disabled. A startup-failure caller, mandatory unload, or voluntary unload
    already past its last veto point must then perform the explicit unbounded
    communication drain before releasing state.

Return Value:

    NTSTATUS.

--*/
{
    PVOID connectionCookie;
    PFLT_PORT serverPortToClose = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    PAGED_CODE();

    FltAcquirePushLockExclusive(&SafeUploadConnectionTransitionLock);
    SafeUploadConnectionClosing = TRUE;
    SafeUploadConnectionCloseAdmission();
    connectionCookie = SafeUploadConnectionGetCurrentCookie();
    if (connectionCookie != NULL) {
        (VOID)SafeUploadRetireCurrentConnection(connectionCookie);
    } else if (SafeUploadData.ClientPort != NULL) {
        /* DriverEntry failure can reach here before a client cookie exists. */
        SafeUploadCloseUnpublishedClientPort();
    }
    status = SafeUploadConnectionWaitForRetirement();
    serverPortToClose = SafeUploadData.ServerPort;
    SafeUploadData.ServerPort = NULL;
    FltReleasePushLock(&SafeUploadConnectionTransitionLock);

    /* Closing the server port prevents new connections; it does not terminate
     * existing client connections, so the shared client slot was retired and
     * closed above. Keep the transition guard dropped around this PASSIVE-only
     * close and let the explicit callback counts, not an API drain assumption,
     * govern the later bounded/unbounded waits. */
    if (serverPortToClose != NULL) FltCloseCommunicationPort(serverPortToClose);

    FltAcquirePushLockExclusive(&SafeUploadConnectionTransitionLock);
    {
        NTSTATUS drainStatus = SafeUploadConnectionWaitForUses();
        if (NT_SUCCESS(drainStatus))
            drainStatus = SafeUploadConnectionWaitForControlCallbacks();
        if (NT_SUCCESS(status)) status = drainStatus;
    }
    FltReleasePushLock(&SafeUploadConnectionTransitionLock);
    return status;
}


NTSTATUS
SafeUploadTryCommunicationUnloadPreflight (
    VOID
    )
/*--

For a voluntary unload, temporarily close admission to new connect/message
work while the server port remains open. Drain the current channel uses and
callbacks with their existing bounded waits. If either wait times out, restore
admission before returning so the caller can veto without leaving the live
service disconnected. A successful return leaves admission closed; the caller
must proceed to port closure and must not veto after that point.

IRQL: PASSIVE_LEVEL.

--*/
{
    NTSTATUS status;

    PAGED_CODE();
    FltAcquirePushLockExclusive(&SafeUploadConnectionTransitionLock);
    if (SafeUploadConnectionClosing) {
        FltReleasePushLock(&SafeUploadConnectionTransitionLock);
        return STATUS_SUCCESS;
    }

    SafeUploadConnectionCloseAdmission();
    status = SafeUploadConnectionWaitForUses();
    if (NT_SUCCESS(status))
        status = SafeUploadConnectionWaitForControlCallbacks();
    if (!NT_SUCCESS(status)) {
        if (SafeUploadConnectionClosing)
            status = STATUS_SUCCESS;
        else
            SafeUploadConnectionOpenAdmission();
    }
    FltReleasePushLock(&SafeUploadConnectionTransitionLock);
    return status;
}

static
BOOLEAN
SafeUploadConnectionUseAcquire (
    _In_opt_ PVOID RequestedCookie,
    _In_ BOOLEAN RequireAuthentication,
    _Out_ PVOID *PinnedCookie
    )
{
    KIRQL oldIrql;
    BOOLEAN acquired = FALSE;
    PVOID currentCookie;

    if (PinnedCookie == NULL) return FALSE;
    *PinnedCookie = NULL;
    KeAcquireSpinLock(&SafeUploadConnectionStateLock, &oldIrql);
    currentCookie = InterlockedCompareExchangePointer(&SafeUploadCurrentConnectionCookie, NULL, NULL);
    if (currentCookie != NULL && SafeUploadCurrentConnectionGeneration > 0 &&
        !SafeUploadControlCallbackAdmissionClosed &&
        (RequestedCookie == NULL || RequestedCookie == currentCookie) &&
        (!RequireAuthentication ||
         InterlockedCompareExchange(&SafeUploadData.AuthenticatedClient, 0, 0) != 0) &&
        (SafeUploadActiveConnectionUseCount == 0 ||
         SafeUploadActiveConnectionUseCookie == currentCookie) &&
        SafeUploadActiveConnectionUseCount < MAXLONG) {
        if (SafeUploadActiveConnectionUseCount == 0) {
            SafeUploadActiveConnectionUseCookie = currentCookie;
            if (SafeUploadConnectionCallbackCount == 0)
                KeClearEvent(&SafeUploadConnectionUsesDrained);
        }
        ++SafeUploadActiveConnectionUseCount;
        *PinnedCookie = currentCookie;
        acquired = TRUE;
    }
    KeReleaseSpinLock(&SafeUploadConnectionStateLock, oldIrql);
    return acquired;
}

static
PVOID
SafeUploadConnectionGetCurrentCookie (
    VOID
    )
{
    KIRQL oldIrql;
    PVOID connectionCookie;

    KeAcquireSpinLock(&SafeUploadConnectionStateLock, &oldIrql);
    connectionCookie = InterlockedCompareExchangePointer(
        &SafeUploadCurrentConnectionCookie, NULL, NULL);
    KeReleaseSpinLock(&SafeUploadConnectionStateLock, oldIrql);
    return connectionCookie;
}

BOOLEAN
SafeUploadHasClientConnection (
    VOID
    )
{
    PAGED_CODE();
    return SafeUploadConnectionGetCurrentCookie() != NULL;
}

BOOLEAN
SafeUploadConnectionIsAuthenticated (
    VOID
    )
{
    KIRQL oldIrql;
    BOOLEAN authenticated;

    /* The current cookie, published port pointer, and authentication bit
     * share this lock. A disconnect therefore cannot leave Policy.c seeing
     * the old authenticated bit paired with a newly published connection. */
    KeAcquireSpinLock(&SafeUploadConnectionStateLock, &oldIrql);
    authenticated =
        InterlockedCompareExchangePointer(
            &SafeUploadCurrentConnectionCookie, NULL, NULL) != NULL &&
        SafeUploadCurrentConnectionGeneration > 0 &&
        !SafeUploadControlCallbackAdmissionClosed &&
        SafeUploadData.ClientPort != NULL &&
        InterlockedCompareExchange(&SafeUploadData.AuthenticatedClient, 0, 0) != 0;
    KeReleaseSpinLock(&SafeUploadConnectionStateLock, oldIrql);
    return authenticated;
}

BOOLEAN
SafeUploadConnectionGetAuthenticatedIdentity (
    _In_opt_ PVOID ExpectedCookie,
    _Out_ PVOID *ConnectionCookie,
    _Out_ PLONG64 ConnectionGeneration,
    _Out_ PULONG ProcessId
    )
{
    KIRQL oldIrql;
    PVOID currentCookie;
    LONG64 currentGeneration;
    BOOLEAN authenticated;

    if (ConnectionCookie == NULL || ConnectionGeneration == NULL || ProcessId == NULL)
        return FALSE;
    *ConnectionCookie = NULL;
    *ConnectionGeneration = 0;
    *ProcessId = 0;

    KeAcquireSpinLock(&SafeUploadConnectionStateLock, &oldIrql);
    currentCookie = InterlockedCompareExchangePointer(
        &SafeUploadCurrentConnectionCookie, NULL, NULL);
    currentGeneration = SafeUploadCurrentConnectionGeneration;
    authenticated = currentCookie != NULL &&
        (ExpectedCookie == NULL || currentCookie == ExpectedCookie) &&
        currentGeneration > 0 &&
        !SafeUploadControlCallbackAdmissionClosed &&
        SafeUploadData.ClientPort != NULL &&
        InterlockedCompareExchange(&SafeUploadData.AuthenticatedClient, 0, 0) != 0;
    if (authenticated) {
        *ConnectionCookie = currentCookie;
        *ConnectionGeneration = currentGeneration;
        *ProcessId = SafeUploadData.InspectorProcessId;
    }
    KeReleaseSpinLock(&SafeUploadConnectionStateLock, oldIrql);
    return authenticated;
}

BOOLEAN
SafeUploadConnectionIsAuthenticatedIdentity (
    _In_opt_ PVOID ConnectionCookie,
    _In_ LONG64 ConnectionGeneration
    )
{
    KIRQL oldIrql;
    BOOLEAN authenticated;

    if (ConnectionCookie == NULL || ConnectionGeneration <= 0) return FALSE;
    KeAcquireSpinLock(&SafeUploadConnectionStateLock, &oldIrql);
    authenticated =
        InterlockedCompareExchangePointer(
            &SafeUploadCurrentConnectionCookie, NULL, NULL) == ConnectionCookie &&
        SafeUploadCurrentConnectionGeneration == ConnectionGeneration &&
        !SafeUploadControlCallbackAdmissionClosed &&
        SafeUploadData.ClientPort != NULL &&
        InterlockedCompareExchange(&SafeUploadData.AuthenticatedClient, 0, 0) != 0;
    KeReleaseSpinLock(&SafeUploadConnectionStateLock, oldIrql);
    return authenticated;
}

/* These state-only helpers remain resident because they acquire the
 * communication spin lock. Their pageable callers establish PASSIVE_LEVEL;
 * no helper waits, closes a port, queries a token, or calls another pageable
 * routine while the lock is held. */
static VOID SafeUploadConnectionCloseAdmission(VOID)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&SafeUploadConnectionStateLock, &oldIrql);
    SafeUploadControlCallbackAdmissionClosed = TRUE;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    SafeUploadStageCallbackAdmissionClosed = TRUE;
#endif
    KeReleaseSpinLock(&SafeUploadConnectionStateLock, oldIrql);
}

static VOID SafeUploadConnectionOpenAdmission(VOID)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&SafeUploadConnectionStateLock, &oldIrql);
    if (!SafeUploadConnectionClosing) {
        SafeUploadControlCallbackAdmissionClosed = FALSE;
#if SAFEUPLOAD_STAGING_PROTOTYPE
        SafeUploadStageCallbackAdmissionClosed = FALSE;
#endif
    }
    KeReleaseSpinLock(&SafeUploadConnectionStateLock, oldIrql);
}

#if SAFEUPLOAD_STAGING_PROTOTYPE
/* Caller holds SafeUploadConnectionTransitionLock. This callback-only gate
 * does not affect outbound connection-use pins or FilterReplyMessage. */
static VOID SafeUploadStageCallbackCloseAdmission(VOID)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&SafeUploadConnectionStateLock, &oldIrql);
    SafeUploadStageCallbackAdmissionClosed = TRUE;
    KeReleaseSpinLock(&SafeUploadConnectionStateLock, oldIrql);
}

/* Caller holds SafeUploadConnectionTransitionLock. Never reopen callback
 * bodies after port close has committed. */
static VOID SafeUploadStageCallbackOpenAdmission(VOID)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&SafeUploadConnectionStateLock, &oldIrql);
    if (!SafeUploadConnectionClosing)
        SafeUploadStageCallbackAdmissionClosed = FALSE;
    KeReleaseSpinLock(&SafeUploadConnectionStateLock, oldIrql);
}

NTSTATUS SafeUploadTryStageCallbackUnloadPreflight(VOID)
{
    NTSTATUS status;

    PAGED_CODE();
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    FltAcquirePushLockExclusive(&SafeUploadConnectionTransitionLock);
    if (SafeUploadConnectionClosing) {
        FltReleasePushLock(&SafeUploadConnectionTransitionLock);
        return STATUS_DEVICE_BUSY;
    }

    SafeUploadStageCallbackCloseAdmission();
    /* The callback wait drops the transition lock. New Connect/Message bodies
     * remain denied by the state gate, while exact outbound channel uses stay
     * available to stage cleanup and the epoch-drain exchange. Disconnect is
     * still cleanup-admitted and may retire only its exact current cookie.
     * A denied callback may be invoked after this count reaches zero, but its
     * admission decision takes the same state lock and prevents its body from
     * touching stage state; neither this wait nor the count proves that
     * Filter Manager has stopped invoking the callback pointer. */
    status = SafeUploadConnectionWaitForControlCallbacks();
    if (!NT_SUCCESS(status)) {
        if (SafeUploadConnectionClosing)
            status = STATUS_DEVICE_BUSY;
        else
            SafeUploadStageCallbackOpenAdmission();
    }
    FltReleasePushLock(&SafeUploadConnectionTransitionLock);
    return status;
}

VOID SafeUploadOpenStageCallbackUnloadAdmission(VOID)
{
    PAGED_CODE();
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    FltAcquirePushLockExclusive(&SafeUploadConnectionTransitionLock);
    SafeUploadStageCallbackOpenAdmission();
    FltReleasePushLock(&SafeUploadConnectionTransitionLock);
}
#endif

static BOOLEAN SafeUploadConnectionRetireState(
    _In_opt_ PVOID ConnectionCookie,
    _Out_ PULONG ProcessId,
    _Out_ PBOOLEAN CloseClientPort,
    _Out_ PLONG64 ConnectionGeneration)
{
    KIRQL oldIrql;
    PVOID currentCookie;
    if (ProcessId == NULL || CloseClientPort == NULL || ConnectionGeneration == NULL)
        return FALSE;
    *ProcessId = 0;
    *CloseClientPort = FALSE;
    *ConnectionGeneration = 0;
    if (ConnectionCookie == NULL || SafeUploadConnectionRetiring) return FALSE;

    KeAcquireSpinLock(&SafeUploadConnectionStateLock, &oldIrql);
    currentCookie = InterlockedCompareExchangePointer(
        &SafeUploadCurrentConnectionCookie, NULL, NULL);
    if (currentCookie != ConnectionCookie) {
        KeReleaseSpinLock(&SafeUploadConnectionStateLock, oldIrql);
        return FALSE;
    }

    *ProcessId = SafeUploadData.InspectorProcessId;
    *CloseClientPort = SafeUploadData.ClientPort != NULL;
    *ConnectionGeneration = SafeUploadCurrentConnectionGeneration;
    InterlockedExchangePointer(&SafeUploadCurrentConnectionCookie, NULL);
    SafeUploadCurrentConnectionGeneration = 0;
    InterlockedExchange(&SafeUploadData.AuthenticatedClient, 0);
    SafeUploadConnectionRetiring = TRUE;
    SafeUploadRetiringConnectionCookie = ConnectionCookie;
    KeClearEvent(&SafeUploadConnectionRetirementComplete);
    KeReleaseSpinLock(&SafeUploadConnectionStateLock, oldIrql);
    return TRUE;
}

static VOID SafeUploadConnectionResetInspectorProcessId(VOID)
{
    KIRQL oldIrql;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    PEPROCESS process;
#endif
    KeAcquireSpinLock(&SafeUploadConnectionStateLock, &oldIrql);
    SafeUploadData.InspectorProcessId = 0;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    process = SafeUploadCurrentConnectionProcess;
    SafeUploadCurrentConnectionProcess = NULL;
#endif
    KeReleaseSpinLock(&SafeUploadConnectionStateLock, oldIrql);
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (process != NULL) ObDereferenceObject(process);
#endif
}

static BOOLEAN SafeUploadConnectionPublishClientPort(
    _In_ PFLT_PORT ClientPort,
    _In_ PVOID ConnectionCookie,
    _In_ LONG64 ConnectionGeneration,
    _In_ ULONG ProcessId)
{
    KIRQL oldIrql;
    BOOLEAN published = FALSE;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    PEPROCESS process;
#endif
    if (ClientPort == NULL || ConnectionCookie == NULL ||
        ConnectionGeneration <= 0 || ProcessId == 0) return FALSE;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    /* Only PortConnect calls this helper, in the accepted process context. */
    if (HandleToULong(PsGetCurrentProcessId()) != ProcessId) return FALSE;
    process = PsGetCurrentProcess();
    ObReferenceObject(process);
#endif

    KeAcquireSpinLock(&SafeUploadConnectionStateLock, &oldIrql);
    if (!SafeUploadControlCallbackAdmissionClosed &&
        InterlockedCompareExchangePointer(
            &SafeUploadCurrentConnectionCookie, NULL, NULL) == NULL &&
        SafeUploadData.ClientPort == NULL
#if SAFEUPLOAD_STAGING_PROTOTYPE
        && SafeUploadCurrentConnectionProcess == NULL
#endif
        ) {
        InterlockedExchange(&SafeUploadData.AuthenticatedClient, 0);
        SafeUploadData.InspectorProcessId = ProcessId;
        SafeUploadData.ClientPort = ClientPort;
        SafeUploadCurrentConnectionGeneration = ConnectionGeneration;
#if SAFEUPLOAD_STAGING_PROTOTYPE
        SafeUploadCurrentConnectionProcess = process;
#endif
        InterlockedExchangePointer(&SafeUploadCurrentConnectionCookie, ConnectionCookie);
        published = TRUE;
    }
    KeReleaseSpinLock(&SafeUploadConnectionStateLock, oldIrql);
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (!published) ObDereferenceObject(process);
#endif
    return published;
}

static VOID SafeUploadConnectionReadDrainState(
    _Out_ PBOOLEAN UsesDrained,
    _Out_ PBOOLEAN CallbacksDrained)
{
    KIRQL oldIrql;
    if (UsesDrained == NULL || CallbacksDrained == NULL) return;
    KeAcquireSpinLock(&SafeUploadConnectionStateLock, &oldIrql);
    *UsesDrained = SafeUploadActiveConnectionUseCount == 0 &&
        SafeUploadConnectionCallbackCount == 0;
    *CallbacksDrained = SafeUploadControlCallbackCount == 0;
    if (!*UsesDrained) KeClearEvent(&SafeUploadConnectionUsesDrained);
    if (!*CallbacksDrained) KeClearEvent(&SafeUploadControlCallbacksDrained);
    KeReleaseSpinLock(&SafeUploadConnectionStateLock, oldIrql);
}

static BOOLEAN SafeUploadConnectionCommitAuthentication(
    _In_opt_ PVOID ConnectionCookie,
    _Out_opt_ PBOOLEAN FirstAuthentication)
{
    KIRQL oldIrql;
    BOOLEAN committed = FALSE;
    PVOID currentCookie;
    if (FirstAuthentication != NULL) *FirstAuthentication = FALSE;
    if (ConnectionCookie == NULL) return FALSE;

    KeAcquireSpinLock(&SafeUploadConnectionStateLock, &oldIrql);
    currentCookie = InterlockedCompareExchangePointer(
        &SafeUploadCurrentConnectionCookie, NULL, NULL);
    if (currentCookie == ConnectionCookie &&
        SafeUploadCurrentConnectionGeneration > 0 &&
        !SafeUploadControlCallbackAdmissionClosed &&
        SafeUploadData.ClientPort != NULL) {
        BOOLEAN wasAuthenticated = InterlockedExchange(
            &SafeUploadData.AuthenticatedClient, 1) == 0;
        if (FirstAuthentication != NULL) *FirstAuthentication = wasAuthenticated;
        committed = TRUE;
    }
    KeReleaseSpinLock(&SafeUploadConnectionStateLock, oldIrql);
    return committed;
}

static
BOOLEAN
SafeUploadConnectionUseIsCurrent (
    _In_opt_ PVOID ConnectionCookie,
    _In_ BOOLEAN RequireAuthentication
    )
{
    KIRQL oldIrql;
    BOOLEAN current;

    if (ConnectionCookie == NULL) return FALSE;
    KeAcquireSpinLock(&SafeUploadConnectionStateLock, &oldIrql);
    current = InterlockedCompareExchangePointer(
        &SafeUploadCurrentConnectionCookie, NULL, NULL) == ConnectionCookie &&
        SafeUploadCurrentConnectionGeneration > 0 &&
        !SafeUploadControlCallbackAdmissionClosed &&
        (!RequireAuthentication ||
         InterlockedCompareExchange(&SafeUploadData.AuthenticatedClient, 0, 0) != 0);
    KeReleaseSpinLock(&SafeUploadConnectionStateLock, oldIrql);
    return current;
}

static
BOOLEAN
SafeUploadConnectionUseIsCurrentForProcess (
    _In_opt_ PVOID ConnectionCookie,
    _In_ ULONG ProcessId
    )
{
    KIRQL oldIrql;
    BOOLEAN current;

    if (ConnectionCookie == NULL || ProcessId == 0) return FALSE;
    KeAcquireSpinLock(&SafeUploadConnectionStateLock, &oldIrql);
    current = InterlockedCompareExchangePointer(
        &SafeUploadCurrentConnectionCookie, NULL, NULL) == ConnectionCookie &&
        SafeUploadCurrentConnectionGeneration > 0 &&
        !SafeUploadControlCallbackAdmissionClosed &&
        SafeUploadData.InspectorProcessId == ProcessId;
    KeReleaseSpinLock(&SafeUploadConnectionStateLock, oldIrql);
    return current;
}

static
VOID
SafeUploadConnectionUseRelease (
    _In_opt_ PVOID ConnectionCookie
    )
{
    KIRQL oldIrql;
    if (ConnectionCookie == NULL) return;
    KeAcquireSpinLock(&SafeUploadConnectionStateLock, &oldIrql);
    if (SafeUploadActiveConnectionUseCookie == ConnectionCookie &&
        SafeUploadActiveConnectionUseCount > 0) {
        --SafeUploadActiveConnectionUseCount;
        if (SafeUploadActiveConnectionUseCount == 0) {
            SafeUploadActiveConnectionUseCookie = NULL;
            if (SafeUploadConnectionCallbackCount == 0)
                KeSetEvent(&SafeUploadConnectionUsesDrained, IO_NO_INCREMENT, FALSE);
        }
    }
    KeReleaseSpinLock(&SafeUploadConnectionStateLock, oldIrql);
}

/* Each callback first takes EX rundown protection and then references the
 * Filter object when it is still referenceable. New-work callback admission
 * is separate from outbound channel-use admission; Disconnect cleanup ignores
 * both gates and remains cookie-scoped. Counts/events are drain aids, never
 * the callback-source removal proof. */
static
BOOLEAN
SafeUploadControlCallbackEnter (
    _In_ BOOLEAN ConnectionScoped,
    _In_ BOOLEAN NewWorkCallback,
    _Out_ PBOOLEAN Admitted,
    _Outptr_result_maybenull_ PFLT_FILTER *ReferencedFilter
    )
{
    KIRQL oldIrql;
    PFLT_FILTER filter;

    *Admitted = FALSE;
    *ReferencedFilter = NULL;

    /* This rundown acquisition is the first shared-state operation. It
     * protects callback-reachable globals through return; it does not protect
     * callback code itself. FltCreateCommunicationPort binds the caller's
     * Connect/Disconnect/Message callback pointers to this Filter, and the
     * Microsoft communication overview classifies them as minifilter callback
     * routines. The FltUnregisterFilter DDI says Filter Manager no longer calls
     * the minifilter and unregisters its callback routines. We apply that
     * broad callback-unregistration contract to the Filter-bound port
     * callbacks as the source/code-image barrier. The DDI does not enumerate
     * these three callback types in that sentence, so the application remains
     * an explicit architecture interpretation for independent review; local
     * counts and EX rundown protect state only and never substitute for this
     * source boundary. A failed rundown acquire must return without reading
     * any mutable global. */
    if (!ExAcquireRundownProtection(&SafeUploadData.CommunicationCallbackRundown))
        return FALSE;

    filter = SafeUploadData.Filter;
    if (filter != NULL && NT_SUCCESS(FltObjectReference(filter)))
        *ReferencedFilter = filter;

    KeAcquireSpinLock(&SafeUploadConnectionStateLock, &oldIrql);
    if (SafeUploadControlCallbackCount == 0)
        KeClearEvent(&SafeUploadControlCallbacksDrained);
    ++SafeUploadControlCallbackCount;
    if (ConnectionScoped) {
        if (SafeUploadConnectionCallbackCount == 0 &&
            SafeUploadActiveConnectionUseCount == 0) {
            KeClearEvent(&SafeUploadConnectionUsesDrained);
        }
        ++SafeUploadConnectionCallbackCount;
    }
    *Admitted = *ReferencedFilter != NULL &&
        !SafeUploadControlCallbackAdmissionClosed;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (NewWorkCallback && SafeUploadStageCallbackAdmissionClosed)
        *Admitted = FALSE;
#else
    UNREFERENCED_PARAMETER(NewWorkCallback);
#endif
    KeReleaseSpinLock(&SafeUploadConnectionStateLock, oldIrql);
    return TRUE;
}

static
VOID
SafeUploadControlCallbackLeave (
    _In_ BOOLEAN ConnectionScoped,
    _In_opt_ PFLT_FILTER ReferencedFilter
    )
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&SafeUploadConnectionStateLock, &oldIrql);
    NT_ASSERT(SafeUploadControlCallbackCount > 0);
    if (SafeUploadControlCallbackCount > 0) {
        --SafeUploadControlCallbackCount;
        if (SafeUploadControlCallbackCount == 0)
            KeSetEvent(&SafeUploadControlCallbacksDrained, IO_NO_INCREMENT, FALSE);
    }
    if (ConnectionScoped) {
        NT_ASSERT(SafeUploadConnectionCallbackCount > 0);
        if (SafeUploadConnectionCallbackCount > 0) {
            --SafeUploadConnectionCallbackCount;
            if (SafeUploadConnectionCallbackCount == 0 &&
                SafeUploadActiveConnectionUseCount == 0) {
                KeSetEvent(&SafeUploadConnectionUsesDrained, IO_NO_INCREMENT, FALSE);
            }
        }
    }
    KeReleaseSpinLock(&SafeUploadConnectionStateLock, oldIrql);
    if (ReferencedFilter != NULL) FltObjectDereference(ReferencedFilter);
    ExReleaseRundownProtection(&SafeUploadData.CommunicationCallbackRundown);
}

static
BOOLEAN
SafeUploadPortMessageAcquire (
    _In_opt_ PVOID ConnectionCookie
    )
{
    PVOID pinnedCookie = NULL;
    if (ConnectionCookie == NULL ||
        !SafeUploadConnectionUseAcquire(ConnectionCookie, FALSE, &pinnedCookie)) return FALSE;
    if (pinnedCookie != ConnectionCookie) {
        SafeUploadConnectionUseRelease(pinnedCookie);
        return FALSE;
    }
    return TRUE;
}

static
VOID
SafeUploadPortMessageRelease (
    _In_opt_ PVOID ConnectionCookie
    )
{
    SafeUploadConnectionUseRelease(ConnectionCookie);
}

static
BOOLEAN
SafeUploadRetireCurrentConnection (
    _In_opt_ PVOID ConnectionCookie
    )
{
    BOOLEAN closeClientPort;
    ULONG processId;
    LONG64 connectionGeneration;

    PAGED_CODE();
    if (ConnectionCookie == NULL || SafeUploadConnectionRetiring) return FALSE;
    /* Revoke both authorities in a resident state-only helper before closing.
     * Retiring is visible under the transition guard, so a replacement cannot
     * publish into the shared send slot while this connection is closed. */
    if (!SafeUploadConnectionRetireState(ConnectionCookie, &processId,
            &closeClientPort, &connectionGeneration)) return FALSE;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    SafeUploadStageProtocolConnectionReset(ConnectionCookie);
#endif

    /* FltCloseClientPort can deliver a disconnect callback. Release the
     * transition lock first; that callback sees the retired token and returns
     * without taking ownership of the close. */
    FltReleasePushLock(&SafeUploadConnectionTransitionLock);
    if (closeClientPort) {
        /* Keep using the shared slot passed to FltSendMessage. Filter Manager
         * synchronizes this close with sends through that exact address. */
        NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
        FltCloseClientPort(SafeUploadData.Filter, &SafeUploadData.ClientPort);
    }

    /* Finish all old-cookie state changes while Retiring still blocks a new
     * publication. In particular an accepted policy callback that passed
     * its earlier cookie test remains counted and cannot cross the replacement
     * boundary before this notification completes. */
    SafeUploadConnectionResetInspectorProcessId();
#if SAFEUPLOAD_STAGING_PROTOTYPE
    SafeUploadClearPublicationPermitsForConnection(ConnectionCookie, connectionGeneration);
    SafeUploadStageServiceDisconnected(ConnectionCookie);
#endif
    SafeUploadTrace("inspector disconnected, pid %lu\n", processId);

    FltAcquirePushLockExclusive(&SafeUploadConnectionTransitionLock);
    SafeUploadRetiringConnectionCookie = NULL;
    SafeUploadConnectionRetiring = FALSE;
    KeSetEvent(&SafeUploadConnectionRetirementComplete, IO_NO_INCREMENT, FALSE);
    return TRUE;
}

static
VOID
SafeUploadCloseUnpublishedClientPort (
    VOID
    )
{
    KIRQL oldIrql;
    BOOLEAN closeClientPort;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (SafeUploadConnectionRetiring || SafeUploadData.ClientPort == NULL) return;
    SafeUploadConnectionRetiring = TRUE;
    SafeUploadRetiringConnectionCookie = NULL;
    KeClearEvent(&SafeUploadConnectionRetirementComplete);
    KeAcquireSpinLock(&SafeUploadConnectionStateLock, &oldIrql);
    InterlockedExchange(&SafeUploadData.AuthenticatedClient, 0);
    SafeUploadData.InspectorProcessId = 0;
    InterlockedExchangePointer(&SafeUploadCurrentConnectionCookie, NULL);
    SafeUploadCurrentConnectionGeneration = 0;
    closeClientPort = SafeUploadData.ClientPort != NULL;
    KeReleaseSpinLock(&SafeUploadConnectionStateLock, oldIrql);

    FltReleasePushLock(&SafeUploadConnectionTransitionLock);
    if (closeClientPort) {
        NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
        FltCloseClientPort(SafeUploadData.Filter, &SafeUploadData.ClientPort);
    }
    SafeUploadConnectionResetInspectorProcessId();
#if SAFEUPLOAD_STAGING_PROTOTYPE
    SafeUploadClearPublicationPermits();
#endif
    FltAcquirePushLockExclusive(&SafeUploadConnectionTransitionLock);
    SafeUploadRetiringConnectionCookie = NULL;
    SafeUploadConnectionRetiring = FALSE;
    KeSetEvent(&SafeUploadConnectionRetirementComplete, IO_NO_INCREMENT, FALSE);
}

/* These two wait helpers are called with the transition push lock held. They
 * drop it across the bounded wait; Retiring/Closing prevents any publication
 * that could otherwise reuse the state being drained. */
static
NTSTATUS
SafeUploadConnectionWaitForUses (
    VOID
    )
{
    KIRQL oldIrql;
    BOOLEAN drained;
    NTSTATUS waitStatus;
    LARGE_INTEGER timeout;

    KeAcquireSpinLock(&SafeUploadConnectionStateLock, &oldIrql);
    drained = SafeUploadActiveConnectionUseCount == 0 &&
        SafeUploadConnectionCallbackCount == 0;
    if (!drained) KeClearEvent(&SafeUploadConnectionUsesDrained);
    KeReleaseSpinLock(&SafeUploadConnectionStateLock, oldIrql);
    if (drained) return STATUS_SUCCESS;

    timeout.QuadPart = -5LL * 10 * 1000 * 1000;
    FltReleasePushLock(&SafeUploadConnectionTransitionLock);
    waitStatus = KeWaitForSingleObject(&SafeUploadConnectionUsesDrained,
        Executive, KernelMode, FALSE, &timeout);
    FltAcquirePushLockExclusive(&SafeUploadConnectionTransitionLock);

    KeAcquireSpinLock(&SafeUploadConnectionStateLock, &oldIrql);
    drained = SafeUploadActiveConnectionUseCount == 0 &&
        SafeUploadConnectionCallbackCount == 0;
    KeReleaseSpinLock(&SafeUploadConnectionStateLock, oldIrql);
    if (!drained || waitStatus == STATUS_TIMEOUT) return STATUS_DEVICE_BUSY;
    return STATUS_SUCCESS;
}

static
NTSTATUS
SafeUploadConnectionWaitForControlCallbacks (
    VOID
    )
{
    KIRQL oldIrql;
    BOOLEAN drained;
    NTSTATUS waitStatus;
    LARGE_INTEGER timeout;

    KeAcquireSpinLock(&SafeUploadConnectionStateLock, &oldIrql);
    drained = SafeUploadControlCallbackCount == 0;
    if (!drained) KeClearEvent(&SafeUploadControlCallbacksDrained);
    KeReleaseSpinLock(&SafeUploadConnectionStateLock, oldIrql);
    if (drained) return STATUS_SUCCESS;

    timeout.QuadPart = -5LL * 10 * 1000 * 1000;
    FltReleasePushLock(&SafeUploadConnectionTransitionLock);
    waitStatus = KeWaitForSingleObject(&SafeUploadControlCallbacksDrained,
        Executive, KernelMode, FALSE, &timeout);
    FltAcquirePushLockExclusive(&SafeUploadConnectionTransitionLock);

    KeAcquireSpinLock(&SafeUploadConnectionStateLock, &oldIrql);
    drained = SafeUploadControlCallbackCount == 0;
    KeReleaseSpinLock(&SafeUploadConnectionStateLock, oldIrql);
    if (!drained || waitStatus == STATUS_TIMEOUT) return STATUS_DEVICE_BUSY;
    return STATUS_SUCCESS;
}

VOID
SafeUploadWaitForCommunicationDrain (
    VOID
    )
/*--

Mandatory teardown and DriverEntry failure unwind cannot be refused. A
voluntary unload also uses this safety wait if it has crossed the last veto
point. After SafeUploadCloseCommunicationPort has revoked the cookie and
closed the server port, this waits without a transition, communication,
namespace, Exchange, or spin lock until every counted channel use and control
callback has left. It is intentionally unbounded; it is not a bounded teardown
guarantee or a source-removal proof. Connect/message callbacks that enter after
admission closes are rejected. Disconnect remains cleanup-admitted, but the
close path retires the current cookie before this wait, so a later stale-cookie
disconnect cannot reset stage state. FltUnregisterFilter plus the callback
rundown below remains the final lifetime boundary.

IRQL: PASSIVE_LEVEL.

--*/
{
    BOOLEAN usesDrained;
    BOOLEAN callbacksDrained;

    PAGED_CODE();
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    for (;;) {
        SafeUploadConnectionReadDrainState(&usesDrained, &callbacksDrained);

        if (usesDrained && callbacksDrained) return;
        if (!usesDrained) {
            (VOID)KeWaitForSingleObject(&SafeUploadConnectionUsesDrained,
                Executive, KernelMode, FALSE, NULL);
        } else {
            (VOID)KeWaitForSingleObject(&SafeUploadControlCallbacksDrained,
                Executive, KernelMode, FALSE, NULL);
        }
    }
}

static
NTSTATUS
SafeUploadConnectionWaitForRetirement (
    VOID
    )
{
    NTSTATUS waitStatus;
    LARGE_INTEGER timeout;

    if (!SafeUploadConnectionRetiring) return STATUS_SUCCESS;
    timeout.QuadPart = -5LL * 10 * 1000 * 1000;
    FltReleasePushLock(&SafeUploadConnectionTransitionLock);
    waitStatus = KeWaitForSingleObject(&SafeUploadConnectionRetirementComplete,
        Executive, KernelMode, FALSE, &timeout);
    FltAcquirePushLockExclusive(&SafeUploadConnectionTransitionLock);
    if (SafeUploadConnectionRetiring || waitStatus == STATUS_TIMEOUT)
        return STATUS_DEVICE_BUSY;
    return STATUS_SUCCESS;
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
{
    NTSTATUS status;
    BOOLEAN admitted;
    PFLT_FILTER referencedFilter;

    PAGED_CODE();
    *ConnectionCookie = NULL;
    if (!SafeUploadControlCallbackEnter(FALSE, TRUE, &admitted, &referencedFilter))
        return STATUS_FLT_DELETING_OBJECT;
    if (referencedFilter == NULL) {
        SafeUploadControlCallbackLeave(FALSE, NULL);
        return STATUS_FLT_DELETING_OBJECT;
    }
    if (!admitted) {
        SafeUploadControlCallbackLeave(FALSE, referencedFilter);
        return STATUS_DEVICE_BUSY;
    }
    status = SafeUploadPortConnectInternal(ClientPort, ServerPortCookie,
        ConnectionContext, SizeOfContext, ConnectionCookie);
    SafeUploadControlCallbackLeave(FALSE, referencedFilter);
    return status;
}

static
NTSTATUS
SafeUploadPortConnectInternal (
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

    ConnectionCookie - Receives the new connection's unique opaque cookie.

Return Value:

    STATUS_SUCCESS to accept the connection.

--*/
{
    LONG64 cookieValue;
    PVOID connectionCookie;
    PVOID previousCookie;
    ULONG processId;
    NTSTATUS status;

    UNREFERENCED_PARAMETER( ServerPortCookie );
    UNREFERENCED_PARAMETER( ConnectionContext );
    UNREFERENCED_PARAMETER( SizeOfContext );

    PAGED_CODE();
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    *ConnectionCookie = NULL;

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

    processId = HandleToULong(PsGetCurrentProcessId());
    if (processId == 0) return STATUS_ACCESS_DENIED;

    /* MaxConnections bounds simultaneous clients; it does not serialize a
     * new connect with the old disconnect callback. The cookie-bound retire
     * below handles either callback order without reusing the shared slot. */
    FltAcquirePushLockExclusive(&SafeUploadConnectionTransitionLock);
    if (SafeUploadConnectionClosing || SafeUploadConnectionRetiring) {
        FltReleasePushLock(&SafeUploadConnectionTransitionLock);
        return STATUS_DEVICE_BUSY;
    }
    previousCookie = SafeUploadConnectionGetCurrentCookie();
    if (previousCookie != NULL) {
        (VOID)SafeUploadRetireCurrentConnection(previousCookie);
    } else if (SafeUploadData.ClientPort != NULL) {
        /* Defensive recovery for partial startup/teardown state. */
        SafeUploadCloseUnpublishedClientPort();
    }
    if (SafeUploadConnectionClosing || SafeUploadConnectionRetiring) {
        FltReleasePushLock(&SafeUploadConnectionTransitionLock);
        return STATUS_DEVICE_BUSY;
    }
    status = SafeUploadConnectionWaitForUses();
    if (!NT_SUCCESS(status)) {
        FltReleasePushLock(&SafeUploadConnectionTransitionLock);
        return status;
    }
    /* Another connect may have won while the bounded drain wait released the
     * transition guard. Only one callback can claim the now-empty slot. */
    if (SafeUploadConnectionClosing || SafeUploadConnectionRetiring ||
        SafeUploadConnectionGetCurrentCookie() != NULL || SafeUploadData.ClientPort != NULL) {
        FltReleasePushLock(&SafeUploadConnectionTransitionLock);
        return STATUS_DEVICE_BUSY;
    }

    cookieValue = InterlockedIncrement64(&SafeUploadConnectionCookieSequence);
    if (cookieValue <= 0 ||
        (ULONGLONG)(ULONG_PTR)cookieValue != (ULONGLONG)cookieValue ||
        (ULONGLONG)cookieValue > 0x00007fffffffffffULL) {
        FltReleasePushLock(&SafeUploadConnectionTransitionLock);
        return STATUS_TOO_MANY_CONTEXT_IDS;
    }
    connectionCookie = (PVOID)(ULONG_PTR)cookieValue;

#if SAFEUPLOAD_STAGING_PROTOTYPE
    /* The old shared slot was closed and all accepted uses drained above;
     * StageProtocol publishes the replacement under its short state lock. */
    SafeUploadStageProtocolPublishClientPort(connectionCookie);
#endif
    if (!SafeUploadConnectionPublishClientPort(ClientPort, connectionCookie,
            cookieValue, processId)) {
#if SAFEUPLOAD_STAGING_PROTOTYPE
        SafeUploadStageProtocolConnectionReset(connectionCookie);
#endif
        FltReleasePushLock(&SafeUploadConnectionTransitionLock);
        return STATUS_DEVICE_BUSY;
    }
    *ConnectionCookie = connectionCookie;

    SafeUploadTrace( "inspector connected, pid %lu\n",
                     SafeUploadData.InspectorProcessId );

    status = STATUS_SUCCESS;
    FltReleasePushLock(&SafeUploadConnectionTransitionLock);
    return status;
}


static
VOID
SafeUploadPortDisconnect (
    _In_opt_ PVOID ConnectionCookie
    )
{
    BOOLEAN admitted;
    PFLT_FILTER referencedFilter;

    PAGED_CODE();
    if (!SafeUploadControlCallbackEnter(TRUE, FALSE, &admitted, &referencedFilter)) return;
    /* Disconnect is cleanup admission, not new-work admission. It must
     * retire only this exact current cookie even when teardown has closed the
     * connect/message gate. If FltObjectReference reports deletion,
     * FltCloseClientPort remains the documented DisconnectNotify cleanup
     * path; callback rundown protects its reachable state through return. */
    UNREFERENCED_PARAMETER(admitted);
    SafeUploadPortDisconnectInternal(ConnectionCookie);
    SafeUploadControlCallbackLeave(TRUE, referencedFilter);
}

static
VOID
SafeUploadPortDisconnectInternal (
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

    ConnectionCookie - Identity of the port being disconnected. A delayed
        callback may be stale after a replacement has already been published.

Return Value:

    None.

--*/
{
    PAGED_CODE();
    FltAcquirePushLockExclusive(&SafeUploadConnectionTransitionLock);
    if (SafeUploadConnectionRetiring && SafeUploadRetiringConnectionCookie == ConnectionCookie) {
        /* FltCloseClientPort may call back synchronously for this retired
         * cookie; the retirement owner already revoked and owns the close. */
        FltReleasePushLock(&SafeUploadConnectionTransitionLock);
        return;
    }
    if (SafeUploadRetireCurrentConnection(ConnectionCookie)) {
        /* Retire performed the conditional auth revoke, protocol reset, and
         * close through the shared port slot, dropping the transition guard
         * only around Filter Manager's shared-slot close. */
    }
    FltReleasePushLock(&SafeUploadConnectionTransitionLock);
}


static NTSTATUS
SafeUploadRequestVerdictInternal (
    _Inout_ PSAFEUPLOAD_EXCHANGE Exchange,
    _Out_ PUINT32 Verdict,
    _Out_ PBOOLEAN Answered,
    _In_opt_ PVOID ConnectionCookie,
    _In_ BOOLEAN ConnectionUseAlreadyPinned
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
    PVOID pinnedCookie = NULL;
    BOOLEAN portUseAcquired = FALSE;

    PAGED_CODE();

    if (Exchange == NULL || Verdict == NULL || Answered == NULL) {
        if (ConnectionUseAlreadyPinned)
            SafeUploadConnectionUseRelease(ConnectionCookie);
        return STATUS_INVALID_PARAMETER;
    }

    //
    //  RN-013 in one line: the answer is "allow" unless user mode actively
    //  says otherwise. Answered defaults to FALSE and is only ever set to
    //  TRUE once a validated reply is in hand - every early exit below
    //  leaves it FALSE, which is what makes those exits fail-open without
    //  being mistaken for a checked verdict.
    //

    *Verdict = SAFEUPLOAD_VERDICT_ALLOW;
    *Answered = FALSE;
    Exchange->MayHaveReachedService = FALSE;

    //
    //  Take rundown protection for the whole call. If unload has already
    //  started this fails immediately and the operation goes through
    //  uninspected, which is exactly what we want: no operation may block
    //  waiting on a channel that is being torn down.
    //

    if (!ExAcquireRundownProtection( &SafeUploadData.ChannelRundown )) {
        if (ConnectionUseAlreadyPinned) SafeUploadConnectionUseRelease(ConnectionCookie);
        return STATUS_FLT_DELETING_OBJECT;
    }

    /* Pin the accepted channel identity from before the last check through
     * FltSendMessage and reply validation. Disconnect may revoke and close
     * without ExchangeMutex; replacement waits for this short-lived use count
     * before reusing the shared ClientPort slot. */
    if (ConnectionUseAlreadyPinned) {
        pinnedCookie = ConnectionCookie;
        portUseAcquired = pinnedCookie != NULL;
    } else if (SafeUploadConnectionUseAcquire(ConnectionCookie,
            ConnectionCookie != NULL, &pinnedCookie)) {
        portUseAcquired = TRUE;
    } else {
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

    /* Check the pinned identity immediately before handing the shared slot to
     * Filter Manager. A later revoke closes this same slot; new publication
     * cannot replace it until this caller releases its channel-use pin. */
    if (!SafeUploadConnectionUseIsCurrent(pinnedCookie, ConnectionCookie != NULL)) {
        status = STATUS_PORT_DISCONNECTED;
        goto Exit;
    }
    Exchange->MayHaveReachedService = TRUE;
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

    if (portUseAcquired) SafeUploadConnectionUseRelease(pinnedCookie);
    ExReleaseRundownProtection( &SafeUploadData.ChannelRundown );

    return status;
}

NTSTATUS
SafeUploadRequestVerdict (
    _Inout_ PSAFEUPLOAD_EXCHANGE Exchange,
    _Out_ PUINT32 Verdict,
    _Out_ PBOOLEAN Answered
    )
{
    PAGED_CODE();
    return SafeUploadRequestVerdictInternal(Exchange, Verdict, Answered, NULL, FALSE);
}

#if SAFEUPLOAD_STAGING_PROTOTYPE
_Use_decl_annotations_
BOOLEAN SafeUploadConnectionPinAuthenticatedProcess(PVOID ConnectionCookie,
    LONG64 ConnectionGeneration, PEPROCESS *Process)
{
    PVOID pinnedCookie = NULL;
    KIRQL oldIrql;
    BOOLEAN acquired = FALSE;
    if (Process == NULL) return FALSE;
    *Process = NULL;
    if (ConnectionCookie == NULL || ConnectionGeneration <= 0 ||
        !SafeUploadConnectionUseAcquire(ConnectionCookie, TRUE, &pinnedCookie)) return FALSE;
    /* Retirement can revoke the cookie after the use is acquired. Recheck
     * the exact generation and reference its accepted process atomically;
     * a replacement cannot publish until this old-cookie use is released. */
    KeAcquireSpinLock(&SafeUploadConnectionStateLock, &oldIrql);
    if (pinnedCookie == ConnectionCookie &&
        InterlockedCompareExchangePointer(&SafeUploadCurrentConnectionCookie, NULL, NULL) == ConnectionCookie &&
        SafeUploadCurrentConnectionGeneration == ConnectionGeneration &&
        !SafeUploadControlCallbackAdmissionClosed && !SafeUploadStageCallbackAdmissionClosed &&
        InterlockedCompareExchange(&SafeUploadData.AuthenticatedClient, 0, 0) != 0 &&
        SafeUploadData.ClientPort != NULL && SafeUploadCurrentConnectionProcess != NULL) {
        ObReferenceObject(SafeUploadCurrentConnectionProcess);
        *Process = SafeUploadCurrentConnectionProcess;
        acquired = TRUE;
    }
    KeReleaseSpinLock(&SafeUploadConnectionStateLock, oldIrql);
    if (!acquired) SafeUploadConnectionUseRelease(pinnedCookie);
    return acquired;
}

VOID SafeUploadConnectionReleaseAuthenticatedProcess(_In_ PVOID ConnectionCookie,
    _In_ PEPROCESS Process)
{
    /* Drop the process hold before publishing the channel-use drain. */
    ObDereferenceObject(Process);
    SafeUploadConnectionUseRelease(ConnectionCookie);
}

BOOLEAN SafeUploadConnectionPinForStage(_In_ PVOID ConnectionCookie)
{
    PVOID pinnedCookie = NULL;
    if (ConnectionCookie == NULL ||
        !SafeUploadConnectionUseAcquire(ConnectionCookie, TRUE, &pinnedCookie)) return FALSE;
    if (pinnedCookie != ConnectionCookie) {
        SafeUploadConnectionUseRelease(pinnedCookie);
        return FALSE;
    }
    return TRUE;
}

NTSTATUS SafeUploadRequestVerdictForPinnedConnection(
    _Inout_ PSAFEUPLOAD_EXCHANGE Exchange,
    _In_ PVOID ConnectionCookie,
    _Out_ PUINT32 Verdict,
    _Out_ PBOOLEAN Answered)
{
    PAGED_CODE();
    if (ConnectionCookie == NULL) {
        if (Verdict != NULL) *Verdict = SAFEUPLOAD_VERDICT_DENY;
        if (Answered != NULL) *Answered = FALSE;
        return STATUS_INVALID_PARAMETER;
    }
    return SafeUploadRequestVerdictInternal(Exchange, Verdict, Answered,
        ConnectionCookie, TRUE);
}
#endif


static
NTSTATUS
SafeUploadPortMessageInternal (
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

    PortCookie - Unique opaque identity for the accepted connection.

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
    PSAFEUPLOAD_ACTIVATING_STATUS_PAGE activatingPage = NULL;
    PSAFEUPLOAD_ACTIVATING_DIAGNOSTIC_STATUS_PAGE activatingDiagnosticPage = NULL;
    PSAFEUPLOAD_ADMISSION_COVERAGE_STATUS coverageStatus = NULL;
#endif
    NTSTATUS status = STATUS_SUCCESS;
    UINT32 command = 0;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    BOOLEAN firstAuthentication = FALSE;
#endif
    BOOLEAN connectionCurrent;

    PAGED_CODE();

    *ReturnOutputBufferLength = 0;

    if (!SafeUploadPortMessageAcquire(PortCookie)) return STATUS_ACCESS_DENIED;

    if (InputBuffer == NULL || InputBufferLength < sizeof( SAFEUPLOAD_CONTROL )) {
        SafeUploadPortMessageRelease(PortCookie);
        return STATUS_INVALID_PARAMETER;
    }

    /* A SYSTEM process may duplicate the client-port handle. Bind every
     * request to the process accepted by PortConnect, not only to whoever
     * presents a handle for the connection. */
    if (!SafeUploadConnectionUseIsCurrentForProcess(PortCookie,
            HandleToULong(PsGetCurrentProcessId()))) {
        SafeUploadPortMessageRelease(PortCookie);
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
        SafeUploadPortMessageRelease(PortCookie);
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

        if (command == SAFEUPLOAD_CONTROL_ADMISSION_PROBE ||
            command == SAFEUPLOAD_CONTROL_REGISTRY_ENTRY ||
            command == SAFEUPLOAD_CONTROL_ACTIVATING_TARGET_STATUS) {
            ULONG maximumProbeSize = (ULONG)FIELD_OFFSET( SAFEUPLOAD_ADMISSION_PROBE_REQUEST, Strings ) +
                (2UL * (ULONG)SAFEUPLOAD_ADMISSION_PROBE_MAX_STRING_CHARS * (ULONG)sizeof( WCHAR ));

            if (InputBufferLength > maximumProbeSize || InputBufferLength > sizeof( *policy )) {
                status = STATUS_INVALID_BUFFER_SIZE;
                leave;
            }
            ProbeForRead( InputBuffer,
                          InputBufferLength,
                          __alignof( SAFEUPLOAD_ADMISSION_PROBE_REQUEST ) );
        } else if (command == SAFEUPLOAD_CONTROL_REGISTRY_SET_CAPACITY) {
            if (InputBufferLength != sizeof(SAFEUPLOAD_CONTROL)) {
                status = STATUS_INVALID_BUFFER_SIZE;
                leave;
            }
            ProbeForRead(InputBuffer, InputBufferLength, __alignof(SAFEUPLOAD_CONTROL));
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

        /* SYSTEM remains the connection prerequisite. Policy replacement,
         * publication permits and override grants additionally require the
         * service SID; the owner decision trusts admins/SYSTEM, so this is
         * inexpensive hardening against unrelated SYSTEM clients. Read-only
         * and feature diagnostics remain available to the SYSTEM Inspector. */
        if (command == SAFEUPLOAD_CONTROL_SET_POLICY ||
            command == SAFEUPLOAD_CONTROL_STAGE_PUBLICATION ||
            command == SAFEUPLOAD_CONTROL_STAGE_DISPOSE ||
            command == SAFEUPLOAD_CONTROL_GRANT_OVERRIDE) {
            if (!SafeUploadCurrentProcessHasAgentServiceSid()) {
                status = STATUS_ACCESS_DENIED;
                leave;
            }
        }

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

        if (command == SAFEUPLOAD_CONTROL_PROMOTION_TRACE_READ_BATCH) {
            SAFEUPLOAD_PROMOTION_TRACE_REQUEST request;
            PSAFEUPLOAD_PROMOTION_TRACE_BATCH batch = (PSAFEUPLOAD_PROMOTION_TRACE_BATCH)policy;
            if (InputBufferLength != sizeof(request)) {
                status = STATUS_INVALID_BUFFER_SIZE;
                leave;
            }
            if (OutputBuffer == NULL || OutputBufferLength != sizeof(*batch)) {
                status = OutputBufferLength < sizeof(*batch) ? STATUS_BUFFER_TOO_SMALL : STATUS_INVALID_BUFFER_SIZE;
                leave;
            }
            RtlCopyMemory(&request, InputBuffer, sizeof(request));
            if (request.Control.Version != SAFEUPLOAD_PROTOCOL_VERSION ||
                request.Control.StructSize != sizeof(request) ||
                request.Control.Command != command || request.Control.Reserved != 0) {
                status = STATUS_REVISION_MISMATCH;
                leave;
            }
#pragma warning( suppress: 6001 )
            ProbeForWrite(OutputBuffer, sizeof(*batch), __alignof(SAFEUPLOAD_PROMOTION_TRACE_BATCH));
            status = SafeUploadStageWritersPromotionTraceReadBatch(&request, batch);
            if (NT_SUCCESS(status)) {
                RtlCopyMemory(OutputBuffer, batch, sizeof(*batch));
                *ReturnOutputBufferLength = sizeof(*batch);
            }
            leave;
        }

        if (command == SAFEUPLOAD_CONTROL_ADMISSION_PROBE ||
            command == SAFEUPLOAD_CONTROL_REGISTRY_ENTRY ||
            command == SAFEUPLOAD_CONTROL_ACTIVATING_TARGET_STATUS) {
            PSAFEUPLOAD_ADMISSION_PROBE_REQUEST request =
                (PSAFEUPLOAD_ADMISSION_PROBE_REQUEST)policy;
            PSAFEUPLOAD_REGISTRY_ENTRY_STATUS registryReply = NULL;
            PSAFEUPLOAD_ACTIVATING_TARGET_STATUS targetReply = NULL;
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
                (command == SAFEUPLOAD_CONTROL_ADMISSION_PROBE ?
                    (OutputBuffer != NULL || OutputBufferLength != 0) :
                    (OutputBuffer == NULL || OutputBufferLength !=
                        (command == SAFEUPLOAD_CONTROL_ACTIVATING_TARGET_STATUS ?
                            sizeof(SAFEUPLOAD_ACTIVATING_TARGET_STATUS) : sizeof(SAFEUPLOAD_REGISTRY_ENTRY_STATUS))))) {
                status = STATUS_INVALID_BUFFER_SIZE;
                leave;
            }

            if (command == SAFEUPLOAD_CONTROL_REGISTRY_ENTRY) {
                C_ASSERT(sizeof(SAFEUPLOAD_POLICY_MESSAGE) >=
                    (ULONG)FIELD_OFFSET(SAFEUPLOAD_ADMISSION_PROBE_REQUEST, Strings) +
                    (2UL * SAFEUPLOAD_ADMISSION_PROBE_MAX_STRING_CHARS * sizeof(WCHAR)) +
                    sizeof(SAFEUPLOAD_REGISTRY_ENTRY_STATUS));
                C_ASSERT((sizeof(SAFEUPLOAD_POLICY_MESSAGE) - sizeof(SAFEUPLOAD_REGISTRY_ENTRY_STATUS)) %
                    __alignof(SAFEUPLOAD_REGISTRY_ENTRY_STATUS) == 0);
#pragma warning( suppress: 6001 )
                ProbeForWrite(OutputBuffer, sizeof(SAFEUPLOAD_REGISTRY_ENTRY_STATUS),
                    __alignof(SAFEUPLOAD_REGISTRY_ENTRY_STATUS));
                /* Keep the reply beyond the bounded request in the existing pool allocation. */
                registryReply = (PSAFEUPLOAD_REGISTRY_ENTRY_STATUS)((PUCHAR)policy +
                    sizeof(*policy) - sizeof(*registryReply));
                RtlZeroMemory(registryReply, sizeof(*registryReply));
            }

            if (command == SAFEUPLOAD_CONTROL_ACTIVATING_TARGET_STATUS) {
                C_ASSERT(sizeof(SAFEUPLOAD_POLICY_MESSAGE) >=
                    FIELD_OFFSET(SAFEUPLOAD_ADMISSION_PROBE_REQUEST, Strings) +
                    2 * SAFEUPLOAD_ADMISSION_PROBE_MAX_STRING_CHARS * sizeof(WCHAR) +
                    sizeof(SAFEUPLOAD_ACTIVATING_TARGET_STATUS));
                C_ASSERT((sizeof(SAFEUPLOAD_POLICY_MESSAGE) - sizeof(SAFEUPLOAD_ACTIVATING_TARGET_STATUS)) %
                    __alignof(SAFEUPLOAD_ACTIVATING_TARGET_STATUS) == 0);
#pragma warning(suppress: 6001)
                ProbeForWrite(OutputBuffer, sizeof(SAFEUPLOAD_ACTIVATING_TARGET_STATUS),
                    __alignof(SAFEUPLOAD_ACTIVATING_TARGET_STATUS));
                targetReply = (PSAFEUPLOAD_ACTIVATING_TARGET_STATUS)((PUCHAR)policy +
                    sizeof(*policy) - sizeof(*targetReply));
            }

            // This bounded request is larger than the control header; copy it
            // into the existing pool scratch buffer, never a kernel stack local.
            RtlCopyMemory( request, InputBuffer, InputBufferLength );

            if (request->Control.Version != SAFEUPLOAD_PROTOCOL_VERSION ||
                request->Control.StructSize != InputBufferLength ||
                request->Control.Command != command ||
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

            if (command == SAFEUPLOAD_CONTROL_ADMISSION_PROBE) {
                status = SafeUploadStageAdmissionProbe(&volumeName, &relativePath);
            } else if (command == SAFEUPLOAD_CONTROL_ACTIVATING_TARGET_STATUS) {
                UNICODE_STRING normalizedName;
                normalizedName.Buffer = request->Strings;
                normalizedName.Length = normalizedName.MaximumLength = (USHORT)stringBytes;
                status = SafeUploadStageWritersActivatingTargetStatus(&normalizedName, targetReply);
                if (NT_SUCCESS(status)) {
                    RtlCopyMemory(OutputBuffer, targetReply, sizeof(*targetReply));
                    *ReturnOutputBufferLength = sizeof(*targetReply);
                }
            } else {
                status = SafeUploadStageRegistryEntryProbe(&volumeName, &relativePath, registryReply);
                if (NT_SUCCESS(status)) {
                    RtlCopyMemory(OutputBuffer, registryReply, sizeof(*registryReply));
                    *ReturnOutputBufferLength = sizeof(*registryReply);
                }
            }
            leave;
        }

        if (command == SAFEUPLOAD_CONTROL_REGISTRY_SET_CAPACITY) {
            SAFEUPLOAD_CONTROL capacityControl;
            if (InputBufferLength != sizeof(capacityControl) || OutputBuffer != NULL ||
                OutputBufferLength != 0) {
                status = STATUS_INVALID_BUFFER_SIZE;
                leave;
            }
            RtlCopyMemory(&capacityControl, InputBuffer, sizeof(capacityControl));
            if (capacityControl.Version != SAFEUPLOAD_PROTOCOL_VERSION ||
                capacityControl.StructSize != sizeof(capacityControl) ||
                capacityControl.Command != command ||
                capacityControl.Reserved > SAFEUPLOAD_WRITER_REGISTRY_TOTAL_LIMIT) {
                status = STATUS_REVISION_MISMATCH;
                leave;
            }
            SafeUploadStageWritersSetCapacity(capacityControl.Reserved);
            status = STATUS_SUCCESS;
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

        if (command == SAFEUPLOAD_CONTROL_ADMISSION_VOLUME_STATUS ||
            command == SAFEUPLOAD_CONTROL_ADMISSION_VOLUME_OBSERVE) {
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
            status = SafeUploadStageAdmissionVolumeStatus(volumeStatus,
                command == SAFEUPLOAD_CONTROL_ADMISSION_VOLUME_STATUS);
            if (NT_SUCCESS(status)) {
                RtlCopyMemory(OutputBuffer, volumeStatus, sizeof(*volumeStatus));
                *ReturnOutputBufferLength = sizeof(*volumeStatus);
            }
            leave;
        }

        if (command == SAFEUPLOAD_CONTROL_ADMISSION_COVERAGE) {
            if (InputBufferLength != sizeof(SAFEUPLOAD_CONTROL) || OutputBuffer == NULL ||
                OutputBufferLength != sizeof(SAFEUPLOAD_ADMISSION_COVERAGE_STATUS)) {
                status = STATUS_INVALID_BUFFER_SIZE;
                leave;
            }
            if (controlHeader.Version != SAFEUPLOAD_PROTOCOL_VERSION ||
                controlHeader.StructSize != sizeof(SAFEUPLOAD_CONTROL) ||
                controlHeader.Command != command || controlHeader.Reserved != 0) {
                status = STATUS_REVISION_MISMATCH;
                leave;
            }
#pragma warning( suppress: 6001 )
            ProbeForWrite(OutputBuffer, sizeof(SAFEUPLOAD_ADMISSION_COVERAGE_STATUS),
                __alignof(SAFEUPLOAD_ADMISSION_COVERAGE_STATUS));
            coverageStatus = ExAllocatePool2(POOL_FLAG_PAGED,
                sizeof(*coverageStatus), SAFEUPLOAD_POOL_TAG);
            if (coverageStatus == NULL) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                leave;
            }
            status = SafeUploadStageAdmissionCoverageStatus(coverageStatus);
            if (NT_SUCCESS(status)) {
                RtlCopyMemory(OutputBuffer, coverageStatus, sizeof(*coverageStatus));
                *ReturnOutputBufferLength = sizeof(*coverageStatus);
            }
            leave;
        }

        if (command == SAFEUPLOAD_CONTROL_ADMISSION_CANARY_HOLD) {
            PSAFEUPLOAD_ADMISSION_CANARY_HOLD_REQUEST request =
                (PSAFEUPLOAD_ADMISSION_CANARY_HOLD_REQUEST)policy;
            PSAFEUPLOAD_ADMISSION_CANARY_HOLD_REPLY reply;
            UNICODE_STRING volumeName;
            ULONG index;

            if (InputBufferLength != sizeof(*request) || OutputBuffer == NULL ||
                OutputBufferLength != sizeof(*reply)) {
                status = STATUS_INVALID_BUFFER_SIZE;
                leave;
            }
            /* Reuse the existing pool scratch buffer instead of placing this fixed request on the stack. */
            RtlCopyMemory(request, InputBuffer, sizeof(*request));
            if (request->Control.Version != SAFEUPLOAD_PROTOCOL_VERSION ||
                request->Control.StructSize != sizeof(*request) ||
                request->Control.Command != command || request->Control.Reserved != 0 ||
                request->Reserved != 0 || request->VolumeNameChars == 0 ||
                request->VolumeNameChars >= SAFEUPLOAD_CANARY_VOLUME_CHARS ||
                request->VolumeName[request->VolumeNameChars] != UNICODE_NULL ||
                request->HoldMilliseconds == 0 ||
                request->HoldMilliseconds > SAFEUPLOAD_CANARY_MAX_HOLD_MS) {
                status = STATUS_INVALID_PARAMETER;
                leave;
            }
            for (index = 0; index < request->VolumeNameChars; ++index) {
                if (request->VolumeName[index] == UNICODE_NULL) {
                    status = STATUS_INVALID_PARAMETER;
                    leave;
                }
            }
            for (index = request->VolumeNameChars + 1; index < SAFEUPLOAD_CANARY_VOLUME_CHARS; ++index) {
                if (request->VolumeName[index] != UNICODE_NULL) {
                    status = STATUS_INVALID_PARAMETER;
                    leave;
                }
            }
            volumeName.Buffer = request->VolumeName;
            volumeName.Length = (USHORT)(request->VolumeNameChars * sizeof(WCHAR));
            volumeName.MaximumLength = sizeof(request->VolumeName);
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
                    request->HoldMilliseconds, reply);
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
        if (command == SAFEUPLOAD_CONTROL_ACTIVATING_STATUS) {
            if (InputBufferLength != sizeof(SAFEUPLOAD_CONTROL) || OutputBuffer == NULL ||
                OutputBufferLength != sizeof(SAFEUPLOAD_ACTIVATING_STATUS_PAGE)) {
                status = STATUS_INVALID_BUFFER_SIZE;
                leave;
            }
            if (controlHeader.Version != SAFEUPLOAD_PROTOCOL_VERSION ||
                controlHeader.StructSize != sizeof(SAFEUPLOAD_CONTROL) ||
                controlHeader.Command != command) {
                status = STATUS_REVISION_MISMATCH;
                leave;
            }
#pragma warning( suppress: 6001 )
            ProbeForWrite(OutputBuffer, sizeof(SAFEUPLOAD_ACTIVATING_STATUS_PAGE),
                __alignof(SAFEUPLOAD_ACTIVATING_STATUS_PAGE));
            activatingPage = ExAllocatePool2(POOL_FLAG_PAGED,
                sizeof(*activatingPage), SAFEUPLOAD_POOL_TAG);
            if (activatingPage == NULL) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                leave;
            }
            status = SafeUploadStageWritersActivatingStatusPage(controlHeader.Reserved, activatingPage);
            if (NT_SUCCESS(status)) {
                RtlCopyMemory(OutputBuffer, activatingPage, sizeof(*activatingPage));
                *ReturnOutputBufferLength = sizeof(*activatingPage);
            }
            leave;
        }

        if (command == SAFEUPLOAD_CONTROL_ACTIVATING_DIAGNOSTIC_STATUS) {
            if (InputBufferLength != sizeof(SAFEUPLOAD_CONTROL) || OutputBuffer == NULL ||
                OutputBufferLength != sizeof(SAFEUPLOAD_ACTIVATING_DIAGNOSTIC_STATUS_PAGE)) {
                status = STATUS_INVALID_BUFFER_SIZE;
                leave;
            }
            if (controlHeader.Version != SAFEUPLOAD_PROTOCOL_VERSION ||
                controlHeader.StructSize != sizeof(SAFEUPLOAD_CONTROL) ||
                controlHeader.Command != command) {
                status = STATUS_REVISION_MISMATCH;
                leave;
            }
#pragma warning( suppress: 6001 )
            ProbeForWrite(OutputBuffer, sizeof(SAFEUPLOAD_ACTIVATING_DIAGNOSTIC_STATUS_PAGE),
                __alignof(SAFEUPLOAD_ACTIVATING_DIAGNOSTIC_STATUS_PAGE));
            activatingDiagnosticPage = ExAllocatePool2(POOL_FLAG_PAGED,
                sizeof(*activatingDiagnosticPage), SAFEUPLOAD_POOL_TAG);
            if (activatingDiagnosticPage == NULL) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                leave;
            }
            status = SafeUploadStageWritersActivatingDiagnosticStatusPage(
                controlHeader.Reserved, activatingDiagnosticPage);
            if (NT_SUCCESS(status)) {
                RtlCopyMemory(OutputBuffer, activatingDiagnosticPage,
                    sizeof(*activatingDiagnosticPage));
                *ReturnOutputBufferLength = sizeof(*activatingDiagnosticPage);
            }
            leave;
        }

        if (command == SAFEUPLOAD_CONTROL_ADMISSION_EPOCH_STATUS) {
            SAFEUPLOAD_ADMISSION_EPOCH_STATUS epochStatus;
            if (InputBufferLength != sizeof(SAFEUPLOAD_CONTROL) || OutputBuffer == NULL ||
                OutputBufferLength != sizeof(epochStatus)) {
                status = STATUS_INVALID_BUFFER_SIZE;
                leave;
            }
            if (controlHeader.Version != SAFEUPLOAD_PROTOCOL_VERSION ||
                controlHeader.StructSize != sizeof(SAFEUPLOAD_CONTROL) ||
                controlHeader.Command != command || controlHeader.Reserved != 0) {
                status = STATUS_REVISION_MISMATCH;
                leave;
            }
#pragma warning( suppress: 6001 )
            ProbeForWrite(OutputBuffer, sizeof(epochStatus), __alignof(SAFEUPLOAD_ADMISSION_EPOCH_STATUS));
            status = SafeUploadPolicyAdmissionEpochStatus(&epochStatus);
            if (NT_SUCCESS(status)) {
                RtlCopyMemory(OutputBuffer, &epochStatus, sizeof(epochStatus));
                *ReturnOutputBufferLength = sizeof(epochStatus);
            }
            leave;
        }

        if (command == SAFEUPLOAD_CONTROL_ADMISSION_EPOCH_FORCE_TIMEOUT) {
            if (InputBufferLength != sizeof(SAFEUPLOAD_CONTROL) || OutputBuffer != NULL ||
                OutputBufferLength != 0 || controlHeader.Version != SAFEUPLOAD_PROTOCOL_VERSION ||
                controlHeader.StructSize != sizeof(SAFEUPLOAD_CONTROL) ||
                controlHeader.Command != command || controlHeader.Reserved != 0) {
                status = STATUS_INVALID_PARAMETER;
                leave;
            }
            SafeUploadPolicyAdmissionForceNextTimeout();
            status = STATUS_SUCCESS;
            leave;
        }

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

        if (command == SAFEUPLOAD_CONTROL_DENY_RING_READ) {
            PSAFEUPLOAD_DENY_RING_BATCH denyBatch = (PSAFEUPLOAD_DENY_RING_BATCH)policy;
            UINT64 afterSequence;

            /* The reply is built in the pool scratch buffer allocated above, never on the stack, and the header
             * fields are validated from the copy taken at the top of this routine: this routine is already close
             * to the stack-use limit (C6262). */
            C_ASSERT( sizeof( SAFEUPLOAD_DENY_RING_BATCH ) <= sizeof( SAFEUPLOAD_POLICY_MESSAGE ) );
            if (InputBufferLength != sizeof( SAFEUPLOAD_DENY_RING_REQUEST )) {
                status = STATUS_INVALID_BUFFER_SIZE;
                leave;
            }
            if (OutputBuffer == NULL || OutputBufferLength != sizeof( SAFEUPLOAD_DENY_RING_BATCH )) {
                status = OutputBufferLength < sizeof( SAFEUPLOAD_DENY_RING_BATCH ) ?
                    STATUS_BUFFER_TOO_SMALL : STATUS_INVALID_BUFFER_SIZE;
                leave;
            }
            if (controlHeader.Version != SAFEUPLOAD_PROTOCOL_VERSION ||
                controlHeader.StructSize != sizeof( SAFEUPLOAD_DENY_RING_REQUEST ) ||
                controlHeader.Reserved != 0) {
                status = STATUS_REVISION_MISMATCH;
                leave;
            }
            RtlCopyMemory( &afterSequence,
                           (PUCHAR)InputBuffer + FIELD_OFFSET( SAFEUPLOAD_DENY_RING_REQUEST, AfterSequence ),
                           sizeof( afterSequence ) );
#pragma warning( suppress: 6001 )
            ProbeForWrite( OutputBuffer, sizeof( SAFEUPLOAD_DENY_RING_BATCH ), __alignof( SAFEUPLOAD_DENY_RING_BATCH ) );
            status = SafeUploadDenyRingReadBatch( afterSequence, denyBatch );
            if (NT_SUCCESS( status )) {
                RtlCopyMemory( OutputBuffer, denyBatch, sizeof( *denyBatch ) );
                *ReturnOutputBufferLength = sizeof( *denyBatch );
            }
            leave;
        }

        if (command == SAFEUPLOAD_CONTROL_DIAG_COUNTERS) {
            PSAFEUPLOAD_DIAG_COUNTERS diagCounters = (PSAFEUPLOAD_DIAG_COUNTERS)policy;

            C_ASSERT( sizeof( SAFEUPLOAD_DIAG_COUNTERS ) <= sizeof( SAFEUPLOAD_POLICY_MESSAGE ) );
            if (InputBufferLength != sizeof( SAFEUPLOAD_CONTROL ) ||
                OutputBuffer == NULL || OutputBufferLength != sizeof( SAFEUPLOAD_DIAG_COUNTERS )) {
                status = STATUS_INVALID_BUFFER_SIZE;
                leave;
            }
            if (controlHeader.Version != SAFEUPLOAD_PROTOCOL_VERSION ||
                controlHeader.StructSize != sizeof( SAFEUPLOAD_CONTROL ) ||
                controlHeader.Reserved != 0) {
                status = STATUS_REVISION_MISMATCH;
                leave;
            }
#pragma warning( suppress: 6001 )
            ProbeForWrite( OutputBuffer, sizeof( SAFEUPLOAD_DIAG_COUNTERS ), __alignof( SAFEUPLOAD_DIAG_COUNTERS ) );
            SafeUploadDenyGetCounters( diagCounters );
            SafeUploadStageGetLifetimeCounters( &diagCounters->Stage );
            RtlCopyMemory( OutputBuffer, diagCounters, sizeof( *diagCounters ) );
            *ReturnOutputBufferLength = sizeof( *diagCounters );
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
            status = SafeUploadSetPublicationPermit(
                (PSAFEUPLOAD_PUBLICATION_MESSAGE) policy, PortCookie);
            leave;
        }

        if (command == SAFEUPLOAD_CONTROL_STAGE_DISPOSE) {
            status = SafeUploadStageDisposeControl( InputBuffer, InputBufferLength, OutputBuffer,
                                                    OutputBufferLength, ReturnOutputBufferLength, policy );
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

#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (activatingPage != NULL) ExFreePoolWithTag(activatingPage, SAFEUPLOAD_POOL_TAG);
    if (activatingDiagnosticPage != NULL)
        ExFreePoolWithTag(activatingDiagnosticPage, SAFEUPLOAD_POOL_TAG);
    if (coverageStatus != NULL) ExFreePoolWithTag(coverageStatus, SAFEUPLOAD_POOL_TAG);
#endif

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
                /* Commit authentication against the same short state lock
                 * used by disconnect. This callback is counted until return,
                 * so retirement cannot publish a replacement before its
                 * stage-connected notification has finished. */
#if SAFEUPLOAD_STAGING_PROTOTYPE
                connectionCurrent = SafeUploadConnectionCommitAuthentication(
                    PortCookie, &firstAuthentication);
#else
                connectionCurrent = SafeUploadConnectionCommitAuthentication(PortCookie, NULL);
#endif
                if (!connectionCurrent) {
                    status = STATUS_PORT_DISCONNECTED;
                } else {
#if SAFEUPLOAD_STAGING_PROTOTYPE
                    /* Recheck staged versions only on the first policy of this
                     * authenticated connection. */
                    if (firstAuthentication) SafeUploadStageServiceConnected(PortCookie);
#endif
                }
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
    SafeUploadPortMessageRelease(PortCookie);

    return status;
}
