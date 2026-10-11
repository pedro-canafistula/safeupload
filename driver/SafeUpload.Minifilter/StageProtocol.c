#include "Filter.h"
#include "Stage.h"

static NTSTATUS StageSendVersionRequest(_In_ UINT32 Operation, _In_ ULONG ProcessId, _In_ PUNICODE_STRING StageName);
static NTSTATUS StageAllocateInternal(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PUNICODE_STRING OriginalName,
    _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind,
    _In_opt_ PUNICODE_STRING PreviousStageName,
    _In_opt_ PUNICODE_STRING TombstoneStageName,
    _Out_writes_(SAFEUPLOAD_MAX_STAGE_NAME_CHARS) PWCH StageName,
    _Out_ PUSHORT StageNameLength,
    _In_ BOOLEAN Version19,
    _Out_opt_ PUINT64 DestinationGeneration,
    _Out_opt_ PVOID StageIdentity,
    _In_opt_ const GUID *DriverInstanceId,
    _Out_opt_ PSAFEUPLOAD_STAGE_ALLOCATE_V19 AllocationIntent,
    _Out_opt_ PSAFEUPLOAD_REQUEST AllocationRequest,
    _Out_opt_ PBOOLEAN AllocationMayExist);
#if SAFEUPLOAD_STAGING_PROTOTYPE
static BOOLEAN StageV19IdentityNonzero(_In_ const SAFEUPLOAD_STAGE_IDENTITY_V19 *Identity);
static NTSTATUS StageSendVersionRequestV19(_In_ UINT32 Operation, _In_ ULONG ProcessId,
    _In_ PUNICODE_STRING StageName, _In_opt_ const GUID *ReservationId,
    _In_ const SAFEUPLOAD_STAGE_IDENTITY_V19 *StageIdentity, _In_ UINT64 DestinationGeneration,
    _In_ UINT32 Kind, _Out_opt_ PUINT32 Result);
static NTSTATUS StageProtocolPrepareAttachRequestV20(_In_ ULONG ProcessId,
    _In_ PUNICODE_STRING DestinationName, _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind,
    _In_ UINT32 Operation, _In_ const GUID *TransferId, _In_ UINT64 DestinationGeneration,
    _In_ const SAFEUPLOAD_STAGE_IDENTITY_V19 *StageIdentity, _In_ const GUID *DriverInstanceId,
    _In_ const SAFEUPLOAD_STAGE_IDENTITY_V19 *ParentDirectoryIdentity,
    _Inout_ PSAFEUPLOAD_REQUEST Request);
static BOOLEAN StageProtocolValidDrainReplayRequest(_In_ const SAFEUPLOAD_REQUEST *Request,
    _In_ const GUID *DriverInstanceId, _Out_ PUINT64 DrainNonce);
#endif

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SafeUploadStageAllocate)
#pragma alloc_text(PAGE, StageAllocateInternal)
#if SAFEUPLOAD_STAGING_PROTOTYPE
#pragma alloc_text(PAGE, SafeUploadStageAllocateV19)
#pragma alloc_text(PAGE, SafeUploadStageRenameExchangeV19)
#pragma alloc_text(PAGE, SafeUploadStageReplayAllocationV19)
#pragma alloc_text(PAGE, SafeUploadStageReplayCreateAfterDiscardV19)
#pragma alloc_text(PAGE, SafeUploadStageReconcileV20)
#pragma alloc_text(PAGE, SafeUploadStageAttachmentExchangeV20)
#pragma alloc_text(PAGE, SafeUploadStageAttachmentRequestV20Matches)
#pragma alloc_text(PAGE, SafeUploadStageEpochDrainV20)
#pragma alloc_text(PAGE, StageProtocolPrepareAttachRequestV20)
#pragma alloc_text(PAGE, StageProtocolValidDrainReplayRequest)
#endif
#pragma alloc_text(PAGE, SafeUploadStageSeal)
#pragma alloc_text(PAGE, SafeUploadStageDiscard)
#pragma alloc_text(PAGE, StageSendVersionRequest)
#if SAFEUPLOAD_STAGING_PROTOTYPE
#pragma alloc_text(PAGE, SafeUploadStageSealVersionV19)
#pragma alloc_text(PAGE, SafeUploadStageDiscardVersionV19)
#pragma alloc_text(PAGE, SafeUploadStageCreateAfterDiscardV19)
#pragma alloc_text(PAGE, StageSendVersionRequestV19)
#endif
#endif

typedef struct _SAFEUPLOAD_PUBLICATION_PERMIT {
    BOOLEAN Active;
    BOOLEAN Created;
    BOOLEAN Consumed;
    SAFEUPLOAD_PUBLICATION_MESSAGE Message;
    ULONGLONG Expires;
    PVOID ConnectionCookie;
    LONG64 ConnectionGeneration;
} SAFEUPLOAD_PUBLICATION_PERMIT;

#if SAFEUPLOAD_STAGING_PROTOTYPE
static BOOLEAN StageProtocolParseTransferId(_In_reads_(Chars) PCWCH Digits,
    _In_ USHORT Chars, _Out_ GUID *Id)
{
    UCHAR bytes[16];
    USHORT index;
    RtlZeroMemory(Id, sizeof(*Id));
    if (Digits == NULL || Chars < 32) return FALSE;
    for (index = 0; index < 32; ++index) {
        WCHAR c = Digits[index];
        UCHAR nibble;
        if (c >= L'0' && c <= L'9') nibble = (UCHAR)(c - L'0');
        else if (c >= L'a' && c <= L'f') nibble = (UCHAR)(c - L'a' + 10);
        else if (c >= L'A' && c <= L'F') nibble = (UCHAR)(c - L'A' + 10);
        else return FALSE;
        if ((index & 1) == 0) bytes[index / 2] = (UCHAR)(nibble << 4);
        else bytes[index / 2] |= nibble;
    }
    Id->Data1 = ((ULONG)bytes[0] << 24) | ((ULONG)bytes[1] << 16) |
        ((ULONG)bytes[2] << 8) | bytes[3];
    Id->Data2 = (USHORT)(((USHORT)bytes[4] << 8) | bytes[5]);
    Id->Data3 = (USHORT)(((USHORT)bytes[6] << 8) | bytes[7]);
    RtlCopyMemory(Id->Data4, bytes + 8, sizeof(Id->Data4));
    return TRUE;
}

static BOOLEAN StageProtocolGuidEqual(_In_ const GUID *Left, _In_ const GUID *Right)
{
    return RtlEqualMemory(Left, Right, sizeof(GUID));
}

static BOOLEAN StageProtocolGuidNonzero(_In_ const GUID *Id)
{
    static const GUID empty = {0};
    return !StageProtocolGuidEqual(Id, &empty);
}

static NTSTATUS StageProtocolReadCreateReply(_In_ PSAFEUPLOAD_EXCHANGE Exchange,
    _In_ const GUID *ExpectedTransferId,
    _Out_writes_(SAFEUPLOAD_MAX_STAGE_NAME_CHARS) PWCH StageName,
    _Out_ PUSHORT StageNameLength,
    _Out_ PUINT64 DestinationGeneration,
    _Out_ PSAFEUPLOAD_STAGE_IDENTITY_V19 StageIdentity)
{
    PSAFEUPLOAD_STAGE_CREATE_REPLY_V19 response =
        (PSAFEUPLOAD_STAGE_CREATE_REPLY_V19)&Exchange->Response;
    static const FILE_ID_128 emptyFileId = {{0}};
    GUID transferId;
    USHORT i, chars;
    if (response->Version != SAFEUPLOAD_PROTOCOL_VERSION ||
        response->StructSize != sizeof(SAFEUPLOAD_RESPONSE) ||
        response->RequestId != Exchange->Request.RequestId ||
        response->Verdict != SAFEUPLOAD_VERDICT_ALLOW ||
        response->StageNameLength < 32 * sizeof(WCHAR) ||
        response->StageNameLength > sizeof(response->StageName) ||
        (response->StageNameLength % sizeof(WCHAR)) != 0 ||
        response->DestinationGeneration == 0 ||
        RtlEqualMemory(&response->StageIdentity.FileId, &emptyFileId, sizeof(emptyFileId)))
        return STATUS_INVALID_BUFFER_SIZE;
    chars = (USHORT)(response->StageNameLength / sizeof(WCHAR));
    for (i = 0; i < chars; ++i) {
        WCHAR ch = response->StageName[i];
        if (i < 32) {
            if (!((ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f')))
                return STATUS_INVALID_PARAMETER;
        } else if (!((ch >= L'a' && ch <= L'z') || (ch >= L'A' && ch <= L'Z') ||
                     (ch >= L'0' && ch <= L'9') || ch == L'.' || ch == L'_')) {
            return STATUS_INVALID_PARAMETER;
        }
    }
    if (!StageProtocolParseTransferId(response->StageName, chars, &transferId) ||
        !StageProtocolGuidEqual(&transferId, ExpectedTransferId))
        return STATUS_OBJECT_NAME_COLLISION;
    RtlCopyMemory(StageName, response->StageName, response->StageNameLength);
    StageName[chars] = L'\0';
    *StageNameLength = (USHORT)response->StageNameLength; /* bounded by StageName above */
    *DestinationGeneration = response->DestinationGeneration;
    *StageIdentity = response->StageIdentity;
    return STATUS_SUCCESS;
}
#endif
static SAFEUPLOAD_PUBLICATION_PERMIT SafeUploadPublicationPermits[64];
static EX_PUSH_LOCK SafeUploadPublicationLock;
#if SAFEUPLOAD_STAGING_PROTOTYPE
static FAST_MUTEX SafeUploadStageV19ExchangeMutex;
/* Channel authority and the drain-only replay tuple use a short state lock.
 * Disconnect and replacement publication must never wait behind an exchange
 * that owns ExchangeMutex across FltSendMessage. */
static KSPIN_LOCK SafeUploadStageV20StateLock;
/* A grant is usable only by the channel generation that received it. The
 * active bit covers the interval between a lock-free disconnect reset and
 * Filter Manager closing the old ClientPort. */
static volatile LONG SafeUploadStageV19ReadyGeneration;
static volatile LONG SafeUploadStageV20ChannelActive;
static volatile LONG SafeUploadStageV20ChannelGeneration;
static PVOID volatile SafeUploadStageV20ConnectionCookie;
/* A result-13 reconciliation authenticates only this exact previously
 * committed epoch-drain request on the current port connection. It never
 * enables ordinary stage traffic. Protected by SafeUploadStageV20StateLock. */
static BOOLEAN SafeUploadStageV20DrainReplayReady;
static LONG SafeUploadStageV20DrainReplayGeneration;
static PVOID SafeUploadStageV20DrainReplayCookie;
static GUID SafeUploadStageV20DrainReplayInstance;
static UINT64 SafeUploadStageV20DrainReplayRequestId;
static UINT64 SafeUploadStageV20DrainReplayNonce;

static VOID StageProtocolClearDrainReplayLocked(VOID)
{
    SafeUploadStageV20DrainReplayReady = FALSE;
    SafeUploadStageV20DrainReplayGeneration = 0;
    SafeUploadStageV20DrainReplayCookie = NULL;
    SafeUploadStageV20DrainReplayRequestId = 0;
    SafeUploadStageV20DrainReplayNonce = 0;
    RtlZeroMemory(&SafeUploadStageV20DrainReplayInstance, sizeof(GUID));
}

static BOOLEAN StageProtocolReadyForGenerationLocked(_In_ LONG Generation)
{
    return Generation != 0 &&
        SafeUploadStageV20ConnectionCookie != NULL &&
        InterlockedCompareExchange(&SafeUploadData.AuthenticatedClient, 0, 0) != 0 &&
        SafeUploadStageV20ChannelActive != 0 &&
        SafeUploadStageV19ReadyGeneration == Generation &&
        SafeUploadStageV20ChannelGeneration == Generation;
}
#endif

VOID SafeUploadClearPublicationPermits(VOID)
{
    FltAcquirePushLockExclusive( &SafeUploadPublicationLock );
    RtlZeroMemory( SafeUploadPublicationPermits, sizeof( SafeUploadPublicationPermits ) );
    FltReleasePushLock( &SafeUploadPublicationLock );
}

VOID SafeUploadClearPublicationPermitsForConnection(
    _In_ PVOID ConnectionCookie,
    _In_ LONG64 ConnectionGeneration)
{
    ULONG index;
    if (ConnectionCookie == NULL || ConnectionGeneration <= 0) return;
    FltAcquirePushLockExclusive(&SafeUploadPublicationLock);
    for (index = 0; index < RTL_NUMBER_OF(SafeUploadPublicationPermits); ++index) {
        SAFEUPLOAD_PUBLICATION_PERMIT *permit = &SafeUploadPublicationPermits[index];
        if (permit->Active && permit->ConnectionCookie == ConnectionCookie &&
            permit->ConnectionGeneration == ConnectionGeneration)
            RtlZeroMemory(permit, sizeof(*permit));
    }
    FltReleasePushLock(&SafeUploadPublicationLock);
}

NTSTATUS SafeUploadSetPublicationPermit(
    _In_ PSAFEUPLOAD_PUBLICATION_MESSAGE Message,
    _In_opt_ PVOID ConnectionCookie)
{
    ULONG index;
    LONG slot = -1;
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    ULONGLONG now = KeQueryInterruptTime();
    GUID emptyId = {0};
    PVOID ownerCookie = NULL;
    LONG64 ownerGeneration = 0;
    ULONG ownerProcessId = 0;

    if (ConnectionCookie == NULL ||
        !SafeUploadConnectionGetAuthenticatedIdentity(ConnectionCookie,
            &ownerCookie, &ownerGeneration, &ownerProcessId) ||
        HandleToULong(PsGetCurrentProcessId()) != ownerProcessId)
        return STATUS_ACCESS_DENIED;
    if (Message->Control.Version != SAFEUPLOAD_PROTOCOL_VERSION ||
        Message->Control.StructSize != sizeof( *Message ) || Message->Control.Reserved != 0 ||
        RtlEqualMemory( &Message->TransferId, &emptyId, sizeof( emptyId ) ) || Message->Reserved != 0 ||
        Message->Revoke > 1) return STATUS_INVALID_PARAMETER;
    if (!Message->Revoke && (Message->TemporaryPathLength == 0 ||
        Message->TemporaryPathLength > SAFEUPLOAD_MAX_PATH_BYTES ||
        Message->DestinationPathLength == 0 ||
        Message->DestinationPathLength > SAFEUPLOAD_MAX_PATH_BYTES ||
        (Message->TemporaryPathLength & 1) || (Message->DestinationPathLength & 1)))
        return STATUS_INVALID_PARAMETER;
    FltAcquirePushLockExclusive( &SafeUploadPublicationLock );
    /* The callback cookie is retained from Filter Manager. Rechecking the
     * exact captured identity under PublicationLock orders grant commit with
     * disconnect's token-scoped clear: after revocation this old callback
     * cannot borrow a replacement channel's authentication. Publication
     * code nests PublicationLock -> CommunicationStateLock; retirement drops
     * CommunicationStateLock before taking PublicationLock, so there is no
     * reverse nested order. */
    if (!SafeUploadConnectionIsAuthenticatedIdentity(ownerCookie, ownerGeneration)) {
        status = STATUS_ACCESS_DENIED;
        goto Exit;
    }
    for (index = 0; index < RTL_NUMBER_OF( SafeUploadPublicationPermits ); ++index) {
        SAFEUPLOAD_PUBLICATION_PERMIT *permit = &SafeUploadPublicationPermits[index];
        if (permit->Active && (permit->Expires <= now ||
            permit->ConnectionCookie != ownerCookie ||
            permit->ConnectionGeneration != ownerGeneration)) {
            RtlZeroMemory(permit, sizeof(*permit));
            continue;
        }
        if (permit->Active && RtlEqualMemory( &permit->Message.TransferId,
                                             &Message->TransferId, sizeof( GUID ) )) {
            if (Message->Revoke) {
                RtlZeroMemory( permit, sizeof( *permit ) );
                status = STATUS_SUCCESS;
            } else status = STATUS_OBJECT_NAME_COLLISION; // no resetting a consumed grant
            goto Exit;
        }
        if (!permit->Active) slot = (LONG) index;
    }
    if (Message->Revoke) status = STATUS_SUCCESS;
    else if (slot >= 0) {
        SAFEUPLOAD_PUBLICATION_PERMIT *permit = &SafeUploadPublicationPermits[slot];
        RtlZeroMemory( permit, sizeof( *permit ) );
        permit->Message = *Message;
        permit->Expires = now + 30ULL * 10000000ULL;
        permit->ConnectionCookie = ownerCookie;
        permit->ConnectionGeneration = ownerGeneration;
        permit->Active = TRUE;
        status = STATUS_SUCCESS;
    }
Exit:
    FltReleasePushLock( &SafeUploadPublicationLock );
    return status;
}

BOOLEAN SafeUploadPublicationCreate(_In_ PUNICODE_STRING Name,
    _In_ ULONG Disposition, _In_ BOOLEAN Writer)
{
    ULONG index;
    BOOLEAN allowed = FALSE;
    ULONGLONG now = KeQueryInterruptTime();
    PVOID currentCookie = NULL;
    LONG64 currentGeneration = 0;
    ULONG currentProcessId = 0;
    FltAcquirePushLockExclusive( &SafeUploadPublicationLock );
    if (!SafeUploadConnectionGetAuthenticatedIdentity(NULL, &currentCookie,
            &currentGeneration, &currentProcessId) || currentProcessId == 0) goto Exit;
    for (index = 0; index < RTL_NUMBER_OF( SafeUploadPublicationPermits ); ++index) {
        SAFEUPLOAD_PUBLICATION_PERMIT *permit = &SafeUploadPublicationPermits[index];
        UNICODE_STRING temporary;
        if (!permit->Active || permit->Consumed || permit->Expires <= now ||
            permit->ConnectionCookie != currentCookie ||
            permit->ConnectionGeneration != currentGeneration) continue;
        temporary.Buffer = permit->Message.TemporaryPath;
        temporary.Length = (USHORT) permit->Message.TemporaryPathLength;
        temporary.MaximumLength = temporary.Length;
        if (RtlEqualUnicodeString( Name, &temporary, TRUE )) {
            if (Writer) {
                if (!permit->Created && Disposition == FILE_CREATE) {
                    permit->Created = TRUE;
                    allowed = TRUE;
                }
            } else if (permit->Created && Disposition == FILE_OPEN) allowed = TRUE;
            break;
        }
    }
Exit:
    FltReleasePushLock( &SafeUploadPublicationLock );
    return allowed;
}

static BOOLEAN StagePathMatchesScope(_In_ PUNICODE_STRING Name,
    _In_ USHORT VolumeLength, _In_ SAFEUPLOAD_VOLUME_KIND Kind, _In_ BOOLEAN IncludeAncestors)
{
    if (VolumeLength > Name->Length || (VolumeLength & 1)) return TRUE;
    /* P1-2: a scope is established by current, pending, or boot policy, never
     * by a volume-independent bootstrap path literal. */
#if SAFEUPLOAD_STAGING_PROTOTYPE
    return SafeUploadPolicyMatchesCurrentOrPendingDestination(Kind, Name, IncludeAncestors);
#else
    return IncludeAncestors ? SafeUploadPolicyTouchesDestinationNamespace( Kind, Name ) :
        SafeUploadPolicyMatchesDestination( Kind, Name );
#endif
}

BOOLEAN SafeUploadStageProtectedPath(_In_ PUNICODE_STRING Name,
    _In_ USHORT VolumeLength, _In_ SAFEUPLOAD_VOLUME_KIND Kind)
{
    return StagePathMatchesScope(Name, VolumeLength, Kind, FALSE);
}

/* The path without its stream suffix. An alternate data stream belongs to its file: for an exact-file prefix
 * "dir\\file", the normalized name "dir\\file:stream" must match like "dir\\file" (the component boundary test accepts only a
 * backslash), otherwise every ADS of a protected file would be classified out of scope. */
static UNICODE_STRING StageBaseName(_In_ PFLT_FILE_NAME_INFORMATION Name)
{
    UNICODE_STRING base = Name->Name;

    if (Name->Stream.Length != 0 && Name->Stream.Length < base.Length && (Name->Stream.Length & 1) == 0) {
        base.Length -= Name->Stream.Length;
        base.MaximumLength = base.Length;
    }
    return base;
}

BOOLEAN SafeUploadStageProtectedName(_In_ PFLT_FILE_NAME_INFORMATION Name,
    _In_ SAFEUPLOAD_VOLUME_KIND Kind)
{
    UNICODE_STRING base;

    if (!NT_SUCCESS(FltParseFileNameInformation(Name))) return TRUE;
    base = StageBaseName(Name);
    return StagePathMatchesScope(&base, Name->Volume.Length, Kind, FALSE);
}

BOOLEAN SafeUploadStageTouchesProtectedNamespace(_In_ PFLT_FILE_NAME_INFORMATION Name,
    _In_ SAFEUPLOAD_VOLUME_KIND Kind)
{
    UNICODE_STRING base;

    if (!NT_SUCCESS(FltParseFileNameInformation(Name))) return TRUE;
    base = StageBaseName(Name);
    return StagePathMatchesScope(&base, Name->Volume.Length, Kind, TRUE);
}

BOOLEAN SafeUploadPublicationRename(_In_ PFLT_VOLUME TargetVolume, _In_ PUNICODE_STRING Source,
    _In_ PUNICODE_STRING Destination, _Out_ PBOOLEAN QuarantineRefused)
{
    ULONG index;
    BOOLEAN allowed = FALSE;
    ULONGLONG now = KeQueryInterruptTime();
    PVOID currentCookie = NULL;
    LONG64 currentGeneration = 0;
    ULONG currentProcessId = 0;

    *QuarantineRefused = FALSE;
    UNREFERENCED_PARAMETER(TargetVolume);

    FltAcquirePushLockExclusive( &SafeUploadPublicationLock );
    if (!SafeUploadConnectionGetAuthenticatedIdentity(NULL, &currentCookie,
            &currentGeneration, &currentProcessId) || currentProcessId == 0) goto Exit;
    for (index = 0; index < RTL_NUMBER_OF( SafeUploadPublicationPermits ); ++index) {
        SAFEUPLOAD_PUBLICATION_PERMIT *permit = &SafeUploadPublicationPermits[index];
        UNICODE_STRING temporary, destination;
        if (!permit->Active || permit->Consumed || !permit->Created || permit->Expires <= now ||
            permit->ConnectionCookie != currentCookie ||
            permit->ConnectionGeneration != currentGeneration) continue;
        temporary.Buffer = permit->Message.TemporaryPath;
        temporary.Length = (USHORT) permit->Message.TemporaryPathLength;
        temporary.MaximumLength = temporary.Length;
        destination.Buffer = permit->Message.DestinationPath;
        destination.Length = (USHORT) permit->Message.DestinationPathLength;
        destination.MaximumLength = destination.Length;
        if (RtlEqualUnicodeString( Source, &temporary, TRUE ) &&
            RtlEqualUnicodeString( Destination, &destination, TRUE )) {
            /* Keep this attempt reserved until explicit revoke/expiry. A
             * repeated authorization message must not reset a consumed grant.
             * The existing publisher revokes when it disposes its attempt. */
            permit->Consumed = TRUE;
            allowed = TRUE;
            break;
        }
    }
Exit:
    FltReleasePushLock( &SafeUploadPublicationLock );
    return allowed;
}

VOID SafeUploadStageInitializeProtocol(VOID)
{
    FltInitializePushLock(&SafeUploadPublicationLock);
#if SAFEUPLOAD_STAGING_PROTOTYPE
    ExInitializeFastMutex(&SafeUploadStageV19ExchangeMutex);
    KeInitializeSpinLock(&SafeUploadStageV20StateLock);
    InterlockedExchange(&SafeUploadStageV19ReadyGeneration, 0);
    InterlockedExchange(&SafeUploadStageV20ChannelActive, 0);
    InterlockedExchange(&SafeUploadStageV20ChannelGeneration, 1);
    InterlockedExchangePointer(&SafeUploadStageV20ConnectionCookie, NULL);
    SafeUploadStageV20DrainReplayReady = FALSE;
    SafeUploadStageV20DrainReplayGeneration = 0;
    SafeUploadStageV20DrainReplayCookie = NULL;
    RtlZeroMemory(&SafeUploadStageV20DrainReplayInstance, sizeof(GUID));
    SafeUploadStageV20DrainReplayRequestId = 0;
    SafeUploadStageV20DrainReplayNonce = 0;
#endif
}

#if SAFEUPLOAD_STAGING_PROTOTYPE
_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadStageProtocolPublishClientPort(_In_ PVOID ConnectionCookie)
{
    KIRQL oldIrql;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (ConnectionCookie == NULL) return;

    /* Communication.c has already retired/closed the previous shared port
     * slot and drained its callbacks/send pins. Publish under only the short
     * state lock: an old exchange can finish post-send checks without
     * blocking replacement publication. */
    KeAcquireSpinLock(&SafeUploadStageV20StateLock, &oldIrql);
    InterlockedExchange(&SafeUploadStageV20ChannelActive, 0);
    InterlockedExchange(&SafeUploadStageV19ReadyGeneration, 0);
    InterlockedIncrement(&SafeUploadStageV20ChannelGeneration);
    StageProtocolClearDrainReplayLocked();
    InterlockedExchangePointer(&SafeUploadStageV20ConnectionCookie, ConnectionCookie);
    InterlockedExchange(&SafeUploadStageV20ChannelActive, 1);
    KeReleaseSpinLock(&SafeUploadStageV20StateLock, oldIrql);
}

static NTSTATUS StageSendV19Exchange(_In_ PSAFEUPLOAD_EXCHANGE Exchange,
    _In_ BOOLEAN IsReconcile, _Out_ PUINT32 Verdict, _Out_ PBOOLEAN Answered)
{
    NTSTATUS status;
    BOOLEAN isDrain;
    BOOLEAN channelActive;
    BOOLEAN channelReady;
    BOOLEAN replayMatches;
    BOOLEAN channelCurrent;
    BOOLEAN channelUsePinned;
    LONG channelGeneration;
    LONG expectedGeneration;
    PVOID channelCookie;
    KIRQL stateIrql;
    if (Exchange == NULL || Verdict == NULL || Answered == NULL) return STATUS_INVALID_PARAMETER;
    ExAcquireFastMutex(&SafeUploadStageV19ExchangeMutex);
    KeAcquireSpinLock(&SafeUploadStageV20StateLock, &stateIrql);
    channelGeneration = SafeUploadStageProtocolChannelGeneration();
    expectedGeneration = Exchange->ChannelGeneration;
    channelCookie = InterlockedCompareExchangePointer(&SafeUploadStageV20ConnectionCookie, NULL, NULL);
    channelActive = InterlockedCompareExchange(&SafeUploadStageV20ChannelActive, 0, 0) != 0;
    channelReady = StageProtocolReadyForGenerationLocked(channelGeneration);
    if (!channelActive || channelCookie == NULL ||
        InterlockedCompareExchange(&SafeUploadData.AuthenticatedClient, 0, 0) == 0 ||
        (IsReconcile && (expectedGeneration == 0 || expectedGeneration != channelGeneration ||
            Exchange->ChannelCookie != channelCookie))) {
        KeReleaseSpinLock(&SafeUploadStageV20StateLock, stateIrql);
        ExReleaseFastMutex(&SafeUploadStageV19ExchangeMutex);
        *Verdict = SAFEUPLOAD_VERDICT_DENY;
        *Answered = FALSE;
        return STATUS_PORT_DISCONNECTED;
    }
    Exchange->ChannelGeneration = channelGeneration;
    Exchange->ChannelCookie = channelCookie;
    if (IsReconcile) {
        /* A fresh handshake replaces any old same-channel drain-only proof.
         * Only the exact Busy response below may install it again. */
        StageProtocolClearDrainReplayLocked();
    }
    isDrain = Exchange != NULL && Exchange->Request.Operation == SAFEUPLOAD_OPERATION_STAGE_EPOCH_DRAIN;
    replayMatches = SafeUploadStageV20DrainReplayReady &&
        SafeUploadStageV20DrainReplayGeneration == channelGeneration &&
        SafeUploadStageV20DrainReplayCookie == channelCookie &&
        Exchange->Request.RequestId == SafeUploadStageV20DrainReplayRequestId &&
        Exchange->Request.ImageNameLength == sizeof(SAFEUPLOAD_STAGE_EPOCH_DRAIN_V20) &&
        ((PSAFEUPLOAD_STAGE_EPOCH_DRAIN_V20)Exchange->Request.ImageName)->DrainNonce ==
            SafeUploadStageV20DrainReplayNonce &&
        RtlEqualMemory(&((PSAFEUPLOAD_STAGE_EPOCH_DRAIN_V20)Exchange->Request.ImageName)->DriverInstanceId,
            &SafeUploadStageV20DrainReplayInstance, sizeof(GUID));
    if (!IsReconcile && ((!isDrain && !channelReady) ||
        (isDrain && !channelReady && !replayMatches))) {
        KeReleaseSpinLock(&SafeUploadStageV20StateLock, stateIrql);
        ExReleaseFastMutex(&SafeUploadStageV19ExchangeMutex);
        *Verdict = SAFEUPLOAD_VERDICT_DENY;
        *Answered = FALSE;
        return STATUS_DEVICE_NOT_READY;
    }
    /* Pin the exact communication cookie while the generation state is still
     * locked. A disconnect either wins before this pin (so no send starts) or
     * revokes later and must drain this use before replacement publication. */
    channelUsePinned = SafeUploadConnectionPinForStage(channelCookie);
    if (!channelUsePinned) {
        KeReleaseSpinLock(&SafeUploadStageV20StateLock, stateIrql);
        ExReleaseFastMutex(&SafeUploadStageV19ExchangeMutex);
        *Verdict = SAFEUPLOAD_VERDICT_DENY;
        *Answered = FALSE;
        return STATUS_PORT_DISCONNECTED;
    }
    if (isDrain) {
        /* A drain attempt is an irreversible service transition. Keep the
         * exact request replayable but close every ordinary stage path even
         * if the response is lost or malformed. */
        InterlockedExchange(&SafeUploadStageV19ReadyGeneration, 0);
        SafeUploadStageV20DrainReplayReady = TRUE;
        SafeUploadStageV20DrainReplayGeneration = channelGeneration;
        SafeUploadStageV20DrainReplayCookie = channelCookie;
        SafeUploadStageV20DrainReplayRequestId = Exchange->Request.RequestId;
        if (Exchange->Request.ImageNameLength == sizeof(SAFEUPLOAD_STAGE_EPOCH_DRAIN_V20)) {
            PSAFEUPLOAD_STAGE_EPOCH_DRAIN_V20 payload =
                (PSAFEUPLOAD_STAGE_EPOCH_DRAIN_V20)Exchange->Request.ImageName;
            SafeUploadStageV20DrainReplayInstance = payload->DriverInstanceId;
            SafeUploadStageV20DrainReplayNonce = payload->DrainNonce;
        }
    }
    KeReleaseSpinLock(&SafeUploadStageV20StateLock, stateIrql);
    /* The request path checks the opaque connection cookie again immediately
     * before FltSendMessage and pins that connection through the reply.
     * Disconnect revokes without waiting; replacement publication waits for
     * that pin but never waits on ExchangeMutex. */
    status = SafeUploadRequestVerdictForPinnedConnection(Exchange, channelCookie, Verdict, Answered);
    channelUsePinned = FALSE; /* The request routine releases the pin on every return path. */
    /* A well-formed reply may describe a durable old-channel transition. Do
     * not use it as authority after reset; the caller retains
     * MayHaveReachedService and can replay its byte-identical request. */
    KeAcquireSpinLock(&SafeUploadStageV20StateLock, &stateIrql);
    channelCurrent = channelGeneration == SafeUploadStageProtocolChannelGeneration() &&
        InterlockedCompareExchange(&SafeUploadStageV20ChannelActive, 0, 0) != 0 &&
        InterlockedCompareExchangePointer(&SafeUploadStageV20ConnectionCookie, NULL, NULL) ==
            channelCookie &&
        InterlockedCompareExchange(&SafeUploadData.AuthenticatedClient, 0, 0) != 0;
    KeReleaseSpinLock(&SafeUploadStageV20StateLock, stateIrql);
    if (!channelCurrent) {
        *Verdict = SAFEUPLOAD_VERDICT_DENY;
        *Answered = FALSE;
        status = STATUS_PORT_DISCONNECTED;
    }
    NT_ASSERT(!channelUsePinned);
    ExReleaseFastMutex(&SafeUploadStageV19ExchangeMutex);
    return status;
}

VOID SafeUploadStageProtocolConnectionReset(_In_ PVOID ConnectionCookie)
{
    KIRQL oldIrql;
    /* Token-conditional revocation takes only the short state spin lock. It
     * never waits for ExchangeMutex or spans FltSendMessage, and an old
     * callback cannot reset a newer connection. */
    if (ConnectionCookie == NULL) return;
    KeAcquireSpinLock(&SafeUploadStageV20StateLock, &oldIrql);
    if (InterlockedCompareExchangePointer(&SafeUploadStageV20ConnectionCookie, NULL, NULL) !=
        ConnectionCookie) {
        KeReleaseSpinLock(&SafeUploadStageV20StateLock, oldIrql);
        return;
    }
    InterlockedExchangePointer(&SafeUploadStageV20ConnectionCookie, NULL);
    InterlockedExchange(&SafeUploadStageV20ChannelActive, 0);
    InterlockedExchange(&SafeUploadStageV19ReadyGeneration, 0);
    InterlockedIncrement(&SafeUploadStageV20ChannelGeneration);
    StageProtocolClearDrainReplayLocked();
    KeReleaseSpinLock(&SafeUploadStageV20StateLock, oldIrql);
}

VOID SafeUploadStageProtocolAuthenticationChanged(_In_ PVOID ConnectionCookie)
{
    KIRQL oldIrql;
    /* Invalidate readiness only for the connection whose policy was accepted. */
    if (ConnectionCookie == NULL) return;
    KeAcquireSpinLock(&SafeUploadStageV20StateLock, &oldIrql);
    if (InterlockedCompareExchangePointer(&SafeUploadStageV20ConnectionCookie, NULL, NULL) !=
        ConnectionCookie) {
        KeReleaseSpinLock(&SafeUploadStageV20StateLock, oldIrql);
        return;
    }
    InterlockedExchange(&SafeUploadStageV19ReadyGeneration, 0);
    InterlockedIncrement(&SafeUploadStageV20ChannelGeneration);
    KeReleaseSpinLock(&SafeUploadStageV20StateLock, oldIrql);
}

BOOLEAN SafeUploadStageProtocolIsReady(VOID)
{
    KIRQL oldIrql;
    BOOLEAN ready;
    LONG channelGeneration = SafeUploadStageProtocolChannelGeneration();
    KeAcquireSpinLock(&SafeUploadStageV20StateLock, &oldIrql);
    ready = StageProtocolReadyForGenerationLocked(channelGeneration);
    KeReleaseSpinLock(&SafeUploadStageV20StateLock, oldIrql);
    return ready;
}

BOOLEAN SafeUploadStageProtocolIsDrainReplayOnly(VOID)
{
    KIRQL oldIrql;
    BOOLEAN replayOnly;
    LONG channelGeneration = SafeUploadStageProtocolChannelGeneration();
    KeAcquireSpinLock(&SafeUploadStageV20StateLock, &oldIrql);
    replayOnly = InterlockedCompareExchange(&SafeUploadStageV20ChannelActive, 0, 0) != 0 &&
        InterlockedCompareExchangePointer(&SafeUploadStageV20ConnectionCookie, NULL, NULL) != NULL &&
        InterlockedCompareExchange(&SafeUploadData.AuthenticatedClient, 0, 0) != 0 &&
        SafeUploadStageV20DrainReplayReady &&
        SafeUploadStageV20DrainReplayGeneration == channelGeneration &&
        SafeUploadStageV20DrainReplayCookie ==
            InterlockedCompareExchangePointer(&SafeUploadStageV20ConnectionCookie, NULL, NULL) &&
        !StageProtocolReadyForGenerationLocked(channelGeneration);
    KeReleaseSpinLock(&SafeUploadStageV20StateLock, oldIrql);
    return replayOnly;
}

LONG SafeUploadStageProtocolChannelGeneration(VOID)
{
    return InterlockedCompareExchange(&SafeUploadStageV20ChannelGeneration, 0, 0);
}

NTSTATUS SafeUploadStageRenameExchangeV19(_In_ PSAFEUPLOAD_EXCHANGE Exchange)
{
    UINT32 verdict = SAFEUPLOAD_VERDICT_DENY;
    BOOLEAN answered = FALSE;
    NTSTATUS status;
    PAGED_CODE();
    if (Exchange == NULL || (Exchange->Request.Operation != SAFEUPLOAD_OPERATION_STAGE_RENAME &&
        Exchange->Request.Operation != SAFEUPLOAD_OPERATION_STAGE_RENAME_COMMIT &&
        Exchange->Request.Operation != SAFEUPLOAD_OPERATION_STAGE_RENAME_ABORT))
        return STATUS_INVALID_PARAMETER;
    status = StageSendV19Exchange(Exchange, FALSE, &verdict, &answered);
    return SafeUploadStageExchangeResult(status, answered, verdict);
}
#endif

static NTSTATUS
StageAllocateInternal (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PUNICODE_STRING OriginalName,
    _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind,
    _In_opt_ PUNICODE_STRING PreviousStageName,
    _In_opt_ PUNICODE_STRING TombstoneStageName,
    _Out_writes_(SAFEUPLOAD_MAX_STAGE_NAME_CHARS) PWCH StageName,
    _Out_ PUSHORT StageNameLength,
    _In_ BOOLEAN Version19,
    _Out_opt_ PUINT64 DestinationGeneration,
    _Out_opt_ PVOID StageIdentity,
    _In_opt_ const GUID *DriverInstanceId,
    _Out_opt_ PSAFEUPLOAD_STAGE_ALLOCATE_V19 AllocationIntent,
    _Out_opt_ PSAFEUPLOAD_REQUEST AllocationRequest,
    _Out_opt_ PBOOLEAN AllocationMayExist
    )
{
    PSAFEUPLOAD_EXCHANGE exchange;
    SAFEUPLOAD_STAGE_ALLOCATE_V19 intent = { 0 };
    UINT32 verdict;
    BOOLEAN answered;
    NTSTATUS status;
    USHORT i;
    PUNICODE_STRING referenceName = PreviousStageName != NULL ? PreviousStageName : TombstoneStageName;

    PAGED_CODE();

    *StageNameLength = 0;
    if (DestinationGeneration != NULL) *DestinationGeneration = 0;
    if (StageIdentity != NULL) RtlZeroMemory(StageIdentity, sizeof(UINT64) + sizeof(FILE_ID_128));
    if (AllocationMayExist != NULL) *AllocationMayExist = FALSE;
    if (AllocationIntent != NULL) RtlZeroMemory(AllocationIntent, sizeof(*AllocationIntent));
    if (AllocationRequest != NULL) RtlZeroMemory(AllocationRequest, sizeof(*AllocationRequest));
    if (Version19 && (DestinationGeneration == NULL || StageIdentity == NULL || DriverInstanceId == NULL ||
        AllocationIntent == NULL || AllocationRequest == NULL || AllocationMayExist == NULL))
        return STATUS_INVALID_PARAMETER;
    if (PreviousStageName != NULL && TombstoneStageName != NULL) return STATUS_INVALID_PARAMETER;
    if (OriginalName->Length == 0 ||
        OriginalName->Length > SAFEUPLOAD_MAX_PATH_BYTES) {
        return STATUS_NAME_TOO_LONG;
    }

    exchange = ExAllocatePool2( POOL_FLAG_NON_PAGED,
                                sizeof( *exchange ), SAFEUPLOAD_POOL_TAG );
    if (exchange == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory( exchange, sizeof( *exchange ) );
    exchange->Request.Version = SAFEUPLOAD_PROTOCOL_VERSION;
    exchange->Request.StructSize = sizeof( SAFEUPLOAD_REQUEST );
    exchange->Request.RequestId =
        (UINT64) InterlockedIncrement64( &SafeUploadData.NextRequestId );
    exchange->Request.Operation = SAFEUPLOAD_OPERATION_STAGE_ALLOCATE;
    if (VolumeKind == SafeUploadVolumeRemovable) {
        exchange->Request.Flags |= SAFEUPLOAD_REQUEST_FLAG_STAGE_REMOVABLE;
    } else if (VolumeKind == SafeUploadVolumeNetwork) {
        exchange->Request.Flags |= SAFEUPLOAD_REQUEST_FLAG_STAGE_NETWORK;
    }
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (Version19) exchange->Request.Flags |= SAFEUPLOAD_REQUEST_FLAG_STAGE_V19_REPLY;
#else
    if (Version19) { status = STATUS_NOT_SUPPORTED; goto Exit; }
#endif
    exchange->Request.RequestorProcessId = FltGetRequestorProcessId( Data );
    /* Most callers allocate from CREATE. EmptyHeld retirement allocates the
     * required successor while handling SET_INFORMATION, where reading the
     * Create union would interpret unrelated bytes as a disposition. */
    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE)
        exchange->Request.Reserved = (Data->Iopb->Parameters.Create.Options >> 24) & 0xff;
    else exchange->Request.Reserved = FILE_OPEN_IF;
    exchange->Request.PathLength = OriginalName->Length;
    RtlCopyMemory( exchange->Request.Path, OriginalName->Buffer,
                   OriginalName->Length );
    if (Version19) {
        USHORT basename = 0;
        /* The typed payload is copied in full below. In particular, the
         * NONE reference kind must carry a zero ParentTransferId rather
         * than whatever bytes happened to be on this stack frame. */
        intent.Version = SAFEUPLOAD_STAGE_EXTENSION_VERSION;
        intent.StructSize = sizeof(intent);
        status = ExUuidCreate(&intent.AllocationReservationId);
        if (!NT_SUCCESS(status)) goto Exit;
        intent.DriverInstanceId = *DriverInstanceId;
        intent.Disposition = exchange->Request.Reserved;
        intent.ReferenceKind = SAFEUPLOAD_STAGE_ALLOC_REFERENCE_NONE;
        if (referenceName != NULL) {
            for (i = 0; i < referenceName->Length / sizeof(WCHAR); ++i)
                if (referenceName->Buffer[i] == L'\\') basename = i + 1;
            if (referenceName->Length / sizeof(WCHAR) - basename < 32 ||
                !StageProtocolParseTransferId(referenceName->Buffer + basename,
                    (USHORT)(referenceName->Length / sizeof(WCHAR) - basename),
                    &intent.ParentTransferId)) {
                status = STATUS_INVALID_PARAMETER;
                goto Exit;
            }
            intent.ReferenceKind = PreviousStageName != NULL ?
                SAFEUPLOAD_STAGE_ALLOC_REFERENCE_FOLLOWUP : SAFEUPLOAD_STAGE_ALLOC_REFERENCE_TOMBSTONE;
        }
        exchange->Request.Reserved = SAFEUPLOAD_STAGE_EXTENSION_VERSION;
        exchange->Request.ImageNameLength = sizeof(intent);
        RtlCopyMemory(exchange->Request.ImageName, &intent, sizeof(intent));
    } else if (referenceName != NULL) {
        USHORT basename = 0;
        for (i = 0; i < referenceName->Length / sizeof( WCHAR ); ++i) {
            if (referenceName->Buffer[i] == L'\\') {
                basename = i + 1;
            }
        }
        if (referenceName->Length / sizeof( WCHAR ) - basename < 32) {
            status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }
        exchange->Request.Flags |= PreviousStageName != NULL ?
            SAFEUPLOAD_REQUEST_FLAG_STAGE_FOLLOWUP : SAFEUPLOAD_REQUEST_FLAG_STAGE_TOMBSTONE_CREATE;
        if (TombstoneStageName != NULL) exchange->Request.Reserved = FILE_CREATE;
        exchange->Request.ImageNameLength = 32 * sizeof( WCHAR );
        RtlCopyMemory( exchange->Request.ImageName,
                       referenceName->Buffer + basename,
                       exchange->Request.ImageNameLength );
    } else {
        SafeUploadCopyRequestImageName( Data, &exchange->Request );
    }

    if (Version19) {
        *AllocationIntent = intent;
        *AllocationRequest = exchange->Request;
    }

    status = Version19 ? StageSendV19Exchange(exchange, FALSE, &verdict, &answered) :
        SafeUploadRequestVerdict(exchange, &verdict, &answered);
    if (Version19 && AllocationMayExist != NULL)
        *AllocationMayExist = exchange->MayHaveReachedService;
    if (!answered || verdict != SAFEUPLOAD_VERDICT_ALLOW) {
        status = !answered ? STATUS_IO_TIMEOUT : STATUS_ACCESS_DENIED;
        goto Exit;
    }
    if (status != STATUS_SUCCESS) { status = STATUS_IO_TIMEOUT; goto Exit; }

    if (Version19) {
#if SAFEUPLOAD_STAGING_PROTOTYPE
        status = StageProtocolReadCreateReply(exchange, &intent.AllocationReservationId,
            StageName, StageNameLength, DestinationGeneration,
            (PSAFEUPLOAD_STAGE_IDENTITY_V19)StageIdentity);
        if (!NT_SUCCESS(status)) goto Exit;
        status = STATUS_SUCCESS;
        goto Exit;
#else
        status = STATUS_NOT_SUPPORTED;
        goto Exit;
#endif
    }

    if (exchange->Response.StageNameLength < 32 * sizeof( WCHAR ) ||
        exchange->Response.StageNameLength >=
            SAFEUPLOAD_MAX_STAGE_NAME_CHARS * sizeof( WCHAR ) ||
        exchange->Response.StageNameLength % sizeof( WCHAR ) != 0) {
        status = STATUS_INVALID_BUFFER_SIZE;
        goto Exit;
    }
    // Accept only the service's GUID basename plus a harmless extension.
    // No separators, colons, dots before the GUID, or relative components.
    for (i = 0; i < exchange->Response.StageNameLength / sizeof( WCHAR ); ++i) {
        WCHAR ch = exchange->Response.StageName[i];
        if (i < 32) {
            if (!((ch >= L'0' && ch <= L'9') ||
                  (ch >= L'a' && ch <= L'f'))) {
                status = STATUS_INVALID_PARAMETER;
                goto Exit;
            }
        } else if (!((ch >= L'a' && ch <= L'z') ||
                     (ch >= L'A' && ch <= L'Z') ||
                     (ch >= L'0' && ch <= L'9') ||
                     ch == L'.' || ch == L'_')) {
            status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }
    }

    *StageNameLength = (USHORT) exchange->Response.StageNameLength;
    RtlCopyMemory( StageName, exchange->Response.StageName,
                   *StageNameLength );
    StageName[*StageNameLength / sizeof( WCHAR )] = L'\0';
    status = STATUS_SUCCESS;

Exit:
    ExFreePoolWithTag( exchange, SAFEUPLOAD_POOL_TAG );
    return status;
}

NTSTATUS SafeUploadStageAllocate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PUNICODE_STRING OriginalName,
    _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind, _In_opt_ PUNICODE_STRING PreviousStageName,
    _In_opt_ PUNICODE_STRING TombstoneStageName,
    _Out_writes_(SAFEUPLOAD_MAX_STAGE_NAME_CHARS) PWCH StageName, _Out_ PUSHORT StageNameLength)
{
    PAGED_CODE();
    return StageAllocateInternal(Data, OriginalName, VolumeKind, PreviousStageName,
        TombstoneStageName, StageName, StageNameLength, FALSE, NULL, NULL, NULL,
        NULL, NULL, NULL);
}

#if SAFEUPLOAD_STAGING_PROTOTYPE
NTSTATUS SafeUploadStageAllocateV19(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PUNICODE_STRING OriginalName,
    _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind, _In_opt_ PUNICODE_STRING PreviousStageName,
    _In_opt_ PUNICODE_STRING TombstoneStageName,
    _Out_writes_(SAFEUPLOAD_MAX_STAGE_NAME_CHARS) PWCH StageName, _Out_ PUSHORT StageNameLength,
    _In_ const GUID *DriverInstanceId,
    _Out_ PUINT64 DestinationGeneration, _Out_ PSAFEUPLOAD_STAGE_IDENTITY_V19 StageIdentity,
    _Out_ PSAFEUPLOAD_STAGE_ALLOCATE_V19 AllocationIntent,
    _Out_ PSAFEUPLOAD_REQUEST AllocationRequest, _Out_ PBOOLEAN AllocationMayExist)
{
    PAGED_CODE();
    return StageAllocateInternal(Data, OriginalName, VolumeKind, PreviousStageName,
        TombstoneStageName, StageName, StageNameLength, TRUE, DestinationGeneration, StageIdentity,
        DriverInstanceId, AllocationIntent, AllocationRequest, AllocationMayExist);
}

NTSTATUS SafeUploadStageReplayAllocationV19(_In_ const SAFEUPLOAD_REQUEST *AllocationRequest,
    _Out_writes_(SAFEUPLOAD_MAX_STAGE_NAME_CHARS) PWCH StageName, _Out_ PUSHORT StageNameLength,
    _Out_ PUINT64 DestinationGeneration, _Out_ PSAFEUPLOAD_STAGE_IDENTITY_V19 StageIdentity)
{
    PSAFEUPLOAD_EXCHANGE exchange;
    SAFEUPLOAD_STAGE_ALLOCATE_V19 intent;
    UINT32 verdict = SAFEUPLOAD_VERDICT_DENY;
    BOOLEAN answered = FALSE;
    NTSTATUS status;
    PAGED_CODE();
    *StageNameLength = 0;
    *DestinationGeneration = 0;
    RtlZeroMemory(StageIdentity, sizeof(*StageIdentity));
    if (AllocationRequest == NULL || AllocationRequest->Version != SAFEUPLOAD_PROTOCOL_VERSION ||
        AllocationRequest->StructSize != sizeof(SAFEUPLOAD_REQUEST) ||
        AllocationRequest->Operation != SAFEUPLOAD_OPERATION_STAGE_ALLOCATE ||
        AllocationRequest->Reserved != SAFEUPLOAD_STAGE_EXTENSION_VERSION ||
        (AllocationRequest->Flags & SAFEUPLOAD_REQUEST_FLAG_STAGE_V19_REPLY) == 0 ||
        AllocationRequest->ImageNameLength != sizeof(intent) ||
        AllocationRequest->RequestId == 0 ||
        AllocationRequest->PathLength == 0 ||
        AllocationRequest->PathLength > SAFEUPLOAD_MAX_PATH_BYTES ||
        (AllocationRequest->PathLength & 1) != 0)
        return STATUS_INVALID_PARAMETER;
    RtlCopyMemory(&intent, AllocationRequest->ImageName, sizeof(intent));
    if (intent.Version != SAFEUPLOAD_STAGE_EXTENSION_VERSION || intent.StructSize != sizeof(intent) ||
        !StageProtocolGuidNonzero(&intent.AllocationReservationId) ||
        !StageProtocolGuidNonzero(&intent.DriverInstanceId) ||
        intent.ReferenceKind > SAFEUPLOAD_STAGE_ALLOC_REFERENCE_TOMBSTONE ||
        ((intent.ReferenceKind == SAFEUPLOAD_STAGE_ALLOC_REFERENCE_NONE) !=
            !StageProtocolGuidNonzero(&intent.ParentTransferId)))
        return STATUS_INVALID_PARAMETER;
    exchange = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*exchange), SAFEUPLOAD_POOL_TAG);
    if (exchange == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(exchange, sizeof(*exchange));
    exchange->Request = *AllocationRequest;
    status = StageSendV19Exchange(exchange, FALSE, &verdict, &answered);
    status = SafeUploadStageExchangeResult(status, answered, verdict);
    if (NT_SUCCESS(status))
        status = StageProtocolReadCreateReply(exchange, &intent.AllocationReservationId,
            StageName, StageNameLength, DestinationGeneration, StageIdentity);
    ExFreePoolWithTag(exchange, SAFEUPLOAD_POOL_TAG);
    return status;
}

static BOOLEAN StageProtocolBytesZero(_In_reads_bytes_(Length) const UCHAR *Bytes, _In_ SIZE_T Length)
{
    UCHAR value = 0;
    SIZE_T index;
    for (index = 0; index < Length; ++index) value |= Bytes[index];
    return value == 0;
}

static BOOLEAN StageProtocolStatusResultValid(_In_ UINT32 Operation, _In_ UINT32 Result)
{
    switch (Operation) {
    case SAFEUPLOAD_OPERATION_STAGE_ATTACH_PREPARE:
        return Result == SAFEUPLOAD_STAGE_RESULT_ATTACH_PREPARED;
    case SAFEUPLOAD_OPERATION_STAGE_ATTACH_COMMIT:
        return Result == SAFEUPLOAD_STAGE_RESULT_ATTACH_COMMITTED ||
            Result == SAFEUPLOAD_STAGE_RESULT_ATTACH_COMMIT_DENIED ||
            Result == SAFEUPLOAD_STAGE_RESULT_ATTACH_ALREADY_COMMITTED;
    case SAFEUPLOAD_OPERATION_STAGE_ATTACH_ABORT:
        return Result == SAFEUPLOAD_STAGE_RESULT_ATTACH_ABORTED ||
            Result == SAFEUPLOAD_STAGE_RESULT_ATTACH_ALREADY_COMMITTED;
    case SAFEUPLOAD_OPERATION_STAGE_ATTACH_COMPLETION_PERMITTED:
        return Result == SAFEUPLOAD_STAGE_RESULT_COMPLETION_PERMITTED;
    case SAFEUPLOAD_OPERATION_STAGE_RETIRE_UNEXPOSED:
        return Result == SAFEUPLOAD_STAGE_RESULT_ATTACH_RETIRED_UNEXPOSED;
    case SAFEUPLOAD_OPERATION_STAGE_RETIRE_ATTACHED_PRIVATE:
        return Result == SAFEUPLOAD_STAGE_RESULT_ATTACH_RETIRED_PRIVATE;
    case SAFEUPLOAD_OPERATION_STAGE_ATTACH_HANDLE_OBSERVED:
        return Result == SAFEUPLOAD_STAGE_RESULT_HANDLE_OBSERVED;
    default:
        return FALSE;
    }
}

static NTSTATUS StageProtocolPrepareAttachRequestV20(_In_ ULONG ProcessId,
    _In_ PUNICODE_STRING DestinationName, _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind,
    _In_ UINT32 Operation, _In_ const GUID *TransferId, _In_ UINT64 DestinationGeneration,
    _In_ const SAFEUPLOAD_STAGE_IDENTITY_V19 *StageIdentity, _In_ const GUID *DriverInstanceId,
    _In_ const SAFEUPLOAD_STAGE_IDENTITY_V19 *ParentDirectoryIdentity,
    _Inout_ PSAFEUPLOAD_REQUEST Request)
{
    PSAFEUPLOAD_REQUEST expected;
    PSAFEUPLOAD_STAGE_ATTACH_STATUS_V20 payload;
    NTSTATUS status;
    PAGED_CODE();
    if (Request == NULL || DestinationName == NULL || DestinationName->Buffer == NULL ||
        DestinationName->Length == 0 || DestinationName->Length > SAFEUPLOAD_MAX_PATH_BYTES ||
        (DestinationName->Length & 1) != 0 || ProcessId == 0 || TransferId == NULL ||
        !StageProtocolGuidNonzero(TransferId) || DestinationGeneration == 0 ||
        StageIdentity == NULL || !StageV19IdentityNonzero(StageIdentity) || DriverInstanceId == NULL ||
        !StageProtocolGuidNonzero(DriverInstanceId) || ParentDirectoryIdentity == NULL ||
        !StageV19IdentityNonzero(ParentDirectoryIdentity) ||
        (Operation != SAFEUPLOAD_OPERATION_STAGE_ATTACH_PREPARE &&
         Operation != SAFEUPLOAD_OPERATION_STAGE_ATTACH_COMMIT &&
         Operation != SAFEUPLOAD_OPERATION_STAGE_ATTACH_ABORT &&
         Operation != SAFEUPLOAD_OPERATION_STAGE_ATTACH_COMPLETION_PERMITTED &&
         Operation != SAFEUPLOAD_OPERATION_STAGE_RETIRE_UNEXPOSED &&
         Operation != SAFEUPLOAD_OPERATION_STAGE_RETIRE_ATTACHED_PRIVATE &&
         Operation != SAFEUPLOAD_OPERATION_STAGE_ATTACH_HANDLE_OBSERVED))
        return STATUS_INVALID_PARAMETER;

    /* Op18 is deliberately unavailable until the Windows lifecycle proof is
     * reviewed. A caller cannot make it available by constructing a payload. */
    if (Operation == SAFEUPLOAD_OPERATION_STAGE_RETIRE_ATTACHED_PRIVATE)
        return STATUS_NOT_SUPPORTED;

    expected = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*expected), SAFEUPLOAD_POOL_TAG);
    if (expected == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(expected, sizeof(*expected));
    expected->Version = SAFEUPLOAD_PROTOCOL_VERSION;
    expected->StructSize = sizeof(*expected);
    expected->RequestId = Request->RequestId;
    if (expected->RequestId == 0)
        expected->RequestId = (UINT64)InterlockedIncrement64(&SafeUploadData.NextRequestId);
    expected->Operation = Operation;
    expected->RequestorProcessId = ProcessId;
    if (VolumeKind == SafeUploadVolumeRemovable)
        expected->Flags = SAFEUPLOAD_REQUEST_FLAG_STAGE_REMOVABLE;
    else if (VolumeKind == SafeUploadVolumeNetwork)
        expected->Flags = SAFEUPLOAD_REQUEST_FLAG_STAGE_NETWORK;
    expected->PathLength = DestinationName->Length;
    RtlCopyMemory(expected->Path, DestinationName->Buffer, DestinationName->Length);
    expected->Reserved = SAFEUPLOAD_STAGE_EXTENSION_VERSION;
    expected->ImageNameLength = sizeof(*payload);
    payload = (PSAFEUPLOAD_STAGE_ATTACH_STATUS_V20)expected->ImageName;
    payload->Version = SAFEUPLOAD_STAGE_EXTENSION_VERSION;
    payload->StructSize = sizeof(*payload);
    payload->Operation = Operation;
    payload->Result = 0;
    payload->RequestId = expected->RequestId;
    payload->TransferId = *TransferId;
    payload->DestinationGeneration = DestinationGeneration;
    payload->StageIdentity = *StageIdentity;
    payload->DriverInstanceId = *DriverInstanceId;
    payload->ParentDirectoryIdentity = *ParentDirectoryIdentity;

    if (Request->RequestId == 0) {
        *Request = *expected;
        status = STATUS_SUCCESS;
    } else {
        /* A may-have-reached-service request is retried byte-for-byte. This
         * comparison prevents a caller from reusing its RequestId for a changed
         * operation, path, epoch, parent or identity tuple. */
        status = RtlEqualMemory(Request, expected, sizeof(*expected)) ? STATUS_SUCCESS :
            STATUS_INVALID_PARAMETER;
    }
    ExFreePoolWithTag(expected, SAFEUPLOAD_POOL_TAG);
    return status;
}

static NTSTATUS StageProtocolReadAttachReplyV20(_In_ PSAFEUPLOAD_EXCHANGE Exchange,
    _In_ const SAFEUPLOAD_STAGE_ATTACH_STATUS_V20 *Expected, _Out_ PUINT32 Result)
{
    SAFEUPLOAD_STAGE_ATTACH_STATUS_V20 reply;
    SAFEUPLOAD_RESPONSE *outer = &Exchange->Response;
    if (outer->Version != SAFEUPLOAD_PROTOCOL_VERSION || outer->StructSize != sizeof(*outer) ||
        outer->RequestId != Exchange->Request.RequestId || outer->Verdict != SAFEUPLOAD_VERDICT_ALLOW ||
        outer->StageNameLength != sizeof(reply) ||
        !StageProtocolBytesZero((const UCHAR *)outer->StageName + sizeof(reply),
            sizeof(outer->StageName) - sizeof(reply)))
        return STATUS_INVALID_BUFFER_SIZE;
    RtlCopyMemory(&reply, outer->StageName, sizeof(reply));
    if (reply.Version != SAFEUPLOAD_STAGE_EXTENSION_VERSION || reply.StructSize != sizeof(reply) ||
        reply.Operation != Expected->Operation || reply.Result == 0 ||
        !StageProtocolStatusResultValid(reply.Operation, reply.Result) ||
        reply.RequestId != Expected->RequestId ||
        !StageProtocolGuidEqual(&reply.TransferId, &Expected->TransferId) ||
        reply.DestinationGeneration != Expected->DestinationGeneration ||
        !RtlEqualMemory(&reply.StageIdentity, &Expected->StageIdentity, sizeof(reply.StageIdentity)) ||
        !StageProtocolGuidEqual(&reply.DriverInstanceId, &Expected->DriverInstanceId) ||
        !RtlEqualMemory(&reply.ParentDirectoryIdentity, &Expected->ParentDirectoryIdentity,
            sizeof(reply.ParentDirectoryIdentity)))
        return STATUS_INVALID_BUFFER_SIZE;
    *Result = reply.Result;
    return STATUS_SUCCESS;
}

NTSTATUS SafeUploadStageAttachmentExchangeV20(_In_ ULONG ProcessId,
    _In_ PUNICODE_STRING DestinationName, _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind,
    _In_ UINT32 Operation, _In_ const GUID *TransferId,
    _In_ UINT64 DestinationGeneration, _In_ const SAFEUPLOAD_STAGE_IDENTITY_V19 *StageIdentity,
    _In_ const GUID *DriverInstanceId,
    _In_ const SAFEUPLOAD_STAGE_IDENTITY_V19 *ParentDirectoryIdentity,
    _Inout_ PSAFEUPLOAD_REQUEST RequestSnapshot, _Out_ PUINT32 Result,
    _Out_ PBOOLEAN RequestMayExist)
{
    PSAFEUPLOAD_EXCHANGE exchange;
    SAFEUPLOAD_STAGE_ATTACH_STATUS_V20 expected;
    UINT32 verdict = SAFEUPLOAD_VERDICT_DENY;
    BOOLEAN answered = FALSE;
    NTSTATUS status;
    PAGED_CODE();
    if (Result != NULL) *Result = 0;
    if (RequestMayExist != NULL) *RequestMayExist = FALSE;
    if (Result == NULL || RequestSnapshot == NULL || RequestMayExist == NULL) return STATUS_INVALID_PARAMETER;
    status = StageProtocolPrepareAttachRequestV20(ProcessId, DestinationName, VolumeKind, Operation,
        TransferId, DestinationGeneration, StageIdentity, DriverInstanceId,
        ParentDirectoryIdentity, RequestSnapshot);
    if (!NT_SUCCESS(status)) return status;
    RtlCopyMemory(&expected, RequestSnapshot->ImageName, sizeof(expected));
    exchange = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*exchange), SAFEUPLOAD_POOL_TAG);
    if (exchange == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(exchange, sizeof(*exchange));
    exchange->Request = *RequestSnapshot;
    status = StageSendV19Exchange(exchange, FALSE, &verdict, &answered);
    *RequestMayExist = exchange->MayHaveReachedService;
    status = SafeUploadStageExchangeResult(status, answered, verdict);
    if (NT_SUCCESS(status)) status = StageProtocolReadAttachReplyV20(exchange, &expected, Result);
    ExFreePoolWithTag(exchange, SAFEUPLOAD_POOL_TAG);
    return status;
}

BOOLEAN SafeUploadStageAttachmentRequestV20Matches(_In_ const SAFEUPLOAD_REQUEST *RequestSnapshot,
    _In_ ULONG ProcessId, _In_ PUNICODE_STRING DestinationName,
    _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind, _In_ UINT32 Operation,
    _In_ const GUID *TransferId, _In_ UINT64 DestinationGeneration,
    _In_ const SAFEUPLOAD_STAGE_IDENTITY_V19 *StageIdentity,
    _In_ const GUID *DriverInstanceId,
    _In_ const SAFEUPLOAD_STAGE_IDENTITY_V19 *ParentDirectoryIdentity)
{
    PSAFEUPLOAD_REQUEST expected;
    NTSTATUS status;
    PAGED_CODE();
    if (RequestSnapshot == NULL || RequestSnapshot->RequestId == 0) return FALSE;
    expected = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*expected), SAFEUPLOAD_POOL_TAG);
    if (expected == NULL) return FALSE;
    *expected = *RequestSnapshot;
    status = StageProtocolPrepareAttachRequestV20(ProcessId, DestinationName, VolumeKind,
        Operation, TransferId, DestinationGeneration, StageIdentity, DriverInstanceId,
        ParentDirectoryIdentity, expected);
    if (NT_SUCCESS(status)) status = RtlEqualMemory(RequestSnapshot, expected, sizeof(*expected)) ?
        STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
    ExFreePoolWithTag(expected, SAFEUPLOAD_POOL_TAG);
    return NT_SUCCESS(status);
}

static BOOLEAN StageProtocolValidDrainReplayRequest(_In_ const SAFEUPLOAD_REQUEST *Request,
    _In_ const GUID *DriverInstanceId, _Out_ PUINT64 DrainNonce)
{
    PSAFEUPLOAD_REQUEST expected;
    SAFEUPLOAD_STAGE_EPOCH_DRAIN_V20 payload;
    PSAFEUPLOAD_STAGE_EPOCH_DRAIN_V20 supplied;
    PAGED_CODE();
    if (DrainNonce != NULL) *DrainNonce = 0;
    if (Request == NULL || DriverInstanceId == NULL || DrainNonce == NULL ||
        Request->RequestId == 0 || Request->PathLength != 0 ||
        Request->RequestorProcessId != 0 || Request->Flags != 0 ||
        Request->Operation != SAFEUPLOAD_OPERATION_STAGE_EPOCH_DRAIN ||
        Request->Reserved != SAFEUPLOAD_STAGE_EXTENSION_VERSION ||
        Request->ImageNameLength != sizeof(payload)) return FALSE;
    supplied = (PSAFEUPLOAD_STAGE_EPOCH_DRAIN_V20)Request->ImageName;
    if (supplied->Version != SAFEUPLOAD_STAGE_EXTENSION_VERSION ||
        supplied->StructSize != sizeof(*supplied) || supplied->DrainNonce == 0 ||
        !StageProtocolGuidEqual(&supplied->DriverInstanceId, DriverInstanceId)) return FALSE;
    expected = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*expected), SAFEUPLOAD_POOL_TAG);
    if (expected == NULL) return FALSE;
    RtlZeroMemory(&payload, sizeof(payload));
    payload.Version = SAFEUPLOAD_STAGE_EXTENSION_VERSION;
    payload.StructSize = sizeof(payload);
    payload.DriverInstanceId = *DriverInstanceId;
    payload.DrainNonce = supplied->DrainNonce;
    RtlZeroMemory(expected, sizeof(*expected));
    expected->Version = SAFEUPLOAD_PROTOCOL_VERSION;
    expected->StructSize = sizeof(*expected);
    expected->RequestId = Request->RequestId;
    expected->Operation = SAFEUPLOAD_OPERATION_STAGE_EPOCH_DRAIN;
    expected->Reserved = SAFEUPLOAD_STAGE_EXTENSION_VERSION;
    expected->ImageNameLength = sizeof(payload);
    RtlCopyMemory(expected->ImageName, &payload, sizeof(payload));
    if (!RtlEqualMemory(expected, Request, sizeof(*expected))) {
        ExFreePoolWithTag(expected, SAFEUPLOAD_POOL_TAG);
        return FALSE;
    }
    *DrainNonce = supplied->DrainNonce;
    ExFreePoolWithTag(expected, SAFEUPLOAD_POOL_TAG);
    return TRUE;
}

/* The outer reconcile routine is pageable and may wait for the service. Keep
 * each spin-lock critical section in resident code, then return to its caller
 * at the original PASSIVE_LEVEL before it touches pageable state again. */
__declspec(noinline) static BOOLEAN StageProtocolReconcileBegin(_In_ LONG ExchangeGeneration,
    _Out_ PVOID *ExchangeCookie)
{
    KIRQL stateIrql;
    PVOID exchangeCookie;
    BOOLEAN channelCurrent;
    *ExchangeCookie = NULL;
    KeAcquireSpinLock(&SafeUploadStageV20StateLock, &stateIrql);
    exchangeCookie = InterlockedCompareExchangePointer(&SafeUploadStageV20ConnectionCookie, NULL, NULL);
    channelCurrent = SafeUploadStageProtocolChannelGeneration() == ExchangeGeneration &&
        exchangeCookie != NULL &&
        InterlockedCompareExchange(&SafeUploadStageV20ChannelActive, 0, 0) != 0 &&
        InterlockedCompareExchange(&SafeUploadData.AuthenticatedClient, 0, 0) != 0;
    if (channelCurrent) {
        InterlockedExchange(&SafeUploadStageV19ReadyGeneration, 0);
        StageProtocolClearDrainReplayLocked();
        *ExchangeCookie = exchangeCookie;
    }
    KeReleaseSpinLock(&SafeUploadStageV20StateLock, stateIrql);
    return channelCurrent;
}

__declspec(noinline) static BOOLEAN StageProtocolReconcilePublish(_In_ LONG ExchangeGeneration,
    _In_ PVOID ExchangeCookie, _In_ BOOLEAN CapabilitiesAccepted,
    _In_ BOOLEAN DrainReplayValid, _In_ GUID DriverInstanceId,
    _In_ UINT64 DrainReplayRequestId, _In_ UINT64 DrainNonce)
{
    KIRQL stateIrql;
    BOOLEAN channelCurrent;
    KeAcquireSpinLock(&SafeUploadStageV20StateLock, &stateIrql);
    channelCurrent = SafeUploadStageProtocolChannelGeneration() == ExchangeGeneration &&
        InterlockedCompareExchangePointer(&SafeUploadStageV20ConnectionCookie, NULL, NULL) ==
            ExchangeCookie &&
        InterlockedCompareExchange(&SafeUploadStageV20ChannelActive, 0, 0) != 0 &&
        InterlockedCompareExchange(&SafeUploadData.AuthenticatedClient, 0, 0) != 0;
    if (channelCurrent && CapabilitiesAccepted) {
        StageProtocolClearDrainReplayLocked();
        InterlockedExchange(&SafeUploadStageV19ReadyGeneration, ExchangeGeneration);
    } else if (channelCurrent) {
        InterlockedExchange(&SafeUploadStageV19ReadyGeneration, 0);
        if (DrainReplayValid) {
            SafeUploadStageV20DrainReplayReady = TRUE;
            SafeUploadStageV20DrainReplayGeneration = ExchangeGeneration;
            SafeUploadStageV20DrainReplayCookie = ExchangeCookie;
            SafeUploadStageV20DrainReplayInstance = DriverInstanceId;
            SafeUploadStageV20DrainReplayRequestId = DrainReplayRequestId;
            SafeUploadStageV20DrainReplayNonce = DrainNonce;
        } else {
            SafeUploadStageV20DrainReplayReady = FALSE;
        }
    }
    KeReleaseSpinLock(&SafeUploadStageV20StateLock, stateIrql);
    return channelCurrent;
}

__declspec(noinline) static VOID StageProtocolReconcileFailure(_In_ LONG ExchangeGeneration,
    _In_ PVOID ExchangeCookie)
{
    KIRQL stateIrql;
    KeAcquireSpinLock(&SafeUploadStageV20StateLock, &stateIrql);
    if (SafeUploadStageProtocolChannelGeneration() == ExchangeGeneration &&
        InterlockedCompareExchangePointer(&SafeUploadStageV20ConnectionCookie, NULL, NULL) ==
            ExchangeCookie) {
        InterlockedExchange(&SafeUploadStageV19ReadyGeneration, 0);
        StageProtocolClearDrainReplayLocked();
    }
    KeReleaseSpinLock(&SafeUploadStageV20StateLock, stateIrql);
}

NTSTATUS SafeUploadStageReconcileV20(_In_ const GUID *DriverInstanceId,
    _In_ LONG ExpectedChannelGeneration, _In_opt_ const SAFEUPLOAD_REQUEST *DrainReplayRequest)
{
    PSAFEUPLOAD_EXCHANGE exchange;
    SAFEUPLOAD_STAGE_RECONCILE_V20 payload;
    SAFEUPLOAD_STAGE_RECONCILE_REPLY_V20 reply;
    UINT32 verdict = SAFEUPLOAD_VERDICT_DENY;
    BOOLEAN answered = FALSE;
    UINT64 drainNonce = 0;
    UINT64 drainReplayRequestId = 0;
    BOOLEAN drainReplayValid = FALSE;
    LONG exchangeGeneration;
    PVOID exchangeCookie;
    BOOLEAN channelCurrent;
    NTSTATUS status;
    PAGED_CODE();
    if (DriverInstanceId == NULL || !StageProtocolGuidNonzero(DriverInstanceId))
        return STATUS_INVALID_PARAMETER;
    exchangeGeneration = SafeUploadStageProtocolChannelGeneration();
    if (ExpectedChannelGeneration == 0 || exchangeGeneration != ExpectedChannelGeneration)
        return STATUS_PORT_DISCONNECTED;
    if (DrainReplayRequest != NULL) {
        drainReplayValid = StageProtocolValidDrainReplayRequest(DrainReplayRequest,
            DriverInstanceId, &drainNonce);
        if (drainReplayValid) drainReplayRequestId = DrainReplayRequest->RequestId;
    }
    /* Reconciliation replaces the authority for this channel. Clear both
     * ordinary readiness and any prior drain-only replay before sending; a
     * timeout, malformed reply, or stale generation must leave no old grant. */
    ExAcquireFastMutex(&SafeUploadStageV19ExchangeMutex);
    channelCurrent = StageProtocolReconcileBegin(exchangeGeneration, &exchangeCookie);
    ExReleaseFastMutex(&SafeUploadStageV19ExchangeMutex);
    if (!channelCurrent) return STATUS_PORT_DISCONNECTED;
    exchange = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*exchange), SAFEUPLOAD_POOL_TAG);
    if (exchange == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(exchange, sizeof(*exchange));
    RtlZeroMemory(&payload, sizeof(payload));
    payload.Version = SAFEUPLOAD_STAGE_EXTENSION_VERSION;
    payload.StructSize = sizeof(payload);
    payload.DriverInstanceId = *DriverInstanceId;
    payload.RequiredCapabilityMask = SAFEUPLOAD_STAGE_CAPABILITY_REQUIRED;
    exchange->Request.Version = SAFEUPLOAD_PROTOCOL_VERSION;
    exchange->Request.StructSize = sizeof(SAFEUPLOAD_REQUEST);
    exchange->Request.RequestId = (UINT64)InterlockedIncrement64(&SafeUploadData.NextRequestId);
    exchange->Request.Operation = SAFEUPLOAD_OPERATION_STAGE_RECONCILE;
    exchange->Request.Reserved = SAFEUPLOAD_STAGE_EXTENSION_VERSION;
    exchange->Request.ImageNameLength = sizeof(payload);
    RtlCopyMemory(exchange->Request.ImageName, &payload, sizeof(payload));
    exchange->ChannelGeneration = exchangeGeneration;
    exchange->ChannelCookie = exchangeCookie;
    status = StageSendV19Exchange(exchange, TRUE, &verdict, &answered);
    status = SafeUploadStageExchangeResult(status, answered, verdict);
    if (NT_SUCCESS(status)) {
        if (exchange->Response.Version != SAFEUPLOAD_PROTOCOL_VERSION ||
            exchange->Response.StructSize != sizeof(SAFEUPLOAD_RESPONSE) ||
            exchange->Response.RequestId != exchange->Request.RequestId ||
            exchange->Response.Verdict != SAFEUPLOAD_VERDICT_ALLOW ||
            exchange->Response.StageNameLength != sizeof(reply) ||
            !StageProtocolBytesZero((const UCHAR *)exchange->Response.StageName + sizeof(reply),
                sizeof(exchange->Response.StageName) - sizeof(reply))) {
            status = STATUS_INVALID_BUFFER_SIZE;
        } else {
            RtlCopyMemory(&reply, exchange->Response.StageName, sizeof(reply));
            if (reply.Version != SAFEUPLOAD_STAGE_EXTENSION_VERSION ||
                reply.StructSize != sizeof(reply) ||
                reply.Operation != SAFEUPLOAD_OPERATION_STAGE_RECONCILE ||
                reply.RequestId != exchange->Request.RequestId ||
                !StageProtocolGuidEqual(&reply.DriverInstanceId, DriverInstanceId) ||
                reply.Reserved != 0 ||
                (reply.Result == SAFEUPLOAD_STAGE_RESULT_CAPABILITIES_ACCEPTED &&
                 reply.AcceptedCapabilityMask != SAFEUPLOAD_STAGE_CAPABILITY_REQUIRED) ||
                (reply.Result == SAFEUPLOAD_STAGE_RESULT_EPOCH_BUSY && reply.AcceptedCapabilityMask != 0) ||
                (reply.Result != SAFEUPLOAD_STAGE_RESULT_CAPABILITIES_ACCEPTED &&
                 reply.Result != SAFEUPLOAD_STAGE_RESULT_EPOCH_BUSY)) {
                status = STATUS_INVALID_BUFFER_SIZE;
            } else if (reply.Result == SAFEUPLOAD_STAGE_RESULT_CAPABILITIES_ACCEPTED) {
                ExAcquireFastMutex(&SafeUploadStageV19ExchangeMutex);
                channelCurrent = StageProtocolReconcilePublish(exchangeGeneration, exchangeCookie,
                    TRUE, FALSE, *DriverInstanceId, 0, 0);
                ExReleaseFastMutex(&SafeUploadStageV19ExchangeMutex);
                if (!channelCurrent) status = STATUS_PORT_DISCONNECTED;
            } else {
                ExAcquireFastMutex(&SafeUploadStageV19ExchangeMutex);
                channelCurrent = StageProtocolReconcilePublish(exchangeGeneration, exchangeCookie,
                    FALSE, drainReplayValid, *DriverInstanceId,
                    drainReplayRequestId, drainNonce);
                ExReleaseFastMutex(&SafeUploadStageV19ExchangeMutex);
                status = channelCurrent ? STATUS_DEVICE_BUSY : STATUS_PORT_DISCONNECTED;
            }
        }
    } else {
        /* A stale/timed-out reply may not clear readiness on a replacement
         * channel. Only clear the generation that began this handshake. */
        StageProtocolReconcileFailure(exchangeGeneration, exchangeCookie);
    }
    ExFreePoolWithTag(exchange, SAFEUPLOAD_POOL_TAG);
    return status;
}

NTSTATUS SafeUploadStageEpochDrainV20(_In_ const GUID *DriverInstanceId,
    _In_ UINT64 DrainNonce, _Inout_ PSAFEUPLOAD_REQUEST RequestSnapshot,
    _Out_ PUINT32 Result)
{
    PSAFEUPLOAD_EXCHANGE exchange;
    SAFEUPLOAD_STAGE_EPOCH_DRAIN_V20 payload;
    SAFEUPLOAD_STAGE_EPOCH_DRAIN_REPLY_V20 reply;
    PSAFEUPLOAD_REQUEST expected;
    UINT32 verdict = SAFEUPLOAD_VERDICT_DENY;
    BOOLEAN answered = FALSE;
    NTSTATUS status;
    PAGED_CODE();
    if (Result != NULL) *Result = 0;
    if (RequestSnapshot == NULL || Result == NULL || DriverInstanceId == NULL || DrainNonce == 0 ||
        !StageProtocolGuidNonzero(DriverInstanceId)) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(&payload, sizeof(payload));
    payload.Version = SAFEUPLOAD_STAGE_EXTENSION_VERSION;
    payload.StructSize = sizeof(payload);
    payload.DriverInstanceId = *DriverInstanceId;
    payload.DrainNonce = DrainNonce;
    if (RequestSnapshot->RequestId == 0) {
        RtlZeroMemory(RequestSnapshot, sizeof(*RequestSnapshot));
        RequestSnapshot->Version = SAFEUPLOAD_PROTOCOL_VERSION;
        RequestSnapshot->StructSize = sizeof(*RequestSnapshot);
        RequestSnapshot->RequestId = (UINT64)InterlockedIncrement64(&SafeUploadData.NextRequestId);
        RequestSnapshot->Operation = SAFEUPLOAD_OPERATION_STAGE_EPOCH_DRAIN;
        RequestSnapshot->Reserved = SAFEUPLOAD_STAGE_EXTENSION_VERSION;
        RequestSnapshot->ImageNameLength = sizeof(payload);
        RtlCopyMemory(RequestSnapshot->ImageName, &payload, sizeof(payload));
    } else {
        expected = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*expected), SAFEUPLOAD_POOL_TAG);
        if (expected == NULL) return STATUS_INSUFFICIENT_RESOURCES;
        RtlZeroMemory(expected, sizeof(*expected));
        expected->Version = SAFEUPLOAD_PROTOCOL_VERSION;
        expected->StructSize = sizeof(*expected);
        expected->RequestId = RequestSnapshot->RequestId;
        expected->Operation = SAFEUPLOAD_OPERATION_STAGE_EPOCH_DRAIN;
        expected->Reserved = SAFEUPLOAD_STAGE_EXTENSION_VERSION;
        expected->ImageNameLength = sizeof(payload);
        RtlCopyMemory(expected->ImageName, &payload, sizeof(payload));
        if (!RtlEqualMemory(RequestSnapshot, expected, sizeof(*expected))) {
            ExFreePoolWithTag(expected, SAFEUPLOAD_POOL_TAG);
            return STATUS_INVALID_PARAMETER;
        }
        ExFreePoolWithTag(expected, SAFEUPLOAD_POOL_TAG);
    }
    exchange = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*exchange), SAFEUPLOAD_POOL_TAG);
    if (exchange == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(exchange, sizeof(*exchange));
    exchange->Request = *RequestSnapshot;
    status = StageSendV19Exchange(exchange, FALSE, &verdict, &answered);
    status = SafeUploadStageExchangeResult(status, answered, verdict);
    if (NT_SUCCESS(status)) {
        if (exchange->Response.Version != SAFEUPLOAD_PROTOCOL_VERSION ||
            exchange->Response.StructSize != sizeof(SAFEUPLOAD_RESPONSE) ||
            exchange->Response.RequestId != exchange->Request.RequestId ||
            exchange->Response.Verdict != SAFEUPLOAD_VERDICT_ALLOW ||
            exchange->Response.StageNameLength != sizeof(reply) ||
            !StageProtocolBytesZero((const UCHAR *)exchange->Response.StageName + sizeof(reply),
                sizeof(exchange->Response.StageName) - sizeof(reply))) {
            status = STATUS_INVALID_BUFFER_SIZE;
        } else {
            RtlCopyMemory(&reply, exchange->Response.StageName, sizeof(reply));
            if (reply.Version != SAFEUPLOAD_STAGE_EXTENSION_VERSION ||
                reply.StructSize != sizeof(reply) ||
                reply.Operation != SAFEUPLOAD_OPERATION_STAGE_EPOCH_DRAIN ||
                (reply.Result != SAFEUPLOAD_STAGE_RESULT_EPOCH_DRAINED &&
                 reply.Result != SAFEUPLOAD_STAGE_RESULT_EPOCH_BUSY) ||
                reply.RequestId != exchange->Request.RequestId ||
                !StageProtocolGuidEqual(&reply.DriverInstanceId, DriverInstanceId) ||
                reply.DrainNonce != DrainNonce) {
                status = STATUS_INVALID_BUFFER_SIZE;
            } else if (reply.Result == SAFEUPLOAD_STAGE_RESULT_EPOCH_BUSY) {
                *Result = reply.Result;
                status = STATUS_DEVICE_BUSY;
            } else {
                *Result = reply.Result;
            }
        }
    }
    ExFreePoolWithTag(exchange, SAFEUPLOAD_POOL_TAG);
    return status;
}
#endif

static NTSTATUS
StageSendVersionRequest (
    _In_ UINT32 Operation,
    _In_ ULONG ProcessId,
    _In_ PUNICODE_STRING StageName
    )
{
    PSAFEUPLOAD_EXCHANGE exchange;
    UINT32 verdict;
    BOOLEAN answered;
    NTSTATUS status;

    PAGED_CODE();
    if (StageName->Length == 0 ||
        StageName->Length > SAFEUPLOAD_MAX_PATH_BYTES) {
        return STATUS_NAME_TOO_LONG;
    }
    exchange = ExAllocatePool2( POOL_FLAG_NON_PAGED,
                                sizeof( *exchange ), SAFEUPLOAD_POOL_TAG );
    if (exchange == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory( exchange, sizeof( *exchange ) );
    exchange->Request.Version = SAFEUPLOAD_PROTOCOL_VERSION;
    exchange->Request.StructSize = sizeof( SAFEUPLOAD_REQUEST );
    exchange->Request.RequestId =
        (UINT64) InterlockedIncrement64( &SafeUploadData.NextRequestId );
    exchange->Request.Operation = Operation;
    exchange->Request.RequestorProcessId = ProcessId;
    exchange->Request.PathLength = StageName->Length;
    RtlCopyMemory( exchange->Request.Path, StageName->Buffer,
                   StageName->Length );
    status = SafeUploadRequestVerdict( exchange, &verdict, &answered );
    ExFreePoolWithTag( exchange, SAFEUPLOAD_POOL_TAG );
    return SafeUploadStageExchangeResult( status, answered, verdict );
}

#if SAFEUPLOAD_STAGING_PROTOTYPE
static NTSTATUS
StageSendVersionRequestV19 (
    _In_ UINT32 Operation,
    _In_ ULONG ProcessId,
    _In_ PUNICODE_STRING StageName,
    _In_opt_ const GUID *ReservationId,
    _In_ const SAFEUPLOAD_STAGE_IDENTITY_V19 *StageIdentity,
    _In_ UINT64 DestinationGeneration,
    _In_ UINT32 Kind,
    _Out_opt_ PUINT32 Result
    )
{
    PSAFEUPLOAD_EXCHANGE exchange;
    SAFEUPLOAD_STAGE_VERSION_V19 extension;
    UINT32 verdict = SAFEUPLOAD_VERDICT_DENY;
    UINT32 result;
    BOOLEAN answered = FALSE;
    NTSTATUS status;

    PAGED_CODE();
    if (Result != NULL) *Result = 0;
    if ((Operation != SAFEUPLOAD_OPERATION_STAGE_DISCARD &&
         Operation != SAFEUPLOAD_OPERATION_STAGE_SEAL) ||
        StageName->Length == 0 || StageName->Length > SAFEUPLOAD_MAX_PATH_BYTES ||
        DestinationGeneration == 0 || StageIdentity == NULL || Result == NULL ||
        (Operation == SAFEUPLOAD_OPERATION_STAGE_DISCARD &&
         (ReservationId == NULL ||
          (Kind != SAFEUPLOAD_STAGE_DISCARD_KIND_PRIVATE_VERSION &&
           Kind != SAFEUPLOAD_STAGE_DISCARD_KIND_EMPTY_HELD_CLEANUP &&
           Kind != SAFEUPLOAD_STAGE_DISCARD_KIND_OWNER_EXIT_EMPTY &&
           Kind != SAFEUPLOAD_STAGE_DISCARD_KIND_DRIVER_UNLOAD_EMPTY &&
           Kind != SAFEUPLOAD_STAGE_DISCARD_KIND_UNATTACHED_ALLOCATION))))
        return STATUS_INVALID_PARAMETER;

    exchange = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*exchange), SAFEUPLOAD_POOL_TAG);
    if (exchange == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(exchange, sizeof(*exchange));
    exchange->Request.Version = SAFEUPLOAD_PROTOCOL_VERSION;
    exchange->Request.StructSize = sizeof(SAFEUPLOAD_REQUEST);
    exchange->Request.RequestId = (UINT64)InterlockedIncrement64(&SafeUploadData.NextRequestId);
    exchange->Request.Operation = Operation;
    exchange->Request.RequestorProcessId = ProcessId;
    exchange->Request.Reserved = SAFEUPLOAD_STAGE_EXTENSION_VERSION;
    exchange->Request.PathLength = StageName->Length;
    RtlCopyMemory(exchange->Request.Path, StageName->Buffer, StageName->Length);

    if (Operation == SAFEUPLOAD_OPERATION_STAGE_DISCARD) {
        RtlZeroMemory(&extension, sizeof(extension));
        extension.Version = SAFEUPLOAD_STAGE_EXTENSION_VERSION;
        extension.StructSize = sizeof(extension);
        extension.ReservationId = *ReservationId;
        extension.StageIdentity = *StageIdentity;
        extension.DestinationGeneration = DestinationGeneration;
        extension.Kind = Kind;
        exchange->Request.ImageNameLength = sizeof(extension);
        RtlCopyMemory(exchange->Request.ImageName, &extension, sizeof(extension));
    } else {
        SAFEUPLOAD_STAGE_SEAL_V19 seal;
        RtlZeroMemory(&seal, sizeof(seal));
        seal.Version = SAFEUPLOAD_STAGE_EXTENSION_VERSION;
        seal.StructSize = sizeof(seal);
        seal.StageIdentity = *StageIdentity;
        seal.DestinationGeneration = DestinationGeneration;
        exchange->Request.ImageNameLength = sizeof(seal);
        RtlCopyMemory(exchange->Request.ImageName, &seal, sizeof(seal));
    }

    status = StageSendV19Exchange(exchange, FALSE, &verdict, &answered);
    status = SafeUploadStageExchangeResult(status, answered, verdict);
    if (NT_SUCCESS(status) && Operation == SAFEUPLOAD_OPERATION_STAGE_DISCARD) {
        result = exchange->Response.StageNameLength;
        if (result != SAFEUPLOAD_STAGE_REPLY_DISCARD_PENDING &&
            result != SAFEUPLOAD_STAGE_REPLY_DISCARD_ACKNOWLEDGED) status = STATUS_INVALID_BUFFER_SIZE;
        else *Result = result;
    } else if (NT_SUCCESS(status) && Operation == SAFEUPLOAD_OPERATION_STAGE_SEAL) {
        /* Require an explicit v19 classification. A legacy allow reply has
         * StageNameLength==0 and must never turn an empty save into a normal
         * sealed version. */
        result = exchange->Response.StageNameLength;
        if (result != SAFEUPLOAD_STAGE_REPLY_SEALED_NONEMPTY &&
            result != SAFEUPLOAD_STAGE_REPLY_EMPTY_HELD) status = STATUS_INVALID_BUFFER_SIZE;
        else if (Result != NULL) *Result = result;
    }
    ExFreePoolWithTag(exchange, SAFEUPLOAD_POOL_TAG);
    return status;
}

NTSTATUS
SafeUploadStageSealVersionV19 (
    _In_ ULONG ProcessId,
    _In_ PUNICODE_STRING StageName,
    _In_ const SAFEUPLOAD_STAGE_IDENTITY_V19 *StageIdentity,
    _In_ UINT64 DestinationGeneration,
    _Out_ PBOOLEAN EmptyHeld
    )
{
    UINT32 result = 0;
    NTSTATUS status;
    PAGED_CODE();
    *EmptyHeld = FALSE;
    status = StageSendVersionRequestV19(SAFEUPLOAD_OPERATION_STAGE_SEAL, ProcessId,
        StageName, NULL, StageIdentity, DestinationGeneration, 0, &result);
    if (NT_SUCCESS(status)) *EmptyHeld = result == SAFEUPLOAD_STAGE_REPLY_EMPTY_HELD;
    return status;
}

NTSTATUS
SafeUploadStageDiscardVersionV19 (
    _In_ ULONG ProcessId,
    _In_ PUNICODE_STRING StageName,
    _In_ const GUID *ReservationId,
    _In_ const SAFEUPLOAD_STAGE_IDENTITY_V19 *StageIdentity,
    _In_ UINT64 DestinationGeneration,
    _In_ UINT32 Kind,
    _Out_ PUINT32 Result
    )
{
    PAGED_CODE();
    return StageSendVersionRequestV19(SAFEUPLOAD_OPERATION_STAGE_DISCARD, ProcessId,
        StageName, ReservationId, StageIdentity, DestinationGeneration, Kind, Result);
}

static BOOLEAN
StageV19IdentityNonzero (
    _In_ const SAFEUPLOAD_STAGE_IDENTITY_V19 *Identity
    )
{
    static const FILE_ID_128 empty = {{0}};
    return !RtlEqualMemory(&Identity->FileId, &empty, sizeof(empty));
}

NTSTATUS
SafeUploadStageCreateAfterDiscardV19 (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PUNICODE_STRING OriginalName,
    _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind,
    _In_ const GUID *ReservationId,
    _In_ const GUID *DeleteTransferId,
    _In_ const SAFEUPLOAD_STAGE_IDENTITY_V19 *DeleteStageIdentity,
    _In_ UINT64 DeleteGeneration,
    _In_ const SAFEUPLOAD_STAGE_IDENTITY_V19 *ParentDirectoryIdentity,
    _In_ UINT32 Disposition,
    _Out_writes_(SAFEUPLOAD_MAX_STAGE_NAME_CHARS) PWCH StageName,
    _Out_ PUSHORT StageNameLength,
    _Out_ PUINT64 DestinationGeneration,
    _Out_ PSAFEUPLOAD_STAGE_IDENTITY_V19 StageIdentity,
    _Out_ PSAFEUPLOAD_REQUEST RequestSnapshot,
    _Out_ PBOOLEAN RequestMayExist
    )
{
    PSAFEUPLOAD_EXCHANGE exchange;
    SAFEUPLOAD_STAGE_CREATE_AFTER_DISCARD_V19 extension;
    UINT32 verdict = SAFEUPLOAD_VERDICT_DENY;
    BOOLEAN answered = FALSE;
    NTSTATUS status;

    PAGED_CODE();
    *StageNameLength = 0;
    *DestinationGeneration = 0;
    RtlZeroMemory(StageIdentity, sizeof(*StageIdentity));
    RtlZeroMemory(RequestSnapshot, sizeof(*RequestSnapshot));
    *RequestMayExist = FALSE;
    if (OriginalName->Length == 0 || OriginalName->Length > SAFEUPLOAD_MAX_PATH_BYTES ||
        (OriginalName->Length & 1) || Disposition != FILE_OVERWRITE_IF ||
        !StageProtocolGuidNonzero(ReservationId) || !StageProtocolGuidNonzero(DeleteTransferId) ||
        DeleteGeneration == 0 ||
        !StageV19IdentityNonzero(DeleteStageIdentity) ||
        !StageV19IdentityNonzero(ParentDirectoryIdentity)) return STATUS_INVALID_PARAMETER;

    exchange = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*exchange), SAFEUPLOAD_POOL_TAG);
    if (exchange == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(exchange, sizeof(*exchange));
    exchange->Request.Version = SAFEUPLOAD_PROTOCOL_VERSION;
    exchange->Request.StructSize = sizeof(SAFEUPLOAD_REQUEST);
    exchange->Request.RequestId = (UINT64)InterlockedIncrement64(&SafeUploadData.NextRequestId);
    exchange->Request.Operation = SAFEUPLOAD_OPERATION_STAGE_CREATE_AFTER_DISCARD;
    exchange->Request.RequestorProcessId = FltGetRequestorProcessId(Data);
    exchange->Request.Reserved = SAFEUPLOAD_STAGE_EXTENSION_VERSION;
    if (VolumeKind == SafeUploadVolumeRemovable) exchange->Request.Flags |= SAFEUPLOAD_REQUEST_FLAG_STAGE_REMOVABLE;
    else if (VolumeKind == SafeUploadVolumeNetwork) exchange->Request.Flags |= SAFEUPLOAD_REQUEST_FLAG_STAGE_NETWORK;
    exchange->Request.PathLength = OriginalName->Length;
    RtlCopyMemory(exchange->Request.Path, OriginalName->Buffer, OriginalName->Length);

    RtlZeroMemory(&extension, sizeof(extension));
    extension.Version = SAFEUPLOAD_STAGE_EXTENSION_VERSION;
    extension.StructSize = sizeof(extension);
    extension.ReservationId = *ReservationId;
    extension.DeleteTransferId = *DeleteTransferId;
    extension.DeleteStageIdentity = *DeleteStageIdentity;
    extension.ParentDirectoryIdentity = *ParentDirectoryIdentity;
    extension.Disposition = Disposition;
    extension.DeleteGeneration = DeleteGeneration;
    exchange->Request.ImageNameLength = sizeof(extension);
    RtlCopyMemory(exchange->Request.ImageName, &extension, sizeof(extension));

    *RequestSnapshot = exchange->Request;
    status = StageSendV19Exchange(exchange, FALSE, &verdict, &answered);
    *RequestMayExist = exchange->MayHaveReachedService;
    status = SafeUploadStageExchangeResult(status, answered, verdict);
    if (!NT_SUCCESS(status)) goto Exit;

    status = StageProtocolReadCreateReply(exchange, ReservationId, StageName,
        StageNameLength, DestinationGeneration, StageIdentity);

Exit:
    ExFreePoolWithTag(exchange, SAFEUPLOAD_POOL_TAG);
    return status;
}

NTSTATUS SafeUploadStageReplayCreateAfterDiscardV19(_In_ const SAFEUPLOAD_REQUEST *Request,
    _Out_writes_(SAFEUPLOAD_MAX_STAGE_NAME_CHARS) PWCH StageName, _Out_ PUSHORT StageNameLength,
    _Out_ PUINT64 DestinationGeneration, _Out_ PSAFEUPLOAD_STAGE_IDENTITY_V19 StageIdentity)
{
    PSAFEUPLOAD_EXCHANGE exchange;
    SAFEUPLOAD_STAGE_CREATE_AFTER_DISCARD_V19 intent;
    UINT32 verdict = SAFEUPLOAD_VERDICT_DENY;
    BOOLEAN answered = FALSE;
    NTSTATUS status;
    PAGED_CODE();
    *StageNameLength = 0;
    *DestinationGeneration = 0;
    RtlZeroMemory(StageIdentity, sizeof(*StageIdentity));
    if (Request == NULL || Request->Version != SAFEUPLOAD_PROTOCOL_VERSION ||
        Request->StructSize != sizeof(SAFEUPLOAD_REQUEST) ||
        Request->Operation != SAFEUPLOAD_OPERATION_STAGE_CREATE_AFTER_DISCARD ||
        Request->Reserved != SAFEUPLOAD_STAGE_EXTENSION_VERSION ||
        Request->RequestId == 0 || Request->ImageNameLength != sizeof(intent) ||
        Request->PathLength == 0 || Request->PathLength > SAFEUPLOAD_MAX_PATH_BYTES ||
        (Request->PathLength & 1) != 0)
        return STATUS_INVALID_PARAMETER;
    RtlCopyMemory(&intent, Request->ImageName, sizeof(intent));
    if (intent.Version != SAFEUPLOAD_STAGE_EXTENSION_VERSION || intent.StructSize != sizeof(intent) ||
        intent.Disposition != FILE_OVERWRITE_IF || !StageProtocolGuidNonzero(&intent.ReservationId) ||
        !StageProtocolGuidNonzero(&intent.DeleteTransferId) || intent.DeleteGeneration == 0 ||
        !StageV19IdentityNonzero(&intent.DeleteStageIdentity) ||
        !StageV19IdentityNonzero(&intent.ParentDirectoryIdentity))
        return STATUS_INVALID_PARAMETER;
    exchange = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*exchange), SAFEUPLOAD_POOL_TAG);
    if (exchange == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(exchange, sizeof(*exchange));
    exchange->Request = *Request;
    status = StageSendV19Exchange(exchange, FALSE, &verdict, &answered);
    status = SafeUploadStageExchangeResult(status, answered, verdict);
    if (NT_SUCCESS(status)) status = StageProtocolReadCreateReply(exchange,
        &intent.ReservationId, StageName, StageNameLength,
        DestinationGeneration, StageIdentity);
    ExFreePoolWithTag(exchange, SAFEUPLOAD_POOL_TAG);
    return status;
}
#endif

NTSTATUS
SafeUploadStageSeal (
    _In_ ULONG ProcessId,
    _In_ PUNICODE_STRING StageName
    )
{
    PAGED_CODE();
    return StageSendVersionRequest( SAFEUPLOAD_OPERATION_STAGE_SEAL, ProcessId, StageName );
}

/* T5: the owner deleted this never-sealed version; the service journals it Discarded and removes the stage. Same idempotent
 * request/reply contract as the seal. */
NTSTATUS
SafeUploadStageDiscard (
    _In_ ULONG ProcessId,
    _In_ PUNICODE_STRING StageName
    )
{
    PAGED_CODE();
    return StageSendVersionRequest( SAFEUPLOAD_OPERATION_STAGE_DISCARD, ProcessId, StageName );
}

/* The result distinguishes allow, refusal, disconnect and no valid reply. Seal/rename callers retry a refusal on service connect;
 * the discard caller retries a refusal on its timer because a connected service may be waiting for a locked stage to close. */
NTSTATUS
SafeUploadStageExchangeResult (
    _In_ NTSTATUS SendStatus,
    _In_ BOOLEAN Answered,
    _In_ UINT32 Verdict
    )
{
    if (SendStatus == STATUS_SUCCESS && Answered) {
        return Verdict == SAFEUPLOAD_VERDICT_ALLOW ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
    }
    if (SendStatus == STATUS_PORT_DISCONNECTED || SendStatus == STATUS_FLT_DELETING_OBJECT) {
        return STATUS_PORT_DISCONNECTED;
    }
    return STATUS_IO_TIMEOUT;
}
