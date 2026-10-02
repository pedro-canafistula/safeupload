#include "Filter.h"
#include "Stage.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SafeUploadStageAllocate)
#pragma alloc_text(PAGE, SafeUploadStageSeal)
#endif

typedef struct _SAFEUPLOAD_PUBLICATION_PERMIT {
    BOOLEAN Active;
    BOOLEAN Created;
    BOOLEAN Consumed;
    SAFEUPLOAD_PUBLICATION_MESSAGE Message;
    ULONGLONG Expires;
} SAFEUPLOAD_PUBLICATION_PERMIT;
static SAFEUPLOAD_PUBLICATION_PERMIT SafeUploadPublicationPermits[64];
static EX_PUSH_LOCK SafeUploadPublicationLock;

VOID SafeUploadClearPublicationPermits(VOID)
{
    FltAcquirePushLockExclusive( &SafeUploadPublicationLock );
    RtlZeroMemory( SafeUploadPublicationPermits, sizeof( SafeUploadPublicationPermits ) );
    FltReleasePushLock( &SafeUploadPublicationLock );
}

NTSTATUS SafeUploadSetPublicationPermit(_In_ PSAFEUPLOAD_PUBLICATION_MESSAGE Message)
{
    ULONG index;
    LONG slot = -1;
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    ULONGLONG now = KeQueryInterruptTime();
    GUID emptyId = {0};
    if (SafeUploadData.ClientPort == NULL ||
        HandleToULong( PsGetCurrentProcessId() ) != SafeUploadData.InspectorProcessId)
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
    for (index = 0; index < RTL_NUMBER_OF( SafeUploadPublicationPermits ); ++index) {
        SAFEUPLOAD_PUBLICATION_PERMIT *permit = &SafeUploadPublicationPermits[index];
        if (permit->Active && RtlEqualMemory( &permit->Message.TransferId,
                                             &Message->TransferId, sizeof( GUID ) )) {
            if (Message->Revoke) {
                RtlZeroMemory( permit, sizeof( *permit ) );
                status = STATUS_SUCCESS;
            } else status = STATUS_OBJECT_NAME_COLLISION; // no resetting a consumed grant
            goto Exit;
        }
        if (!permit->Active || permit->Expires <= now) slot = (LONG) index;
    }
    if (Message->Revoke) status = STATUS_SUCCESS;
    else if (slot >= 0) {
        SAFEUPLOAD_PUBLICATION_PERMIT *permit = &SafeUploadPublicationPermits[slot];
        RtlZeroMemory( permit, sizeof( *permit ) );
        permit->Message = *Message;
        permit->Expires = now + 30ULL * 10000000ULL;
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
    FltAcquirePushLockExclusive( &SafeUploadPublicationLock );
    for (index = 0; index < RTL_NUMBER_OF( SafeUploadPublicationPermits ); ++index) {
        SAFEUPLOAD_PUBLICATION_PERMIT *permit = &SafeUploadPublicationPermits[index];
        UNICODE_STRING temporary;
        if (!permit->Active || permit->Consumed || permit->Expires <= now) continue;
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
    FltReleasePushLock( &SafeUploadPublicationLock );
    return allowed;
}

static BOOLEAN StageNameMatchesScope(_In_ PFLT_FILE_NAME_INFORMATION Name,
    _In_ SAFEUPLOAD_VOLUME_KIND Kind, _In_ BOOLEAN IncludeAncestors)
{
    UNICODE_STRING bootstrap = RTL_CONSTANT_STRING( L"\\SafeUpload\\Escopo Monitorado" );
    UNICODE_STRING relative;
    USHORT bootstrapChars = bootstrap.Length / sizeof(WCHAR), relativeChars;
    if (!NT_SUCCESS( FltParseFileNameInformation( Name ) )) return TRUE;
    relative.Buffer = (PWCH) ((PUCHAR) Name->Name.Buffer + Name->Volume.Length);
    relative.Length = Name->Name.Length - Name->Volume.Length;
    relative.MaximumLength = relative.Length;
    relativeChars = relative.Length / sizeof(WCHAR);
    if (RtlPrefixUnicodeString( &bootstrap, &relative, TRUE ) &&
        (relative.Length == bootstrap.Length || relative.Buffer[bootstrapChars] == L'\\')) return TRUE;
    if (IncludeAncestors && relative.Length != 0 &&
        RtlPrefixUnicodeString( &relative, &bootstrap, TRUE ) &&
        (relative.Length == bootstrap.Length || relative.Buffer[relativeChars - 1] == L'\\' ||
         bootstrap.Buffer[relativeChars] == L'\\')) return TRUE;
    return IncludeAncestors ? SafeUploadPolicyTouchesDestinationNamespace( Kind, &Name->Name ) :
        SafeUploadPolicyMatchesDestination( Kind, &Name->Name );
}

BOOLEAN SafeUploadStageProtectedName(_In_ PFLT_FILE_NAME_INFORMATION Name,
    _In_ SAFEUPLOAD_VOLUME_KIND Kind)
{
    return StageNameMatchesScope( Name, Kind, FALSE );
}

BOOLEAN SafeUploadStageTouchesProtectedNamespace(_In_ PFLT_FILE_NAME_INFORMATION Name,
    _In_ SAFEUPLOAD_VOLUME_KIND Kind)
{
    return StageNameMatchesScope( Name, Kind, TRUE );
}

BOOLEAN SafeUploadPublicationRename(_In_ PUNICODE_STRING Source,
    _In_ PUNICODE_STRING Destination)
{
    ULONG index;
    BOOLEAN allowed = FALSE;
    ULONGLONG now = KeQueryInterruptTime();
    FltAcquirePushLockExclusive( &SafeUploadPublicationLock );
    for (index = 0; index < RTL_NUMBER_OF( SafeUploadPublicationPermits ); ++index) {
        SAFEUPLOAD_PUBLICATION_PERMIT *permit = &SafeUploadPublicationPermits[index];
        UNICODE_STRING temporary, destination;
        if (!permit->Active || permit->Consumed || !permit->Created || permit->Expires <= now) continue;
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
    FltReleasePushLock( &SafeUploadPublicationLock );
    return allowed;
}

VOID SafeUploadStageInitializeProtocol(VOID)
{
    FltInitializePushLock(&SafeUploadPublicationLock);
}

NTSTATUS
SafeUploadStageAllocate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PUNICODE_STRING OriginalName,
    _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind,
    _In_opt_ PUNICODE_STRING PreviousStageName,
    _In_opt_ PUNICODE_STRING TombstoneStageName,
    _Out_writes_(SAFEUPLOAD_MAX_STAGE_NAME_CHARS) PWCH StageName,
    _Out_ PUSHORT StageNameLength
    )
{
    PSAFEUPLOAD_EXCHANGE exchange;
    UINT32 verdict;
    BOOLEAN answered;
    NTSTATUS status;
    USHORT i;
    PUNICODE_STRING referenceName = PreviousStageName != NULL ? PreviousStageName : TombstoneStageName;

    PAGED_CODE();

    *StageNameLength = 0;
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
    exchange->Request.RequestorProcessId = FltGetRequestorProcessId( Data );
    exchange->Request.Reserved =
        (Data->Iopb->Parameters.Create.Options >> 24) & 0xff;
    exchange->Request.PathLength = OriginalName->Length;
    RtlCopyMemory( exchange->Request.Path, OriginalName->Buffer,
                   OriginalName->Length );
    if (referenceName != NULL) {
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

    status = SafeUploadRequestVerdict( exchange, &verdict, &answered );
    if (status != STATUS_SUCCESS || !answered ||
        verdict != SAFEUPLOAD_VERDICT_ALLOW) {
        status = STATUS_ACCESS_DENIED;
        goto Exit;
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

NTSTATUS
SafeUploadStageSeal (
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
    exchange->Request.Operation = SAFEUPLOAD_OPERATION_STAGE_SEAL;
    exchange->Request.RequestorProcessId = ProcessId;
    exchange->Request.PathLength = StageName->Length;
    RtlCopyMemory( exchange->Request.Path, StageName->Buffer,
                   StageName->Length );
    status = SafeUploadRequestVerdict( exchange, &verdict, &answered );
    ExFreePoolWithTag( exchange, SAFEUPLOAD_POOL_TAG );
    if (!NT_SUCCESS( status ) || !answered ||
        verdict != SAFEUPLOAD_VERDICT_ALLOW) {
        return STATUS_ACCESS_DENIED;
    }
    return STATUS_SUCCESS;
}
