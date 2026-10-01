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

// Packed into the post-create completion context beside the volume kind.
#define SAFEUPLOAD_POSTCREATE_OVERRIDE 0x10
#define SAFEUPLOAD_POSTCREATE_STAGE 0x20
#define SAFEUPLOAD_POSTCREATE_STAGE_WRITER 0x40

// Experimental namespace redirect used only on the staged-kernel-prototype
// branch. It does not release files or provide a complete virtual namespace.
// Disabled in normal builds; never include it in a production package.
#ifndef SAFEUPLOAD_STAGING_PROTOTYPE
#define SAFEUPLOAD_STAGING_PROTOTYPE 0
#endif

#if SAFEUPLOAD_STAGING_PROTOTYPE
#include "StageSecurity.h"

typedef struct _SAFEUPLOAD_PROTOTYPE_STAGE_ECP {
    ULONG StageNameLength;
    ACCESS_MASK GrantedAccess;
    BOOLEAN StagePrepared;
    BOOLEAN Writer;
    ULONG CreateInformation;
    WCHAR StageName[SAFEUPLOAD_MAX_PATH_CHARS];
} SAFEUPLOAD_PROTOTYPE_STAGE_ECP, *PSAFEUPLOAD_PROTOTYPE_STAGE_ECP;

static const GUID SafeUploadPrototypeStageEcpGuid =
    { 0xb1e0d980, 0x4afd, 0x41cf,
      { 0x93, 0x65, 0x2c, 0x55, 0x9e, 0x09, 0x76, 0x16 } };

typedef struct _SAFEUPLOAD_PROTOTYPE_MAPPING {
    LIST_ENTRY Link;
    volatile LONG References;
    ULONG OwnerProcessId;
    BOOLEAN OwnerExited;
    LONG OpenWriters;
    BOOLEAN Sealing;
    BOOLEAN Sealed;
    BOOLEAN Rotating;
    PFILE_OBJECT MappedFileObject;
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    BOOLEAN AssignedSecurityDescriptor;
    BOOLEAN OriginalNameDynamic;
    USHORT OriginalVolumeLength;
    LIST_ENTRY OldNames;
    UNICODE_STRING OriginalName;
    UNICODE_STRING StageName;
    UNICODE_STRING PreviousStageName;
    PSAFEUPLOAD_STAGE_HANDLE_NAME HandleName;
    PSAFEUPLOAD_STAGE_HANDLE_NAME PreviousHandleName;
} SAFEUPLOAD_PROTOTYPE_MAPPING, *PSAFEUPLOAD_PROTOTYPE_MAPPING;

typedef struct _SAFEUPLOAD_PROTOTYPE_OLD_NAME {
    LIST_ENTRY Link;
    UNICODE_STRING Name;
} SAFEUPLOAD_PROTOTYPE_OLD_NAME, *PSAFEUPLOAD_PROTOTYPE_OLD_NAME;

static LIST_ENTRY SafeUploadPrototypeMappings;
static EX_PUSH_LOCK SafeUploadPrototypeMappingLock;
static ULONG SafeUploadPrototypeMappingCount;
static BOOLEAN SafeUploadPrototypeNotifyRegistered;
static KEVENT SafeUploadPrototypeWorkerStop;
static HANDLE SafeUploadPrototypeWorkerHandle;

static PSAFEUPLOAD_PROTOTYPE_STAGE_ECP SafeUploadPrototypeHasRedirectMarker(
    _Inout_ PFLT_CALLBACK_DATA Data, _In_opt_ PUNICODE_STRING StageName);

// A version owns its virtual name independently of the mutable namespace map.
// Handles to earlier versions retain it across rotation and owner-process exit.
VOID SafeUploadReleaseStageHandleName(_In_opt_ PSAFEUPLOAD_STAGE_HANDLE_NAME Name)
{
    if (Name != NULL && InterlockedDecrement( &Name->References ) == 0)
        ExFreePoolWithTag( Name, SAFEUPLOAD_POOL_TAG );
}

static PSAFEUPLOAD_STAGE_HANDLE_NAME SafeUploadNewStageHandleName(
    _In_ PUNICODE_STRING Original, _In_ USHORT VolumeLength)
{
    PSAFEUPLOAD_STAGE_HANDLE_NAME name;
    if (Original->Length <= VolumeLength ||
        Original->Length - VolumeLength > sizeof( name->Name )) return NULL;
    name = ExAllocatePool2( POOL_FLAG_NON_PAGED, sizeof( *name ), SAFEUPLOAD_POOL_TAG );
    if (name != NULL) {
        name->References = 1;
        name->Length = Original->Length - VolumeLength;
        RtlCopyMemory( name->Name, (PUCHAR) Original->Buffer + VolumeLength, name->Length );
    }
    return name;
}

static NTSTATUS SafeUploadAttachStageHandleName(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects)
{
    PSAFEUPLOAD_STREAMHANDLE_CONTEXT context = NULL;
    PSAFEUPLOAD_STAGE_HANDLE_NAME name = NULL;
    PSAFEUPLOAD_PROTOTYPE_STAGE_ECP marker;
    PLIST_ENTRY link;
    NTSTATUS status;
    // The marker is present only on the successful redirected CREATE.
    marker = SafeUploadPrototypeHasRedirectMarker( Data, NULL );
    if (marker == NULL) return STATUS_ACCESS_DENIED;
    FltAcquirePushLockShared( &SafeUploadPrototypeMappingLock );
    for (link = SafeUploadPrototypeMappings.Flink; link != &SafeUploadPrototypeMappings;
         link = link->Flink) {
        PSAFEUPLOAD_PROTOTYPE_MAPPING mapping = CONTAINING_RECORD(
            link, SAFEUPLOAD_PROTOTYPE_MAPPING, Link );
        if (mapping->StageName.Length == marker->StageNameLength &&
            RtlCompareMemory( mapping->StageName.Buffer, marker->StageName,
                marker->StageNameLength ) == marker->StageNameLength) {
            name = mapping->HandleName;
            if (name != NULL) InterlockedIncrement( &name->References );
            break;
        }
    }
    FltReleasePushLock( &SafeUploadPrototypeMappingLock );
    if (name == NULL) return STATUS_OBJECT_NAME_NOT_FOUND;
    status = FltGetStreamHandleContext( Objects->Instance, Objects->FileObject,
        (PFLT_CONTEXT *) &context );
    if (!NT_SUCCESS( status )) {
        status = FltAllocateContext( Objects->Filter, FLT_STREAMHANDLE_CONTEXT,
            sizeof( *context ), NonPagedPool, (PFLT_CONTEXT *) &context );
        if (NT_SUCCESS( status )) {
            RtlZeroMemory( context, sizeof( *context ) );
            FltInitializePushLock( &context->DirectoryLock );
            status = FltSetStreamHandleContext( Objects->Instance, Objects->FileObject,
                FLT_SET_CONTEXT_KEEP_IF_EXISTS, context, NULL );
        }
    }
    if (NT_SUCCESS( status )) {
        context->StageName = name;
        name = NULL;
    }
    if (context != NULL) FltReleaseContext( context );
    SafeUploadReleaseStageHandleName( name );
    return status;
}

static BOOLEAN SafeUploadDirectoryChild(_In_ PUNICODE_STRING Directory,
    _In_ PUNICODE_STRING FullName, _Out_ PUNICODE_STRING Child)
{
    USHORT offset = Directory->Length;
    UNICODE_STRING prefix = *FullName;
    USHORT index;
    if (FullName->Length <= offset || FullName->Buffer[offset / sizeof( WCHAR )] != L'\\') return FALSE;
    prefix.Length = offset;
    if (!RtlEqualUnicodeString( Directory, &prefix, TRUE )) return FALSE;
    offset += sizeof( WCHAR );
    Child->Buffer = (PWCH) ((PUCHAR) FullName->Buffer + offset);
    Child->Length = FullName->Length - offset;
    Child->MaximumLength = Child->Length;
    for (index = 0; index < Child->Length / sizeof( WCHAR ); ++index)
        if (Child->Buffer[index] == L'\\') return FALSE;
    return Child->Length != 0;
}

BOOLEAN SafeUploadProcessHasMappings(_In_ ULONG Owner)
{
    PLIST_ENTRY link;
    BOOLEAN found = FALSE;
    FltAcquirePushLockShared( &SafeUploadPrototypeMappingLock );
    for (link = SafeUploadPrototypeMappings.Flink; link != &SafeUploadPrototypeMappings; link = link->Flink) {
        PSAFEUPLOAD_PROTOTYPE_MAPPING mapping = CONTAINING_RECORD( link, SAFEUPLOAD_PROTOTYPE_MAPPING, Link );
        if (!mapping->OwnerExited && mapping->OwnerProcessId == Owner) { found = TRUE; break; }
    }
    FltReleasePushLock( &SafeUploadPrototypeMappingLock );
    return found;
}

BOOLEAN SafeUploadHasDirectoryOverlay(_In_ ULONG Owner, _In_ PUNICODE_STRING Directory)
{
    PLIST_ENTRY link, old;
    BOOLEAN found = FALSE;
    UNICODE_STRING child;
    FltAcquirePushLockShared( &SafeUploadPrototypeMappingLock );
    for (link = SafeUploadPrototypeMappings.Flink; link != &SafeUploadPrototypeMappings; link = link->Flink) {
        PSAFEUPLOAD_PROTOTYPE_MAPPING mapping = CONTAINING_RECORD( link, SAFEUPLOAD_PROTOTYPE_MAPPING, Link );
        if (mapping->OwnerExited || mapping->OwnerProcessId != Owner) continue;
        if (SafeUploadDirectoryChild( Directory, &mapping->OriginalName, &child )) { found = TRUE; break; }
        for (old = mapping->OldNames.Flink; old != &mapping->OldNames; old = old->Flink) {
            if (SafeUploadDirectoryChild( Directory, &CONTAINING_RECORD( old,
                SAFEUPLOAD_PROTOTYPE_OLD_NAME, Link )->Name, &child )) { found = TRUE; break; }
        }
        if (found) break;
    }
    FltReleasePushLock( &SafeUploadPrototypeMappingLock );
    return found;
}

static NTSTATUS SafeUploadAddDirectoryOverlay(_Inout_ PLIST_ENTRY Overlays,
    _In_ PUNICODE_STRING Name, _In_opt_ PUNICODE_STRING Stage)
{
    PSAFEUPLOAD_DIRECTORY_OVERLAY overlay = ExAllocatePool2( POOL_FLAG_PAGED,
        sizeof( *overlay ) + Name->Length + (Stage != NULL ? Stage->Length : 0), SAFEUPLOAD_POOL_TAG );
    if (overlay == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    overlay->Deleted = Stage == NULL;
    overlay->Name.Buffer = (PWCH) (overlay + 1);
    overlay->Name.Length = overlay->Name.MaximumLength = Name->Length;
    RtlCopyMemory( overlay->Name.Buffer, Name->Buffer, Name->Length );
    if (Stage != NULL) {
        overlay->StageName.Buffer = (PWCH) ((PUCHAR) overlay->Name.Buffer + Name->Length);
        overlay->StageName.Length = overlay->StageName.MaximumLength = Stage->Length;
        RtlCopyMemory( overlay->StageName.Buffer, Stage->Buffer, Stage->Length );
    }
    InsertTailList( Overlays, &overlay->Link );
    return STATUS_SUCCESS;
}

NTSTATUS SafeUploadCollectDirectoryOverlay(_In_ ULONG Owner, _In_ PUNICODE_STRING Directory,
    _Inout_ PLIST_ENTRY Overlays)
{
    PLIST_ENTRY link, old;
    UNICODE_STRING child;
    NTSTATUS status = STATUS_SUCCESS;
    FltAcquirePushLockShared( &SafeUploadPrototypeMappingLock );
    for (link = SafeUploadPrototypeMappings.Flink; link != &SafeUploadPrototypeMappings; link = link->Flink) {
        PSAFEUPLOAD_PROTOTYPE_MAPPING mapping = CONTAINING_RECORD( link, SAFEUPLOAD_PROTOTYPE_MAPPING, Link );
        if (mapping->OwnerExited || mapping->OwnerProcessId != Owner) continue;
        for (old = mapping->OldNames.Flink; old != &mapping->OldNames; old = old->Flink) {
            if (SafeUploadDirectoryChild( Directory, &CONTAINING_RECORD( old,
                SAFEUPLOAD_PROTOTYPE_OLD_NAME, Link )->Name, &child )) {
                status = SafeUploadAddDirectoryOverlay( Overlays, &child, NULL );
                if (!NT_SUCCESS( status )) goto Exit;
            }
        }
        if (SafeUploadDirectoryChild( Directory, &mapping->OriginalName, &child )) {
            status = SafeUploadAddDirectoryOverlay( Overlays, &child, &mapping->StageName );
            if (!NT_SUCCESS( status )) goto Exit;
        }
    }
Exit:
    FltReleasePushLock( &SafeUploadPrototypeMappingLock );
    return status;
}

// A connected service has no blanket write bypass. Each publication grants
// exactly one create and one final rename, expires in 30 seconds, and is
// revoked on port disconnect. The issuer is the authenticated LocalSystem
// port owner; applications cannot submit these controls.
typedef struct _SAFEUPLOAD_PUBLICATION_PERMIT {
    BOOLEAN Active;
    BOOLEAN Created;
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
    if (SafeUploadData.ClientPort == NULL ||
        HandleToULong( PsGetCurrentProcessId() ) != SafeUploadData.InspectorProcessId)
        return STATUS_ACCESS_DENIED;
    if (Message->Control.Version != SAFEUPLOAD_PROTOCOL_VERSION ||
        Message->Control.StructSize != sizeof( *Message ) || Message->Reserved != 0 ||
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

static BOOLEAN SafeUploadPublicationCreate(_In_ PUNICODE_STRING Name,
    _In_ ULONG Disposition, _In_ BOOLEAN Writer)
{
    ULONG index;
    BOOLEAN allowed = FALSE;
    ULONGLONG now = KeQueryInterruptTime();
    FltAcquirePushLockExclusive( &SafeUploadPublicationLock );
    for (index = 0; index < RTL_NUMBER_OF( SafeUploadPublicationPermits ); ++index) {
        SAFEUPLOAD_PUBLICATION_PERMIT *permit = &SafeUploadPublicationPermits[index];
        UNICODE_STRING temporary;
        if (!permit->Active || permit->Expires <= now) continue;
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

static BOOLEAN SafeUploadPrototypeProtectedName(_In_ PFLT_FILE_NAME_INFORMATION Name,
    _In_ SAFEUPLOAD_VOLUME_KIND Kind)
{
    UNICODE_STRING bootstrap = RTL_CONSTANT_STRING( L"\\SafeUpload\\Escopo Monitorado\\" );
    UNICODE_STRING relative;
    if (!NT_SUCCESS( FltParseFileNameInformation( Name ) )) return TRUE;
    relative.Buffer = (PWCH) ((PUCHAR) Name->Name.Buffer + Name->Volume.Length);
    relative.Length = Name->Name.Length - Name->Volume.Length;
    relative.MaximumLength = relative.Length;
    return SafeUploadPolicyMatchesDestination( Kind, &Name->Name ) ||
        RtlPrefixUnicodeString( &bootstrap, &relative, TRUE );
}

static BOOLEAN SafeUploadPublicationRename(_In_ PUNICODE_STRING Source,
    _In_ PUNICODE_STRING Destination)
{
    ULONG index;
    BOOLEAN allowed = FALSE;
    ULONGLONG now = KeQueryInterruptTime();
    FltAcquirePushLockExclusive( &SafeUploadPublicationLock );
    for (index = 0; index < RTL_NUMBER_OF( SafeUploadPublicationPermits ); ++index) {
        SAFEUPLOAD_PUBLICATION_PERMIT *permit = &SafeUploadPublicationPermits[index];
        UNICODE_STRING temporary, destination;
        if (!permit->Active || !permit->Created || permit->Expires <= now) continue;
        temporary.Buffer = permit->Message.TemporaryPath;
        temporary.Length = (USHORT) permit->Message.TemporaryPathLength;
        temporary.MaximumLength = temporary.Length;
        destination.Buffer = permit->Message.DestinationPath;
        destination.Length = (USHORT) permit->Message.DestinationPathLength;
        destination.MaximumLength = destination.Length;
        if (RtlEqualUnicodeString( Source, &temporary, TRUE ) &&
            RtlEqualUnicodeString( Destination, &destination, TRUE )) {
            permit->Active = FALSE;
            allowed = TRUE;
            break;
        }
    }
    FltReleasePushLock( &SafeUploadPublicationLock );
    return allowed;
}

static
VOID
SafeUploadPrototypeFreeMapping (
    _In_ PSAFEUPLOAD_PROTOTYPE_MAPPING Mapping
    );

static
VOID
SafeUploadPrototypeProcessNotify (
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create
    );

static
VOID
SafeUploadPrototypeFreeMappings (
    VOID
    );

static
VOID
SafeUploadPrototypeMappedSealWorker (
    _In_opt_ PVOID Context
    );

static
VOID
SafeUploadPrototypeStopWorker (
    VOID
    );

static
FLT_PREOP_CALLBACK_STATUS
SafeUploadPrototypeRename (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PUNICODE_STRING SourceName,
    _In_ PFILE_RENAME_INFORMATION Rename,
    _In_ BOOLEAN Extended
    )
{
    PFLT_FILE_NAME_INFORMATION destination = NULL;
    PSAFEUPLOAD_PROTOTYPE_MAPPING mapping = NULL;
    PSAFEUPLOAD_PROTOTYPE_OLD_NAME oldName = NULL;
    PFLT_VOLUME volume = NULL;
    PFLT_INSTANCE instance = NULL;
    PSAFEUPLOAD_EXCHANGE exchange = NULL;
    PWCH newName = NULL;
    PLIST_ENTRY link;
    USHORT basename;
    BOOLEAN replace;
    BOOLEAN answered = FALSE;
    UINT32 verdict;
    NTSTATUS status;
    ULONG phase = 1;

    PAGED_CODE();
    replace = Extended ? (BOOLEAN) FlagOn( *(PULONG) Rename, FILE_RENAME_REPLACE_IF_EXISTS )
                       : Rename->ReplaceIfExists;
    if (!FltObjects->FileObject->DeleteAccess) {
        status = STATUS_ACCESS_DENIED;
        goto Exit;
    }
    phase = 2;
    status = FltGetDestinationFileNameInformation( FltObjects->Instance,
        FltObjects->FileObject, Rename->RootDirectory, Rename->FileName,
        Rename->FileNameLength, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &destination );
    if (!NT_SUCCESS( status )) goto Exit;
    phase = 3;
    status = FltParseFileNameInformation( destination );
    if (!NT_SUCCESS( status )) goto Exit;
    if (destination->Name.Length > SAFEUPLOAD_MAX_PATH_BYTES) {
        status = STATUS_NAME_TOO_LONG;
        goto Exit;
    }
    newName = ExAllocatePool2( POOL_FLAG_PAGED, destination->Name.Length + sizeof( WCHAR ),
                               SAFEUPLOAD_POOL_TAG );
    if (newName == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    RtlCopyMemory( newName, destination->Name.Buffer, destination->Name.Length );
    newName[destination->Name.Length / sizeof( WCHAR )] = L'\0';
    phase = 4;
    FltAcquirePushLockExclusive( &SafeUploadPrototypeMappingLock );
    for (link = SafeUploadPrototypeMappings.Flink; link != &SafeUploadPrototypeMappings;
         link = link->Flink) {
        PSAFEUPLOAD_PROTOTYPE_MAPPING candidate = CONTAINING_RECORD(
            link, SAFEUPLOAD_PROTOTYPE_MAPPING, Link );
        if (!candidate->OwnerExited &&
            candidate->OwnerProcessId == FltGetRequestorProcessId( Data ) &&
            RtlEqualUnicodeString( &candidate->StageName, SourceName, TRUE )) {
            mapping = candidate;
            break;
        }
    }
    if (mapping != NULL) {
        for (link = SafeUploadPrototypeMappings.Flink; link != &SafeUploadPrototypeMappings;
             link = link->Flink) {
            PSAFEUPLOAD_PROTOTYPE_MAPPING candidate = CONTAINING_RECORD(
                link, SAFEUPLOAD_PROTOTYPE_MAPPING, Link );
            if (candidate != mapping && !candidate->OwnerExited &&
                candidate->OwnerProcessId == mapping->OwnerProcessId &&
                RtlEqualUnicodeString( &candidate->OriginalName, &destination->Name, TRUE )) {
                mapping = NULL;
                break;
            }
        }
    }
    if (mapping == NULL || mapping->Sealing || mapping->Rotating) {
        mapping = NULL;
        status = STATUS_SHARING_VIOLATION;
    } else if (mapping->OriginalVolumeLength != destination->Volume.Length ||
        RtlCompareMemory( mapping->OriginalName.Buffer, destination->Volume.Buffer,
                          destination->Volume.Length ) != destination->Volume.Length) {
        mapping = NULL;
        status = STATUS_NOT_SAME_DEVICE;
    } else {
        oldName = ExAllocatePool2( POOL_FLAG_PAGED,
            sizeof( *oldName ) + mapping->OriginalName.Length, SAFEUPLOAD_POOL_TAG );
        if (oldName == NULL) {
            mapping = NULL;
            status = STATUS_INSUFFICIENT_RESOURCES;
        } else {
            oldName->Name.Buffer = (PWCH) (oldName + 1);
            oldName->Name.Length = mapping->OriginalName.Length;
            oldName->Name.MaximumLength = oldName->Name.Length;
            RtlCopyMemory( oldName->Name.Buffer, mapping->OriginalName.Buffer,
                           oldName->Name.Length );
            mapping->Rotating = TRUE;
            InterlockedIncrement( &mapping->References );
            status = STATUS_SUCCESS;
        }
    }
    FltReleasePushLock( &SafeUploadPrototypeMappingLock );
    if (!NT_SUCCESS( status )) goto Exit;

    phase = 5;
    status = FltGetVolumeFromName( SafeUploadData.Filter, &destination->Volume, &volume );
    if (!NT_SUCCESS( status )) goto Exit;
    phase = 6;
    status = FltGetVolumeInstanceFromName( SafeUploadData.Filter, volume, NULL, &instance );
    if (!NT_SUCCESS( status )) goto Exit;
    phase = 7;
    status = SafeUploadStageCheckRenameAccess( instance, &destination->Name, replace );
    if (!NT_SUCCESS( status )) goto Exit;

    exchange = ExAllocatePool2( POOL_FLAG_NON_PAGED, sizeof( *exchange ), SAFEUPLOAD_POOL_TAG );
    if (exchange == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    exchange->Request.Version = SAFEUPLOAD_PROTOCOL_VERSION;
    exchange->Request.StructSize = sizeof( SAFEUPLOAD_REQUEST );
    exchange->Request.RequestId = (UINT64) InterlockedIncrement64( &SafeUploadData.NextRequestId );
    exchange->Request.Operation = SAFEUPLOAD_OPERATION_STAGE_RENAME;
    exchange->Request.RequestorProcessId = mapping->OwnerProcessId;
    exchange->Request.Reserved = mapping->Sealed ? 1 : 0;
    exchange->Request.PathLength = destination->Name.Length;
    RtlCopyMemory( exchange->Request.Path, destination->Name.Buffer, destination->Name.Length );
    basename = mapping->StageName.Length / sizeof( WCHAR );
    while (basename > 0 && mapping->StageName.Buffer[basename - 1] != L'\\') --basename;
    exchange->Request.ImageNameLength = 32 * sizeof( WCHAR );
    RtlCopyMemory( exchange->Request.ImageName, mapping->StageName.Buffer + basename,
                   exchange->Request.ImageNameLength );
    phase = 8;
    status = SafeUploadRequestVerdict( exchange, &verdict, &answered );
    if (status != STATUS_SUCCESS || !answered || verdict != SAFEUPLOAD_VERDICT_ALLOW) {
        status = STATUS_SHARING_VIOLATION;
        goto Exit;
    }
    FltAcquirePushLockExclusive( &SafeUploadPrototypeMappingLock );
    if (mapping->OriginalNameDynamic) {
        ExFreePoolWithTag( mapping->OriginalName.Buffer, SAFEUPLOAD_POOL_TAG );
    }
    mapping->OriginalName.Buffer = newName;
    mapping->OriginalName.Length = destination->Name.Length;
    mapping->OriginalName.MaximumLength = destination->Name.Length + sizeof( WCHAR );
    mapping->OriginalNameDynamic = TRUE;
    if (mapping->HandleName != NULL) {
        mapping->HandleName->Length = destination->Name.Length - mapping->OriginalVolumeLength;
        RtlCopyMemory( mapping->HandleName->Name,
            (PUCHAR) destination->Name.Buffer + mapping->OriginalVolumeLength,
            mapping->HandleName->Length );
    }
    newName = NULL;
    InsertTailList( &mapping->OldNames, &oldName->Link );
    oldName = NULL;
    mapping->Rotating = FALSE;
    FltReleasePushLock( &SafeUploadPrototypeMappingLock );
    status = STATUS_SUCCESS;
Exit:
    if (!NT_SUCCESS( status ) && SafeUploadData.ClientPort != NULL) {
        PSAFEUPLOAD_EXCHANGE diagnostic = ExAllocatePool2( POOL_FLAG_NON_PAGED,
            sizeof( *diagnostic ), SAFEUPLOAD_POOL_TAG );
        if (diagnostic != NULL) {
            diagnostic->Request.Version = SAFEUPLOAD_PROTOCOL_VERSION;
            diagnostic->Request.StructSize = sizeof( SAFEUPLOAD_REQUEST );
            diagnostic->Request.RequestId = (UINT64) InterlockedIncrement64( &SafeUploadData.NextRequestId );
            diagnostic->Request.Operation = SAFEUPLOAD_OPERATION_STAGE_DIAGNOSTIC;
            diagnostic->Request.Flags = phase;
            diagnostic->Request.Reserved = (UINT32) status;
            diagnostic->Request.PathLength = SourceName->Length;
            RtlCopyMemory( diagnostic->Request.Path, SourceName->Buffer, SourceName->Length );
            (VOID) SafeUploadRequestVerdict( diagnostic, &verdict, &answered );
            ExFreePoolWithTag( diagnostic, SAFEUPLOAD_POOL_TAG );
        }
    }
    if (mapping != NULL) {
        FltAcquirePushLockExclusive( &SafeUploadPrototypeMappingLock );
        mapping->Rotating = FALSE;
        FltReleasePushLock( &SafeUploadPrototypeMappingLock );
        SafeUploadPrototypeFreeMapping( mapping );
    }
    if (exchange != NULL) ExFreePoolWithTag( exchange, SAFEUPLOAD_POOL_TAG );
    if (oldName != NULL) ExFreePoolWithTag( oldName, SAFEUPLOAD_POOL_TAG );
    if (newName != NULL) ExFreePoolWithTag( newName, SAFEUPLOAD_POOL_TAG );
    if (instance != NULL) FltObjectDereference( instance );
    if (volume != NULL) FltObjectDereference( volume );
    if (destination != NULL) FltReleaseFileNameInformation( destination );
    Data->IoStatus.Status = status;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

static
FLT_PREOP_CALLBACK_STATUS
SafeUploadPrototypeRedirectCreate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PFLT_INSTANCE Instance,
    _Out_ PBOOLEAN Writer
    );

static
NTSTATUS
SafeUploadPrototypeAllocateStageName (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PUNICODE_STRING OriginalName,
    _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind,
    _In_opt_ PUNICODE_STRING PreviousStageName,
    _Out_writes_(SAFEUPLOAD_MAX_STAGE_NAME_CHARS) PWCH StageName,
    _Out_ PUSHORT StageNameLength
    );

static
NTSTATUS
SafeUploadPrototypeMarkRedirect (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_reads_bytes_(StageNameLength) PWCH StageName,
    _In_ USHORT StageNameLength,
    _In_ ACCESS_MASK GrantedAccess,
    _In_ BOOLEAN StagePrepared,
    _In_ BOOLEAN Writer,
    _In_ ULONG CreateInformation
    );

static
PSAFEUPLOAD_PROTOTYPE_STAGE_ECP
SafeUploadPrototypeHasRedirectMarker (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_opt_ PUNICODE_STRING StageName
    );

static
NTSTATUS
SafeUploadPrototypeSealStage (
    _In_ ULONG ProcessId,
    _In_ PUNICODE_STRING StageName
    );

static
VOID
SafeUploadPrototypeFinishStageOpen (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ BOOLEAN Writer,
    _In_ BOOLEAN Succeeded
    );

static
BOOLEAN
SafeUploadPrototypeCleanupStageWriter (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

static
FLT_PREOP_CALLBACK_STATUS
SafeUploadPrototypeQueryOpen (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    PLIST_ENTRY link;
    BOOLEAN virtualView = FALSE;
    ULONG processId = FltGetRequestorProcessId( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    *CompletionContext = NULL;
    FltAcquirePushLockShared( &SafeUploadPrototypeMappingLock );
    for (link = SafeUploadPrototypeMappings.Flink; link != &SafeUploadPrototypeMappings;
         link = link->Flink) {
        PSAFEUPLOAD_PROTOTYPE_MAPPING mapping = CONTAINING_RECORD(
            link, SAFEUPLOAD_PROTOTYPE_MAPPING, Link );
        if (!mapping->OwnerExited && mapping->OwnerProcessId == processId) {
            virtualView = TRUE;
            break;
        }
    }
    FltReleasePushLock( &SafeUploadPrototypeMappingLock );
    if (virtualView) {
        if (Data->Iopb->MajorFunction == IRP_MJ_QUERY_OPEN) {
            return FLT_PREOP_DISALLOW_FSFILTER_IO;
        }
        if (FLT_IS_FASTIO_OPERATION( Data )) {
            return FLT_PREOP_DISALLOW_FASTIO;
        }
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static
FLT_PREOP_CALLBACK_STATUS
SafeUploadPrototypeQueryName (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    FILE_INFORMATION_CLASS informationClass =
        Data->Iopb->Parameters.QueryFileInformation.FileInformationClass;
    PFLT_FILE_NAME_INFORMATION opened = NULL;
    PFILE_NAME_INFORMATION output;
    PWCH virtualName = NULL;
    USHORT nameLength = 0;
    ULONG length;
    ULONG copied;
    ULONG nameOffset = 0;
    PLIST_ENTRY link;
    NTSTATUS status;

    *CompletionContext = NULL;
    if ((informationClass != FileNameInformation &&
         informationClass != FileNormalizedNameInformation &&
         informationClass != FileAllInformation &&
         informationClass != FileAlternateNameInformation) ||
        (SafeUploadData.ClientPort != NULL &&
         FltGetRequestorProcessId( Data ) == SafeUploadData.InspectorProcessId)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (FLT_IS_FASTIO_OPERATION( Data )) return FLT_PREOP_DISALLOW_FASTIO;
    {
        PSAFEUPLOAD_STREAMHANDLE_CONTEXT context = NULL;
        status = FltGetStreamHandleContext( FltObjects->Instance, FltObjects->FileObject,
            (PFLT_CONTEXT *) &context );
        if (NT_SUCCESS( status )) {
            FltAcquirePushLockShared( &SafeUploadPrototypeMappingLock );
            if (context->StageName != NULL) {
                nameLength = context->StageName->Length;
                virtualName = ExAllocatePool2( POOL_FLAG_PAGED, nameLength, SAFEUPLOAD_POOL_TAG );
                if (virtualName != NULL)
                    RtlCopyMemory( virtualName, context->StageName->Name, nameLength );
            }
            FltReleasePushLock( &SafeUploadPrototypeMappingLock );
            FltReleaseContext( context );
        }
    }
    if (nameLength != 0) goto EmitName;
    status = FltGetFileNameInformationUnsafe( FltObjects->FileObject,
        FltObjects->Instance, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY,
        &opened );
    if (!NT_SUCCESS( status )) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    FltAcquirePushLockShared( &SafeUploadPrototypeMappingLock );
    for (link = SafeUploadPrototypeMappings.Flink; link != &SafeUploadPrototypeMappings;
         link = link->Flink) {
        PSAFEUPLOAD_PROTOTYPE_MAPPING mapping = CONTAINING_RECORD(
            link, SAFEUPLOAD_PROTOTYPE_MAPPING, Link );
        if (RtlEqualUnicodeString( &mapping->StageName, &opened->Name, TRUE )) {
            nameLength = mapping->OriginalName.Length - mapping->OriginalVolumeLength;
            virtualName = ExAllocatePool2( POOL_FLAG_PAGED, nameLength, SAFEUPLOAD_POOL_TAG );
            if (virtualName != NULL) {
                RtlCopyMemory( virtualName,
                    (PUCHAR) mapping->OriginalName.Buffer + mapping->OriginalVolumeLength,
                    nameLength );
            }
            break;
        }
    }
    FltReleasePushLock( &SafeUploadPrototypeMappingLock );
    FltReleaseFileNameInformation( opened );
EmitName:
    if (nameLength == 0) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (virtualName == NULL) {
        Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    if (informationClass == FileAlternateNameInformation) {
        // The private backing file's DOS alias is not an alias of the virtual
        // destination. A new virtual file has no short name until publication.
        ExFreePoolWithTag( virtualName, SAFEUPLOAD_POOL_TAG );
        Data->IoStatus.Status = STATUS_OBJECT_NAME_NOT_FOUND;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    length = Data->Iopb->Parameters.QueryFileInformation.Length;
    output = Data->Iopb->Parameters.QueryFileInformation.InfoBuffer;
    if (informationClass == FileAllInformation) {
        PFILE_ALL_INFORMATION all;
        ULONG bytes = FIELD_OFFSET( FILE_ALL_INFORMATION, NameInformation.FileName ) +
            SAFEUPLOAD_MAX_PATH_BYTES;
        nameOffset = FIELD_OFFSET( FILE_ALL_INFORMATION, NameInformation );
        all = ExAllocatePool2( POOL_FLAG_NON_PAGED, bytes, SAFEUPLOAD_POOL_TAG );
        if (all == NULL) status = STATUS_INSUFFICIENT_RESOURCES;
        else {
            status = FltQueryInformationFile( FltObjects->Instance, FltObjects->FileObject,
                all, bytes, FileAllInformation, NULL );
            if (NT_SUCCESS( status ) || status == STATUS_BUFFER_OVERFLOW) {
                __try {
                    RtlCopyMemory( output, all, min( length, nameOffset ) );
                    output = (PFILE_NAME_INFORMATION) ((PUCHAR) output + nameOffset);
                    status = STATUS_SUCCESS;
                } __except( EXCEPTION_EXECUTE_HANDLER ) { status = GetExceptionCode(); }
            }
            ExFreePoolWithTag( all, SAFEUPLOAD_POOL_TAG );
        }
        if (!NT_SUCCESS( status )) {
            ExFreePoolWithTag( virtualName, SAFEUPLOAD_POOL_TAG );
            Data->IoStatus.Status = status;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
    }
    if (length < nameOffset + (ULONG) FIELD_OFFSET( FILE_NAME_INFORMATION, FileName )) {
        Data->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
        Data->IoStatus.Information = 0;
    } else {
        copied = min( nameLength, length - nameOffset - FIELD_OFFSET( FILE_NAME_INFORMATION, FileName ) );
        copied &= ~(sizeof( WCHAR ) - 1);
        __try {
            output->FileNameLength = nameLength;
            RtlCopyMemory( output->FileName, virtualName, copied );
            Data->IoStatus.Status = copied == nameLength ? STATUS_SUCCESS : STATUS_BUFFER_OVERFLOW;
            Data->IoStatus.Information = nameOffset + FIELD_OFFSET( FILE_NAME_INFORMATION, FileName ) + copied;
        } __except( EXCEPTION_EXECUTE_HANDLER ) {
            Data->IoStatus.Status = GetExceptionCode();
            Data->IoStatus.Information = 0;
        }
    }
    ExFreePoolWithTag( virtualName, SAFEUPLOAD_POOL_TAG );
    return FLT_PREOP_COMPLETE;
}
#endif

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
BOOLEAN
SafeUploadEvaluate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind,
    _Out_ PUINT32 ScopeFlags,
    _Out_ PUINT32 Verdict
    );

static
BOOLEAN
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
    #pragma alloc_text(PAGE, SafeUploadPreWrite)
    #pragma alloc_text(PAGE, SafeUploadPreSetInformation)
#if SAFEUPLOAD_STAGING_PROTOTYPE
    #pragma alloc_text(PAGE, SafeUploadPrototypeRedirectCreate)
    #pragma alloc_text(PAGE, SafeUploadPrototypeAllocateStageName)
    #pragma alloc_text(PAGE, SafeUploadPrototypeMarkRedirect)
    #pragma alloc_text(PAGE, SafeUploadPrototypeHasRedirectMarker)
    #pragma alloc_text(PAGE, SafeUploadPrototypeSealStage)
    #pragma alloc_text(PAGE, SafeUploadPrototypeFinishStageOpen)
    #pragma alloc_text(PAGE, SafeUploadPrototypeCleanupStageWriter)
    #pragma alloc_text(PAGE, SafeUploadPrototypeFreeMappings)
    #pragma alloc_text(PAGE, SafeUploadPrototypeProcessNotify)
#endif
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

#if SAFEUPLOAD_STAGING_PROTOTYPE
    // Metadata shortcuts must fall back to the same virtual create path.
    { IRP_MJ_NETWORK_QUERY_OPEN, 0, SafeUploadPrototypeQueryOpen, NULL },
    { IRP_MJ_QUERY_OPEN, 0, SafeUploadPrototypeQueryOpen, NULL },
    { IRP_MJ_QUERY_INFORMATION, 0, SafeUploadPrototypeQueryName, NULL },
    { IRP_MJ_DIRECTORY_CONTROL, 0, SafeUploadPrototypeDirectoryQuery, NULL },
#endif

    //
    //  Cleanup invalidates a cached verdict when a writable handle closes.
    //  The write hook below serves a different purpose: catching writes
    //  through handles opened before their process became tainted.
    //

    { IRP_MJ_CLEANUP,
      0,
      SafeUploadPreCleanup,
      NULL },

    // A handle may have been opened before its process read sensitive
    // content. Check subsequent user writes as well as the create itself.
    // Paging writes often run in System's context, where the initiating PID
    // is unavailable; the existing create gate remains their protection.

    { IRP_MJ_WRITE,
      FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
      SafeUploadPreWrite,
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

#if SAFEUPLOAD_STAGING_PROTOTYPE
    InitializeListHead( &SafeUploadPrototypeMappings );
    FltInitializePushLock( &SafeUploadPrototypeMappingLock );
    FltInitializePushLock( &SafeUploadPublicationLock );
    SafeUploadPrototypeMappingCount = 0;
    SafeUploadPrototypeNotifyRegistered = FALSE;
    SafeUploadPrototypeWorkerHandle = NULL;
    KeInitializeEvent( &SafeUploadPrototypeWorkerStop, NotificationEvent, FALSE );
#endif

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

#if SAFEUPLOAD_STAGING_PROTOTYPE
    // A recycled PID must never inherit an earlier process's staged view.
    // A failed notification registration makes this test build fail to load.
    status = PsSetCreateProcessNotifyRoutine(
        SafeUploadPrototypeProcessNotify, FALSE );
    if (!NT_SUCCESS( status )) {
        goto FreeState;
    }
    SafeUploadPrototypeNotifyRegistered = TRUE;
#endif

    SafeUploadData.DriverObject = DriverObject;

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &SafeUploadData.Filter );

    if (!NT_SUCCESS( status )) {

        SafeUploadTrace( "FltRegisterFilter failed, status 0x%08X\n", status );
        goto FreeState;
    }

    //
    //  From here on the filter manager may call our callbacks, so every
    //  failure path below has to unregister before returning.
    //

    status = SafeUploadCreateCommunicationPort();

    if (!NT_SUCCESS( status )) {
        goto UnregisterFilter;
    }

#if SAFEUPLOAD_STAGING_PROTOTYPE
    {
        OBJECT_ATTRIBUTES attributes;
        InitializeObjectAttributes( &attributes, NULL, OBJ_KERNEL_HANDLE,
                                    NULL, NULL );
        status = PsCreateSystemThread( &SafeUploadPrototypeWorkerHandle,
                                       SYNCHRONIZE, &attributes, NULL, NULL,
                                       SafeUploadPrototypeMappedSealWorker,
                                       NULL );
        if (!NT_SUCCESS( status )) {
            goto ClosePort;
        }
    }
#endif

    status = FltStartFiltering( SafeUploadData.Filter );

    if (!NT_SUCCESS( status )) {

        SafeUploadTrace( "FltStartFiltering failed, status 0x%08X\n", status );

        goto ClosePort;
    }

    SafeUploadTrace( "loaded and filtering\n" );

    return STATUS_SUCCESS;

ClosePort:
    // A client can connect after the port is created even if filtering
    // fails to start. Close it and drain any in-flight port callback first.
    SafeUploadCloseCommunicationPort();
    ExWaitForRundownProtectionRelease( &SafeUploadData.ChannelRundown );
#if SAFEUPLOAD_STAGING_PROTOTYPE
    SafeUploadPrototypeStopWorker();
#endif

UnregisterFilter:
    FltUnregisterFilter( SafeUploadData.Filter );
    SafeUploadData.Filter = NULL;

FreeState:
#if SAFEUPLOAD_STAGING_PROTOTYPE
    SafeUploadPrototypeFreeMappings();
#endif
    // These were initialized before FltRegisterFilter. In particular, the
    // taint table may have registered a process notification callback; it
    // must be removed even when registration itself failed.
    SafeUploadFreeOverrides();
    SafeUploadFreeTaint();
    SafeUploadFreePolicy();

    return status;
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

#if SAFEUPLOAD_STAGING_PROTOTYPE
    SafeUploadPrototypeStopWorker();
#endif

    //
    //  3. Unregister. FltUnregisterFilter waits for every in-flight
    //     callback to return, so once it completes no code of ours can run.
    //

    FltUnregisterFilter( SafeUploadData.Filter );
    SafeUploadData.Filter = NULL;

#if SAFEUPLOAD_STAGING_PROTOTYPE
    SafeUploadPrototypeFreeMappings();
#endif

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
BOOLEAN
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

    TRUE when Verdict is a checked answer safe to cache - the operation was
    out of scope or user mode actually replied.
    FALSE when Verdict is ALLOW only because user mode could not be reached
    (allocation failure, name resolution failure, or a fail-open inside
    SafeUploadRequestVerdict): the caller must treat this as unchecked, not
    cache it, and count it as AllowedWithoutInspection.

--*/
{
    PSAFEUPLOAD_EXCHANGE exchange;
    UNICODE_STRING normalizedPath;
    UNICODE_STRING imageName;
    NTSTATUS status;
    BOOLEAN answered;

    PAGED_CODE();

    *ScopeFlags = 0;
    *Verdict = SAFEUPLOAD_VERDICT_ALLOW;

    exchange = (PSAFEUPLOAD_EXCHANGE) ExAllocatePool2( POOL_FLAG_NON_PAGED,
                                                       sizeof( SAFEUPLOAD_EXCHANGE ),
                                                       SAFEUPLOAD_POOL_TAG );

    if (exchange == NULL) {

        //
        //  Could not even build the request. Same fail-open reasoning as a
        //  timeout: RN-013 says allow, and this was never a checked verdict.
        //

        SafeUploadCount( AllowedWithoutInspection );
        return FALSE;
    }

    exchange->Request.Version = SAFEUPLOAD_PROTOCOL_VERSION;
    exchange->Request.StructSize = sizeof( SAFEUPLOAD_REQUEST );
    exchange->Request.RequestId =
        (UINT64) InterlockedIncrement64( &SafeUploadData.NextRequestId );
    exchange->Request.Operation = SAFEUPLOAD_OPERATION_CREATE;
    exchange->Request.RequestorProcessId = FltGetRequestorProcessId( Data );

    status = SafeUploadCopyRequestPath( Data, &exchange->Request );

    if (!NT_SUCCESS( status )) {

        //
        //  Could not even resolve the name being operated on. Same
        //  fail-open reasoning as a timeout: never a checked verdict.
        //

        SafeUploadCount( AllowedWithoutInspection );
        ExFreePoolWithTag( exchange, SAFEUPLOAD_POOL_TAG );
        return FALSE;
    }

    SafeUploadCount( ScopeEvaluations );

    normalizedPath.Buffer = exchange->Request.Path;
    normalizedPath.Length = (USHORT) exchange->Request.PathLength;
    normalizedPath.MaximumLength = normalizedPath.Length;

    if (SafeUploadPolicyMatchesDestination( VolumeKind, &normalizedPath )) {

        SetFlag( exchange->Request.Flags, SAFEUPLOAD_REQUEST_FLAG_SCOPE_DESTINATION );
    }

    // Only a read open may classify a source and mark its process. A
    // write-only open of a sensitive file must not taint the writer.
    if (Data->Iopb->Parameters.Create.SecurityContext != NULL &&
        FlagOn( Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess,
                FILE_READ_DATA ) &&
        SafeUploadPolicyMatchesSource( &normalizedPath )) {

        SetFlag( exchange->Request.Flags, SAFEUPLOAD_REQUEST_FLAG_SCOPE_SOURCE );
    }

    *ScopeFlags = exchange->Request.Flags &
                  (SAFEUPLOAD_REQUEST_FLAG_SCOPE_DESTINATION |
                   SAFEUPLOAD_REQUEST_FLAG_SCOPE_SOURCE);

    if (*ScopeFlags == 0) {

        //
        //  Out of scope is a real, checked answer - just not one that
        //  needed a round trip to reach.
        //

        ExFreePoolWithTag( exchange, SAFEUPLOAD_POOL_TAG );
        return TRUE;
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

            //
            //  An image exclusion belongs to this requestor, not the file.
            //  Another process still needs its own inspection.
            //

            *ScopeFlags = 0;
            ExFreePoolWithTag( exchange, SAFEUPLOAD_POOL_TAG );
            return FALSE;
        }
    }

    SafeUploadCount( UserModeRoundTrips );

    (VOID) SafeUploadRequestVerdict( exchange, Verdict, &answered );

    if (!answered) {

        SafeUploadCount( AllowedWithoutInspection );
    }

    ExFreePoolWithTag( exchange, SAFEUPLOAD_POOL_TAG );

    return answered;
}


static
BOOLEAN
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
        be read. A failed query is distinct from a confirmed empty file.

Return Value:

    TRUE only when the file size and time were read successfully.

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
        return TRUE;
    }

    return FALSE;
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


#if SAFEUPLOAD_STAGING_PROTOTYPE
static
VOID
SafeUploadPrototypeFreeMapping (
    _In_ PSAFEUPLOAD_PROTOTYPE_MAPPING Mapping
    )
{
    if (InterlockedDecrement( &Mapping->References ) != 0) {
        return;
    }
    if (Mapping->MappedFileObject != NULL) {
        ObDereferenceObject( Mapping->MappedFileObject );
    }
    SafeUploadReleaseStageHandleName( Mapping->HandleName );
    SafeUploadReleaseStageHandleName( Mapping->PreviousHandleName );
    while (!IsListEmpty( &Mapping->OldNames )) {
        PLIST_ENTRY link = RemoveHeadList( &Mapping->OldNames );
        ExFreePoolWithTag( CONTAINING_RECORD( link,
            SAFEUPLOAD_PROTOTYPE_OLD_NAME, Link ), SAFEUPLOAD_POOL_TAG );
    }
    if (Mapping->OriginalNameDynamic) {
        ExFreePoolWithTag( Mapping->OriginalName.Buffer, SAFEUPLOAD_POOL_TAG );
    }
    SafeUploadStageFreeSecurity( Mapping->SecurityDescriptor,
                                 Mapping->AssignedSecurityDescriptor );
    ExFreePoolWithTag( Mapping, SAFEUPLOAD_POOL_TAG );
}

static
VOID
SafeUploadPrototypeProcessNotify (
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create
    )
{
    PLIST_ENTRY link;
    PLIST_ENTRY next;

    UNREFERENCED_PARAMETER( ParentId );
    PAGED_CODE();

    if (Create) {
        return;
    }

    FltAcquirePushLockExclusive( &SafeUploadPrototypeMappingLock );
    for (link = SafeUploadPrototypeMappings.Flink;
         link != &SafeUploadPrototypeMappings;
         link = next) {
        PSAFEUPLOAD_PROTOTYPE_MAPPING mapping =
            CONTAINING_RECORD( link, SAFEUPLOAD_PROTOTYPE_MAPPING, Link );
        next = link->Flink;
        if (mapping->OwnerProcessId == HandleToULong( ProcessId )) {
            // A duplicated handle or mapped section can outlive its writer
            // process. Retain its version tracking, but revoke the PID's view
            // immediately so PID reuse cannot inherit the namespace.
            mapping->OwnerExited = TRUE;
            if (mapping->OpenWriters == 0 && mapping->Sealed &&
                !mapping->Rotating && !mapping->Sealing) {
                RemoveEntryList( link );
                SafeUploadPrototypeMappingCount -= 1;
                SafeUploadPrototypeFreeMapping( mapping );
            }
        }
    }
    FltReleasePushLock( &SafeUploadPrototypeMappingLock );
}

static
VOID
SafeUploadPrototypeFreeMappings (
    VOID
    )
{
    PLIST_ENTRY link;

    PAGED_CODE();

    if (SafeUploadPrototypeNotifyRegistered) {
        (VOID) PsSetCreateProcessNotifyRoutine(
            SafeUploadPrototypeProcessNotify, TRUE );
        SafeUploadPrototypeNotifyRegistered = FALSE;
    }

    FltAcquirePushLockExclusive( &SafeUploadPrototypeMappingLock );
    while (!IsListEmpty( &SafeUploadPrototypeMappings )) {
        link = RemoveHeadList( &SafeUploadPrototypeMappings );
        {
            PSAFEUPLOAD_PROTOTYPE_MAPPING mapping =
                CONTAINING_RECORD( link, SAFEUPLOAD_PROTOTYPE_MAPPING, Link );
            SafeUploadPrototypeFreeMapping( mapping );
        }
    }
    SafeUploadPrototypeMappingCount = 0;
    FltReleasePushLock( &SafeUploadPrototypeMappingLock );
}

static
VOID
SafeUploadPrototypeStopWorker (
    VOID
    )
{
    PAGED_CODE();
    if (SafeUploadPrototypeWorkerHandle != NULL) {
        KeSetEvent( &SafeUploadPrototypeWorkerStop, IO_NO_INCREMENT, FALSE );
        (VOID) ZwWaitForSingleObject( SafeUploadPrototypeWorkerHandle,
                                      FALSE, NULL );
        ZwClose( SafeUploadPrototypeWorkerHandle );
        SafeUploadPrototypeWorkerHandle = NULL;
    }
}

static
VOID
SafeUploadPrototypeMappedSealWorker (
    _In_opt_ PVOID Context
    )
{
    LARGE_INTEGER interval;
    UNICODE_STRING stageName;
    WCHAR stageBuffer[SAFEUPLOAD_MAX_PATH_CHARS];
    ULONG processId;
    PLIST_ENTRY link;
    NTSTATUS status;

    UNREFERENCED_PARAMETER( Context );
    interval.QuadPart = -250 * 10000LL;
    for (;;) {
        if (KeWaitForSingleObject( &SafeUploadPrototypeWorkerStop,
                                   Executive, KernelMode, FALSE,
                                   &interval ) == STATUS_SUCCESS) {
            break;
        }

        stageName.Buffer = stageBuffer;
        stageName.Length = 0;
        stageName.MaximumLength = sizeof( stageBuffer );
        processId = 0;
        FltAcquirePushLockExclusive( &SafeUploadPrototypeMappingLock );
        for (link = SafeUploadPrototypeMappings.Flink;
             link != &SafeUploadPrototypeMappings;
             link = link->Flink) {
            PSAFEUPLOAD_PROTOTYPE_MAPPING mapping =
                CONTAINING_RECORD( link, SAFEUPLOAD_PROTOTYPE_MAPPING, Link );
            if (mapping->MappedFileObject == NULL || mapping->OpenWriters != 0 ||
                mapping->Sealing || mapping->Sealed || mapping->Rotating ||
                mapping->StageName.Length >= sizeof( stageBuffer )) {
                continue;
            }
            if (mapping->MappedFileObject->SectionObjectPointer != NULL &&
                MmDoesFileHaveUserWritableReferences(
                    mapping->MappedFileObject->SectionObjectPointer ) != 0) {
                continue;
            }
            mapping->Sealing = TRUE;
            stageName.Length = mapping->StageName.Length;
            RtlCopyMemory( stageBuffer, mapping->StageName.Buffer,
                           stageName.Length + sizeof( WCHAR ) );
            processId = mapping->OwnerProcessId;
            break;
        }
        FltReleasePushLock( &SafeUploadPrototypeMappingLock );

        if (stageName.Length == 0) {
            continue;
        }
        status = SafeUploadPrototypeSealStage( processId, &stageName );
        FltAcquirePushLockExclusive( &SafeUploadPrototypeMappingLock );
        for (link = SafeUploadPrototypeMappings.Flink;
             link != &SafeUploadPrototypeMappings;
             link = link->Flink) {
            PSAFEUPLOAD_PROTOTYPE_MAPPING mapping =
                CONTAINING_RECORD( link, SAFEUPLOAD_PROTOTYPE_MAPPING, Link );
            if (mapping->OwnerProcessId == processId &&
                RtlEqualUnicodeString( &mapping->StageName,
                                       &stageName, TRUE )) {
                mapping->Sealing = FALSE;
                if (NT_SUCCESS( status )) {
                    mapping->Sealed = TRUE;
                    ObDereferenceObject( mapping->MappedFileObject );
                    mapping->MappedFileObject = NULL;
                }
                break;
            }
        }
        FltReleasePushLock( &SafeUploadPrototypeMappingLock );
    }
    PsTerminateSystemThread( STATUS_SUCCESS );
}

static
NTSTATUS
SafeUploadPrototypeAllocateStageName (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PUNICODE_STRING OriginalName,
    _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind,
    _In_opt_ PUNICODE_STRING PreviousStageName,
    _Out_writes_(SAFEUPLOAD_MAX_STAGE_NAME_CHARS) PWCH StageName,
    _Out_ PUSHORT StageNameLength
    )
{
    PSAFEUPLOAD_EXCHANGE exchange;
    UINT32 verdict;
    BOOLEAN answered;
    NTSTATUS status;
    USHORT i;

    PAGED_CODE();

    *StageNameLength = 0;
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
    if (PreviousStageName != NULL) {
        USHORT basename = 0;
        for (i = 0; i < PreviousStageName->Length / sizeof( WCHAR ); ++i) {
            if (PreviousStageName->Buffer[i] == L'\\') {
                basename = i + 1;
            }
        }
        if (PreviousStageName->Length / sizeof( WCHAR ) - basename < 32) {
            status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }
        exchange->Request.Flags |=
            SAFEUPLOAD_REQUEST_FLAG_STAGE_FOLLOWUP;
        exchange->Request.ImageNameLength = 32 * sizeof( WCHAR );
        RtlCopyMemory( exchange->Request.ImageName,
                       PreviousStageName->Buffer + basename,
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

static
NTSTATUS
SafeUploadPrototypeMarkRedirect (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_reads_bytes_(StageNameLength) PWCH StageName,
    _In_ USHORT StageNameLength,
    _In_ ACCESS_MASK GrantedAccess,
    _In_ BOOLEAN StagePrepared,
    _In_ BOOLEAN Writer,
    _In_ ULONG CreateInformation
    )
{
    PECP_LIST ecpList = NULL;
    PSAFEUPLOAD_PROTOTYPE_STAGE_ECP ecp = NULL;
    BOOLEAN ownList = FALSE;
    NTSTATUS status;

    PAGED_CODE();

    if (StageNameLength == 0 ||
        StageNameLength >= SAFEUPLOAD_MAX_PATH_CHARS * sizeof( WCHAR )) {
        return STATUS_NAME_TOO_LONG;
    }

    status = FltGetEcpListFromCallbackData( SafeUploadData.Filter,
                                            Data, &ecpList );
    if (!NT_SUCCESS( status )) {
        return status;
    }
    if (ecpList == NULL) {
        status = FltAllocateExtraCreateParameterList(
            SafeUploadData.Filter, 0, &ecpList );
        if (!NT_SUCCESS( status )) {
            return status;
        }
        ownList = TRUE;
    }

    status = FltAllocateExtraCreateParameter(
        SafeUploadData.Filter, &SafeUploadPrototypeStageEcpGuid,
        sizeof( *ecp ), 0, NULL, SAFEUPLOAD_POOL_TAG, (PVOID *) &ecp );
    if (!NT_SUCCESS( status )) {
        goto Cleanup;
    }
    RtlZeroMemory( ecp, sizeof( *ecp ) );
    ecp->StageNameLength = StageNameLength;
    ecp->GrantedAccess = GrantedAccess;
    ecp->StagePrepared = StagePrepared;
    ecp->Writer = Writer;
    ecp->CreateInformation = CreateInformation;
    RtlCopyMemory( ecp->StageName, StageName, StageNameLength );

    status = FltInsertExtraCreateParameter( SafeUploadData.Filter,
                                            ecpList, ecp );
    if (!NT_SUCCESS( status )) {
        FltFreeExtraCreateParameter( SafeUploadData.Filter, ecp );
        goto Cleanup;
    }

    if (ownList) {
        status = FltSetEcpListIntoCallbackData( SafeUploadData.Filter,
                                                Data, ecpList );
        if (!NT_SUCCESS( status )) {
            goto Cleanup;
        }
    }

    // The I/O manager owns the attached ECP until the entire create,
    // including its reparse retry, completes.
    return STATUS_SUCCESS;

Cleanup:
    if (ownList) {
        FltFreeExtraCreateParameterList( SafeUploadData.Filter, ecpList );
    }
    return status;
}

static
PSAFEUPLOAD_PROTOTYPE_STAGE_ECP
SafeUploadPrototypeHasRedirectMarker (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_opt_ PUNICODE_STRING StageName
    )
{
    PECP_LIST ecpList = NULL;
    PSAFEUPLOAD_PROTOTYPE_STAGE_ECP ecp = NULL;
    ULONG ecpSize = 0;
    UNICODE_STRING markedName;
    NTSTATUS status;

    PAGED_CODE();

    status = FltGetEcpListFromCallbackData( SafeUploadData.Filter,
                                            Data, &ecpList );
    if (!NT_SUCCESS( status ) || ecpList == NULL) {
        return NULL;
    }
    status = FltFindExtraCreateParameter(
        SafeUploadData.Filter, ecpList, &SafeUploadPrototypeStageEcpGuid,
        (PVOID *) &ecp, &ecpSize );
    if (!NT_SUCCESS( status ) || ecp == NULL ||
        ecpSize != sizeof( *ecp ) ||
        FltIsEcpFromUserMode( SafeUploadData.Filter, ecp ) ||
        ecp->StageNameLength == 0 || ecp->StageNameLength >= sizeof( ecp->StageName ) ||
        (StageName != NULL && ecp->StageNameLength != StageName->Length)) {
        return NULL;
    }

    markedName.Buffer = ecp->StageName;
    markedName.Length = (USHORT) ecp->StageNameLength;
    markedName.MaximumLength = markedName.Length;
    return StageName == NULL || RtlEqualUnicodeString( &markedName, StageName, TRUE ) ? ecp : NULL;
}

static
NTSTATUS
SafeUploadPrototypeSealStage (
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

static
VOID
SafeUploadPrototypeFinishStageOpen (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ BOOLEAN Writer,
    _In_ BOOLEAN Succeeded
    )
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PLIST_ENTRY link;
    PSAFEUPLOAD_PROTOTYPE_STAGE_ECP marker;

    PAGED_CODE();
    if (!Writer) {
        return;
    }
    if (!NT_SUCCESS( FltGetFileNameInformation(
            Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT,
            &nameInfo ) )) {
        // A lost count prevents sealing; it never releases unknown bytes.
        return;
    }
    marker = SafeUploadPrototypeHasRedirectMarker( Data, &nameInfo->Name );
    if (Succeeded && marker != NULL && marker->StagePrepared) {
        Data->IoStatus.Information = marker->CreateInformation;
    }
    FltAcquirePushLockExclusive( &SafeUploadPrototypeMappingLock );
    for (link = SafeUploadPrototypeMappings.Flink;
         link != &SafeUploadPrototypeMappings;
         link = link->Flink) {
        PSAFEUPLOAD_PROTOTYPE_MAPPING mapping =
            CONTAINING_RECORD( link, SAFEUPLOAD_PROTOTYPE_MAPPING, Link );
        if (RtlEqualUnicodeString( &mapping->StageName,
                                   &nameInfo->Name, TRUE )) {
            if (!Succeeded && mapping->OpenWriters > 0) {
                mapping->OpenWriters -= 1;
            }
            if (mapping->Rotating &&
                mapping->PreviousStageName.Length != 0) {
                if (Succeeded) {
                    mapping->Sealed = FALSE;
                    SafeUploadReleaseStageHandleName( mapping->PreviousHandleName );
                    mapping->PreviousHandleName = NULL;
                } else {
                    RtlCopyMemory( mapping->StageName.Buffer,
                                   mapping->PreviousStageName.Buffer,
                                   mapping->PreviousStageName.Length +
                                       sizeof( WCHAR ) );
                    SafeUploadReleaseStageHandleName( mapping->HandleName );
                    mapping->HandleName = mapping->PreviousHandleName;
                    mapping->PreviousHandleName = NULL;
                }
                mapping->PreviousStageName.Length = 0;
                mapping->Rotating = FALSE;
            }
            break;
        }
    }
    FltReleasePushLock( &SafeUploadPrototypeMappingLock );
    FltReleaseFileNameInformation( nameInfo );
}

static
BOOLEAN
SafeUploadPrototypeCleanupStageWriter (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PLIST_ENTRY link;
    ULONG processId;
    BOOLEAN found = FALSE;
    BOOLEAN shouldSeal = FALSE;
    NTSTATUS status;

    PAGED_CODE();
    if (!NT_SUCCESS( FltGetFileNameInformation(
            Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT,
            &nameInfo ) )) {
        return FALSE;
    }
    processId = 0;
    FltAcquirePushLockExclusive( &SafeUploadPrototypeMappingLock );
    for (link = SafeUploadPrototypeMappings.Flink;
         link != &SafeUploadPrototypeMappings;
         link = link->Flink) {
        PSAFEUPLOAD_PROTOTYPE_MAPPING mapping =
            CONTAINING_RECORD( link, SAFEUPLOAD_PROTOTYPE_MAPPING, Link );
        if (RtlEqualUnicodeString( &mapping->StageName,
                                   &nameInfo->Name, TRUE )) {
            // CLEANUP belongs to the file object, not the current process.
            // The last duplicate/inherited handle may close elsewhere.
            processId = mapping->OwnerProcessId;
            found = TRUE;
            if (mapping->OpenWriters > 0) {
                mapping->OpenWriters -= 1;
            }
            if (mapping->OpenWriters == 0 &&
                !mapping->Sealing && !mapping->Sealed) {
                // Keep enough identity to retry a final-close seal after a
                // service outage, even when this file has no mapped views.
                if (mapping->MappedFileObject == NULL) {
                    ObReferenceObject( FltObjects->FileObject );
                    mapping->MappedFileObject = FltObjects->FileObject;
                }
                if (mapping->Rotating ||
                    (FltObjects->FileObject->SectionObjectPointer != NULL &&
                    MmDoesFileHaveUserWritableReferences(
                        FltObjects->FileObject->SectionObjectPointer ) != 0)) {
                    // The worker waits until the last writable view ends.
                } else {
                    mapping->Sealing = TRUE;
                    shouldSeal = TRUE;
                }
            }
            break;
        }
    }
    FltReleasePushLock( &SafeUploadPrototypeMappingLock );

    if (shouldSeal) {
        status = SafeUploadPrototypeSealStage( processId, &nameInfo->Name );
        FltAcquirePushLockExclusive( &SafeUploadPrototypeMappingLock );
        for (link = SafeUploadPrototypeMappings.Flink;
             link != &SafeUploadPrototypeMappings;
             link = link->Flink) {
            PSAFEUPLOAD_PROTOTYPE_MAPPING mapping =
                CONTAINING_RECORD( link, SAFEUPLOAD_PROTOTYPE_MAPPING, Link );
            if (mapping->OwnerProcessId == processId &&
                RtlEqualUnicodeString( &mapping->StageName,
                                       &nameInfo->Name, TRUE )) {
                mapping->Sealing = FALSE;
                mapping->Sealed = NT_SUCCESS( status );
                if (mapping->Sealed && mapping->MappedFileObject != NULL) {
                    ObDereferenceObject( mapping->MappedFileObject );
                    mapping->MappedFileObject = NULL;
                }
                break;
            }
        }
        FltReleasePushLock( &SafeUploadPrototypeMappingLock );
    }
    FltReleaseFileNameInformation( nameInfo );
    return found;
}

static
FLT_PREOP_CALLBACK_STATUS
SafeUploadPrototypeRedirectCreate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PFLT_INSTANCE Instance,
    _Out_ PBOOLEAN Writer
    )
{
    UNICODE_STRING sourcePrefix = RTL_CONSTANT_STRING( L"\\SafeUpload\\Escopo Monitorado\\" );
    UNICODE_STRING stagePrefix = RTL_CONSTANT_STRING( L"\\ProgramData\\SafeUpload\\staging\\" );
    UNICODE_STRING stageRoot = RTL_CONSTANT_STRING( L"\\ProgramData\\SafeUpload\\staging" );
    UNICODE_STRING stageDrive = RTL_CONSTANT_STRING( L"\\??\\C:" );
    UNICODE_STRING stageVolumeName = { 0 };
    PFLT_VOLUME stageVolume = NULL;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PIO_SECURITY_CONTEXT securityContext;
    PSAFEUPLOAD_INSTANCE_CONTEXT instanceContext = NULL;
    SAFEUPLOAD_VOLUME_KIND volumeKind = SafeUploadVolumeUnknown;
    UNICODE_STRING relativeName;
    WCHAR stageBaseName[SAFEUPLOAD_MAX_STAGE_NAME_CHARS];
    WCHAR previousStageBuffer[SAFEUPLOAD_MAX_PATH_CHARS];
    UNICODE_STRING previousStageName = { 0 };
    PSAFEUPLOAD_PROTOTYPE_MAPPING mapping = NULL;
    PSAFEUPLOAD_PROTOTYPE_STAGE_ECP marker = NULL;
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;
    BOOLEAN assignedSecurityDescriptor = FALSE;
    BOOLEAN destinationExists = TRUE;
    ACCESS_MASK grantedAccess = 0;
    ULONG disposition;
    ULONG createInformation;
    PLIST_ENTRY link;
    PWCH newName = NULL;
    ULONG processId;
    BOOLEAN isWriter;
    BOOLEAN newMapping = FALSE;
    BOOLEAN followup = FALSE;
    BOOLEAN rotationPrepared = FALSE;
    USHORT suffixLength;
    USHORT stageBaseNameLength;
    USHORT extensionOffset;
    USHORT newNameLength;
    USHORT i;
    NTSTATUS status;

    PAGED_CODE();

    // Rename asks the I/O manager to open the destination's parent using
    // the full target name and SL_OPEN_TARGET_DIRECTORY. FILE_ADD_FILE has
    // the same access bit as FILE_WRITE_DATA, but this is a directory open;
    // redirecting it to a backing *file* breaks rename before SET_INFORMATION.
    if (FlagOn( Data->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY )) {
        *Writer = FALSE;
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    securityContext = Data->Iopb->Parameters.Create.SecurityContext;
    disposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xff;
    processId = FltGetRequestorProcessId( Data );
    isWriter = securityContext != NULL &&
        (BOOLEAN) FlagOn( securityContext->DesiredAccess,
                          FILE_WRITE_DATA | FILE_APPEND_DATA | MAXIMUM_ALLOWED );
    isWriter = isWriter || disposition == FILE_SUPERSEDE ||
        disposition == FILE_CREATE || disposition == FILE_OVERWRITE ||
        disposition == FILE_OVERWRITE_IF;
    *Writer = isWriter;

    if (isWriter && FlagOn( Data->Iopb->Parameters.Create.Options,
                            FILE_OPEN_BY_FILE_ID ) &&
        !(SafeUploadData.ClientPort != NULL &&
          processId == SafeUploadData.InspectorProcessId)) {
        // Resolving an ID only after create is too late for truncation.
        // Until IDs have a virtual identity, fail before the filesystem.
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    status = FltGetFileNameInformation( Data,
                                        FLT_FILE_NAME_NORMALIZED |
                                            FLT_FILE_NAME_QUERY_DEFAULT,
                                        &nameInfo );
    if (!NT_SUCCESS( status )) {
        if (isWriter && !(SafeUploadData.ClientPort != NULL &&
                         processId == SafeUploadData.InspectorProcessId)) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltParseFileNameInformation( nameInfo );
    if (!NT_SUCCESS( status ) ||
        nameInfo->Name.Length <= nameInfo->Volume.Length) {
        FltReleaseFileNameInformation( nameInfo );
        if (isWriter && !(SafeUploadData.ClientPort != NULL &&
                         processId == SafeUploadData.InspectorProcessId)) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    relativeName.Buffer = (PWCH) ((PUCHAR) nameInfo->Name.Buffer +
                                   nameInfo->Volume.Length);
    relativeName.Length = nameInfo->Name.Length - nameInfo->Volume.Length;
    relativeName.MaximumLength = relativeName.Length;

    // A user must not bypass the original destination name by opening the
    // stage path directly. Only a create carrying our kernel-issued ECP from
    // the reparse, or the connected agent, may open this private namespace.
    if (RtlEqualUnicodeString( &stageRoot, &relativeName, TRUE )) {
        // The agent must be able to initialize its stage root before it
        // connects to the port. File opens underneath it still need ECPs.
        FltReleaseFileNameInformation( nameInfo );
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (RtlPrefixUnicodeString( &stagePrefix, &relativeName, TRUE )) {
        if (SafeUploadData.ClientPort != NULL &&
            processId == SafeUploadData.InspectorProcessId) {
            FltReleaseFileNameInformation( nameInfo );
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        marker = SafeUploadPrototypeHasRedirectMarker( Data, &nameInfo->Name );
        if (marker == NULL || securityContext == NULL ||
            securityContext->AccessState == NULL || marker->GrantedAccess == 0) {
            status = STATUS_ACCESS_DENIED;
            goto Deny;
        }
        isWriter = marker->Writer;
        *Writer = isWriter;

        FltAcquirePushLockExclusive( &SafeUploadPrototypeMappingLock );
        for (link = SafeUploadPrototypeMappings.Flink;
             link != &SafeUploadPrototypeMappings;
             link = link->Flink) {
            PSAFEUPLOAD_PROTOTYPE_MAPPING candidate =
                CONTAINING_RECORD( link, SAFEUPLOAD_PROTOTYPE_MAPPING, Link );
            if (!candidate->OwnerExited && candidate->OwnerProcessId == processId &&
                (RtlEqualUnicodeString( &candidate->StageName,
                                        &nameInfo->Name, TRUE ) ||
                 (candidate->Rotating && !isWriter &&
                  candidate->PreviousStageName.Length != 0 &&
                  RtlEqualUnicodeString( &candidate->PreviousStageName,
                                         &nameInfo->Name, TRUE )))) {
                mapping = candidate;
                break;
            }
        }
        if (mapping == NULL ||
            (isWriter && (mapping->Sealing ||
                          (mapping->Sealed &&
                           !(mapping->Rotating &&
                             mapping->PreviousStageName.Length != 0))))) {
            status = STATUS_ACCESS_DENIED;
        } else if (isWriter) {
            mapping->OpenWriters += 1;
        }
        FltReleasePushLock( &SafeUploadPrototypeMappingLock );
        if (!NT_SUCCESS( status )) {
            goto Deny;
        }
        // The access check was made against the virtual destination using
        // the caller's original subject context. The trusted reparse carries
        // only those granted rights; the backing ACL remains service-only.
        securityContext->AccessState->PreviouslyGrantedAccess |= marker->GrantedAccess;
        securityContext->AccessState->RemainingDesiredAccess &=
            ~(marker->GrantedAccess | MAXIMUM_ALLOWED);
        if (marker->StagePrepared) {
            Data->Iopb->Parameters.Create.Options =
                (Data->Iopb->Parameters.Create.Options & 0x00ffffff) |
                (FILE_OPEN << 24);
            FltSetCallbackDataDirty( Data );
        } else if (disposition == FILE_SUPERSEDE) {
            Data->Iopb->Parameters.Create.Options =
                (Data->Iopb->Parameters.Create.Options & 0x00ffffff) |
                (FILE_OVERWRITE << 24);
            FltSetCallbackDataDirty( Data );
        }
        FltReleaseFileNameInformation( nameInfo );
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    if (securityContext == NULL ||
        FlagOn( Data->Iopb->Parameters.Create.Options,
                FILE_DIRECTORY_FILE | FILE_OPEN_BY_FILE_ID ) ||
        FlagOn( Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE )) {
        FltReleaseFileNameInformation( nameInfo );
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetInstanceContext( Instance, (PFLT_CONTEXT *) &instanceContext );
    if (NT_SUCCESS( status )) {
        volumeKind = instanceContext->VolumeKind;
        FltReleaseContext( instanceContext );
    }
    if (!SafeUploadPolicyMatchesDestination( volumeKind, &nameInfo->Name ) &&
        !RtlPrefixUnicodeString( &sourcePrefix, &relativeName, TRUE )) {
        FltReleaseFileNameInformation( nameInfo );
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (SafeUploadData.ClientPort != NULL &&
        processId == SafeUploadData.InspectorProcessId) {
        // Reads are needed for source checks and reconciliation. Writes in
        // protected scope require this transfer's exact one-use permit.
        if (!isWriter || SafeUploadPublicationCreate( &nameInfo->Name, disposition, isWriter )) {
            FltReleaseFileNameInformation( nameInfo );
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        status = STATUS_ACCESS_DENIED;
        goto Deny;
    }

    suffixLength = nameInfo->FinalComponent.Length;

    // A subsequent open by the writer sees its staged version, including
    // metadata-only and read opens. Other processes still see the old
    // destination. The map is keyed by the full opened name, not extension.
    FltAcquirePushLockExclusive( &SafeUploadPrototypeMappingLock );
    for (link = SafeUploadPrototypeMappings.Flink;
         link != &SafeUploadPrototypeMappings;
         link = link->Flink) {
        PSAFEUPLOAD_PROTOTYPE_MAPPING candidate =
            CONTAINING_RECORD( link, SAFEUPLOAD_PROTOTYPE_MAPPING, Link );
        if (!candidate->OwnerExited && candidate->OwnerProcessId == processId &&
            RtlEqualUnicodeString( &candidate->OriginalName,
                                   &nameInfo->Name, TRUE )) {
            mapping = candidate;
            break;
        }
    }

    if (mapping != NULL) {
        status = SafeUploadStageCheckAccess( Data, mapping->SecurityDescriptor,
            securityContext->DesiredAccess, &grantedAccess );
        if (!NT_SUCCESS( status ) || disposition == FILE_CREATE) {
            FltReleasePushLock( &SafeUploadPrototypeMappingLock );
            if (NT_SUCCESS( status )) status = STATUS_OBJECT_NAME_COLLISION;
            goto Deny;
        }
        if (isWriter && (mapping->Sealing || mapping->Rotating)) {
            FltReleasePushLock( &SafeUploadPrototypeMappingLock );
            status = STATUS_SHARING_VIOLATION;
            goto Deny;
        }
        if (isWriter && mapping->Sealed) {
            if (((Data->Iopb->Parameters.Create.Options >> 24) & 0xff) ==
                FILE_CREATE) {
                FltReleasePushLock( &SafeUploadPrototypeMappingLock );
                status = STATUS_OBJECT_NAME_COLLISION;
                goto Deny;
            }
            if (mapping->StageName.Length >= sizeof( previousStageBuffer )) {
                FltReleasePushLock( &SafeUploadPrototypeMappingLock );
                status = STATUS_NAME_TOO_LONG;
                goto Deny;
            }
            previousStageName.Buffer = previousStageBuffer;
            previousStageName.Length = mapping->StageName.Length;
            previousStageName.MaximumLength = sizeof( previousStageBuffer );
            RtlCopyMemory( previousStageBuffer, mapping->StageName.Buffer,
                           mapping->StageName.Length + sizeof( WCHAR ) );
            mapping->Rotating = TRUE;
            InterlockedIncrement( &mapping->References );
            followup = TRUE;
            FltReleasePushLock( &SafeUploadPrototypeMappingLock );
            goto AllocateStage;
        }
        newNameLength = mapping->Rotating &&
                        mapping->PreviousStageName.Length != 0
            ? mapping->PreviousStageName.Length : mapping->StageName.Length;
        newName = ExAllocatePool2( POOL_FLAG_PAGED,
                                   newNameLength + sizeof( WCHAR ),
                                   SAFEUPLOAD_POOL_TAG );
        if (newName != NULL) {
            RtlCopyMemory( newName,
                           mapping->Rotating &&
                           mapping->PreviousStageName.Length != 0
                               ? mapping->PreviousStageName.Buffer
                               : mapping->StageName.Buffer,
                           newNameLength + sizeof( WCHAR ) );
        }
        FltReleasePushLock( &SafeUploadPrototypeMappingLock );
        if (newName == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Deny;
        }
        goto Reparse;
    }

    if (mapping == NULL && (!isWriter || disposition == FILE_OPEN || disposition == FILE_OVERWRITE)) {
        for (link = SafeUploadPrototypeMappings.Flink; link != &SafeUploadPrototypeMappings;
             link = link->Flink) {
            PSAFEUPLOAD_PROTOTYPE_MAPPING candidate = CONTAINING_RECORD(
                link, SAFEUPLOAD_PROTOTYPE_MAPPING, Link );
            PLIST_ENTRY oldLink;
            if (candidate->OwnerExited || candidate->OwnerProcessId != processId) continue;
            for (oldLink = candidate->OldNames.Flink; oldLink != &candidate->OldNames;
                 oldLink = oldLink->Flink) {
                PSAFEUPLOAD_PROTOTYPE_OLD_NAME oldName = CONTAINING_RECORD(
                    oldLink, SAFEUPLOAD_PROTOTYPE_OLD_NAME, Link );
                if (RtlEqualUnicodeString( &oldName->Name, &nameInfo->Name, TRUE )) {
                    FltReleasePushLock( &SafeUploadPrototypeMappingLock );
                    status = STATUS_OBJECT_NAME_NOT_FOUND;
                    goto Deny;
                }
            }
        }
    }
    if (!isWriter) {
        FltReleasePushLock( &SafeUploadPrototypeMappingLock );
        FltReleaseFileNameInformation( nameInfo );
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (SafeUploadPrototypeMappingCount >= 128) {
        FltReleasePushLock( &SafeUploadPrototypeMappingLock );
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Deny;
    }
    FltReleasePushLock( &SafeUploadPrototypeMappingLock );

    status = SafeUploadStageCaptureSecurity( Data, Instance, &nameInfo->Name,
        &securityDescriptor, &assignedSecurityDescriptor,
        &destinationExists, &grantedAccess );
    if (!NT_SUCCESS( status )) {
        goto Deny;
    }

AllocateStage:
    // A service-owned journal entry must exist before this name is used.
    // A missing, late, or malformed service answer denies the create.
    status = SafeUploadPrototypeAllocateStageName( Data, &nameInfo->Name, volumeKind,
                                                    followup ? &previousStageName : NULL,
                                                    stageBaseName,
                                                    &stageBaseNameLength );
    if (!NT_SUCCESS( status )) {
        goto Deny;
    }

    extensionOffset = suffixLength;
    for (i = 0; i < suffixLength / sizeof( WCHAR ); ++i) {
        if (nameInfo->FinalComponent.Buffer[i] == L'.') {
            extensionOffset = i * sizeof( WCHAR );
        }
    }
    if (stageBaseNameLength != 32 * sizeof( WCHAR ) +
                                   suffixLength - extensionOffset ||
        RtlCompareMemory( (PUCHAR) stageBaseName + 32 * sizeof( WCHAR ),
                          (PUCHAR) nameInfo->FinalComponent.Buffer + extensionOffset,
                          suffixLength - extensionOffset ) !=
                              suffixLength - extensionOffset) {
        status = STATUS_INVALID_PARAMETER;
        goto Deny;
    }

    // Resolve the private local stage independently of the destination.
    status = FltGetVolumeFromName( SafeUploadData.Filter,
                                   &stageDrive, &stageVolume );
    if (!NT_SUCCESS( status )) {
        goto Deny;
    }
    {
        ULONG needed = 0;
        status = FltGetVolumeName( stageVolume, NULL, &needed );
        if (status != STATUS_BUFFER_TOO_SMALL || needed > MAXUSHORT) {
            if (status == STATUS_BUFFER_TOO_SMALL) {
                status = STATUS_NAME_TOO_LONG;
            }
            goto Deny;
        }
        stageVolumeName.Buffer = ExAllocatePool2( POOL_FLAG_PAGED,
                                                  needed,
                                                  SAFEUPLOAD_POOL_TAG );
        if (stageVolumeName.Buffer == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Deny;
        }
        stageVolumeName.MaximumLength = (USHORT) needed;
        status = FltGetVolumeName( stageVolume, &stageVolumeName, NULL );
        if (!NT_SUCCESS( status )) {
            goto Deny;
        }
    }

    if ((ULONG) stageVolumeName.Length + stagePrefix.Length +
        stageBaseNameLength >
        MAXUSHORT - sizeof( WCHAR )) {
        status = STATUS_NAME_TOO_LONG;
        goto Deny;
    }

    newNameLength = stageVolumeName.Length + stagePrefix.Length +
                    stageBaseNameLength;
    newName = ExAllocatePool2( POOL_FLAG_PAGED,
                               newNameLength + sizeof( WCHAR ),
                               SAFEUPLOAD_POOL_TAG );
    if (newName == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Deny;
    }

    RtlCopyMemory( newName, stageVolumeName.Buffer, stageVolumeName.Length );
    RtlCopyMemory( (PUCHAR) newName + stageVolumeName.Length,
                   stagePrefix.Buffer, stagePrefix.Length );
    RtlCopyMemory( (PUCHAR) newName + stageVolumeName.Length +
                   stagePrefix.Length, stageBaseName, stageBaseNameLength );
    newName[newNameLength / sizeof( WCHAR )] = L'\0';

    // Keep the two names together so a later open can resolve exactly the
    // staged version owned by this process. The durable manifest is owned by
    // the service; this in-memory map is only the prototype writer view.
    if (followup) {
        FltAcquirePushLockExclusive( &SafeUploadPrototypeMappingLock );
        if (!mapping->Rotating || mapping->StageName.Length != newNameLength) {
            status = STATUS_INVALID_PARAMETER;
        } else {
            PSAFEUPLOAD_STAGE_HANDLE_NAME nextName = SafeUploadNewStageHandleName(
                &mapping->OriginalName, mapping->OriginalVolumeLength );
            if (nextName == NULL) {
                FltReleasePushLock( &SafeUploadPrototypeMappingLock );
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto Deny;
            }
            mapping->PreviousHandleName = mapping->HandleName;
            mapping->HandleName = nextName;
            mapping->PreviousStageName.Length = mapping->StageName.Length;
            RtlCopyMemory( mapping->PreviousStageName.Buffer,
                           mapping->StageName.Buffer,
                           mapping->StageName.Length + sizeof( WCHAR ) );
            RtlCopyMemory( mapping->StageName.Buffer, newName,
                           newNameLength + sizeof( WCHAR ) );
            rotationPrepared = TRUE;
        }
        FltReleasePushLock( &SafeUploadPrototypeMappingLock );
        if (!NT_SUCCESS( status )) {
            goto Deny;
        }
    } else {
        mapping = ExAllocatePool2( POOL_FLAG_PAGED,
            sizeof( *mapping ) + nameInfo->Name.Length + sizeof( WCHAR ) +
            2 * (newNameLength + sizeof( WCHAR )), SAFEUPLOAD_POOL_TAG );
        if (mapping == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Deny;
        }
        mapping->OwnerProcessId = processId;
        mapping->References = 1;
        mapping->OriginalVolumeLength = nameInfo->Volume.Length;
        InitializeListHead( &mapping->OldNames );
        mapping->OpenWriters = 0;
        mapping->Sealing = FALSE;
        mapping->Sealed = FALSE;
        mapping->Rotating = FALSE;
        mapping->SecurityDescriptor = securityDescriptor;
        mapping->AssignedSecurityDescriptor = assignedSecurityDescriptor;
        securityDescriptor = NULL;
        mapping->OriginalName.Buffer = (PWCH) (mapping + 1);
        mapping->OriginalName.Length = nameInfo->Name.Length;
        mapping->OriginalName.MaximumLength =
            nameInfo->Name.Length + sizeof( WCHAR );
        RtlCopyMemory( mapping->OriginalName.Buffer, nameInfo->Name.Buffer,
                       nameInfo->Name.Length );
        mapping->OriginalName.Buffer[nameInfo->Name.Length / sizeof( WCHAR )] = L'\0';
        mapping->StageName.Buffer = (PWCH) ((PUCHAR) mapping->OriginalName.Buffer +
                                            mapping->OriginalName.MaximumLength);
        mapping->StageName.Length = newNameLength;
        mapping->StageName.MaximumLength = newNameLength + sizeof( WCHAR );
        RtlCopyMemory( mapping->StageName.Buffer, newName,
                       newNameLength + sizeof( WCHAR ) );
        mapping->PreviousStageName.Buffer = (PWCH)
            ((PUCHAR) mapping->StageName.Buffer + mapping->StageName.MaximumLength);
        mapping->PreviousStageName.Length = 0;
        mapping->PreviousStageName.MaximumLength =
            newNameLength + sizeof( WCHAR );
        mapping->HandleName = SafeUploadNewStageHandleName(
            &mapping->OriginalName, mapping->OriginalVolumeLength );
        if (mapping->HandleName == NULL) {
            SafeUploadPrototypeFreeMapping( mapping );
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Deny;
        }
        newMapping = TRUE;
    }

Reparse:
    if (stageVolume != NULL) {
        FltObjectDereference( stageVolume );
        stageVolume = NULL;
    }
    if (stageVolumeName.Buffer != NULL) {
        ExFreePoolWithTag( stageVolumeName.Buffer, SAFEUPLOAD_POOL_TAG );
        stageVolumeName.Buffer = NULL;
    }
    createInformation = disposition == FILE_SUPERSEDE
        ? (destinationExists ? FILE_SUPERSEDED : FILE_CREATED)
        : (disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF)
            ? (destinationExists ? FILE_OVERWRITTEN : FILE_CREATED)
            : destinationExists ? FILE_OPENED : FILE_CREATED;
    status = SafeUploadPrototypeMarkRedirect( Data, newName, newNameLength,
        grantedAccess, newMapping || followup, isWriter, createInformation );
    if (!NT_SUCCESS( status )) {
        if (newMapping) {
            SafeUploadPrototypeFreeMapping( mapping );
        }
        goto Deny;
    }
    status = IoReplaceFileObjectName( Data->Iopb->TargetFileObject,
                                      newName, newNameLength );
    ExFreePoolWithTag( newName, SAFEUPLOAD_POOL_TAG );
    newName = NULL;

    if (NT_SUCCESS( status )) {
        if (newMapping) {
            FltAcquirePushLockExclusive( &SafeUploadPrototypeMappingLock );
            for (link = SafeUploadPrototypeMappings.Flink;
                 link != &SafeUploadPrototypeMappings;
                 link = link->Flink) {
                PSAFEUPLOAD_PROTOTYPE_MAPPING candidate =
                    CONTAINING_RECORD( link, SAFEUPLOAD_PROTOTYPE_MAPPING, Link );
                if (candidate->OwnerProcessId == mapping->OwnerProcessId &&
                    RtlEqualUnicodeString( &candidate->OriginalName,
                                           &mapping->OriginalName, TRUE )) {
                    status = STATUS_SHARING_VIOLATION;
                    break;
                }
            }
            if (NT_SUCCESS( status ) && SafeUploadPrototypeMappingCount < 128) {
                InsertTailList( &SafeUploadPrototypeMappings, &mapping->Link );
                SafeUploadPrototypeMappingCount += 1;
            } else if (NT_SUCCESS( status )) {
                status = STATUS_INSUFFICIENT_RESOURCES;
            }
            FltReleasePushLock( &SafeUploadPrototypeMappingLock );
            if (!NT_SUCCESS( status )) {
                SafeUploadPrototypeFreeMapping( mapping );
                goto Deny;
            }
        }
        FltReleaseFileNameInformation( nameInfo );
        if (followup) {
            SafeUploadPrototypeFreeMapping( mapping );
        }
        Data->IoStatus.Status = STATUS_REPARSE;
        Data->IoStatus.Information = IO_REPARSE;
        return FLT_PREOP_COMPLETE;
    }

    if (newMapping) {
        SafeUploadPrototypeFreeMapping( mapping );
    }

Deny:
    if (status == STATUS_ACCESS_DENIED && SafeUploadData.ClientPort != NULL &&
        nameInfo != NULL) {
        PSAFEUPLOAD_EXCHANGE diagnostic = ExAllocatePool2( POOL_FLAG_NON_PAGED,
            sizeof( *diagnostic ), SAFEUPLOAD_POOL_TAG );
        if (diagnostic != NULL && nameInfo->Name.Length <= SAFEUPLOAD_MAX_PATH_BYTES) {
            UINT32 diagnosticVerdict;
            BOOLEAN diagnosticAnswered;
            diagnostic->Request.Version = SAFEUPLOAD_PROTOCOL_VERSION;
            diagnostic->Request.StructSize = sizeof( SAFEUPLOAD_REQUEST );
            diagnostic->Request.RequestId = (UINT64) InterlockedIncrement64( &SafeUploadData.NextRequestId );
            diagnostic->Request.Operation = SAFEUPLOAD_OPERATION_STAGE_DIAGNOSTIC;
            diagnostic->Request.Flags = 0x10000000 |
                (securityContext != NULL ? securityContext->DesiredAccess : 0);
            diagnostic->Request.Reserved = (UINT32) status;
            diagnostic->Request.PathLength = nameInfo->Name.Length;
            RtlCopyMemory( diagnostic->Request.Path, nameInfo->Name.Buffer, nameInfo->Name.Length );
            (VOID) SafeUploadRequestVerdict( diagnostic, &diagnosticVerdict, &diagnosticAnswered );
        }
        if (diagnostic != NULL) ExFreePoolWithTag( diagnostic, SAFEUPLOAD_POOL_TAG );
    }
    SafeUploadStageFreeSecurity( securityDescriptor, assignedSecurityDescriptor );
    if (followup && mapping != NULL) {
        FltAcquirePushLockExclusive( &SafeUploadPrototypeMappingLock );
        if (rotationPrepared) {
            RtlCopyMemory( mapping->StageName.Buffer,
                           mapping->PreviousStageName.Buffer,
                           mapping->PreviousStageName.Length + sizeof( WCHAR ) );
            mapping->PreviousStageName.Length = 0;
            SafeUploadReleaseStageHandleName( mapping->HandleName );
            mapping->HandleName = mapping->PreviousHandleName;
            mapping->PreviousHandleName = NULL;
        }
        mapping->Rotating = FALSE;
        FltReleasePushLock( &SafeUploadPrototypeMappingLock );
        SafeUploadPrototypeFreeMapping( mapping );
    }
    if (stageVolume != NULL) {
        FltObjectDereference( stageVolume );
    }
    if (stageVolumeName.Buffer != NULL) {
        ExFreePoolWithTag( stageVolumeName.Buffer, SAFEUPLOAD_POOL_TAG );
    }
    if (newName != NULL) {
        ExFreePoolWithTag( newName, SAFEUPLOAD_POOL_TAG );
    }
    FltReleaseFileNameInformation( nameInfo );
    Data->IoStatus.Status = status;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}
#endif


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
    BOOLEAN monitoredExtension;
    BOOLEAN taintedWriter = FALSE;
    NTSTATUS status;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    FLT_PREOP_CALLBACK_STATUS stageStatus;
    BOOLEAN stageWriter;
#endif

    *CompletionContext = NULL;

    PAGED_CODE();

    SafeUploadCount( CreatesSeen );

#if SAFEUPLOAD_STAGING_PROTOTYPE
    // The experiment intercepts only direct top-level writes to the test
    // folder. Production staging needs policy-driven cross-volume mapping,
    // handle tracking, namespace virtualization, and recovery.
    stageStatus = SafeUploadPrototypeRedirectCreate( Data, FltObjects->Instance,
                                                     &stageWriter );
    if (stageStatus == FLT_PREOP_COMPLETE) {
        return FLT_PREOP_COMPLETE;
    }
    if (stageStatus == FLT_PREOP_SUCCESS_WITH_CALLBACK) {
        *CompletionContext = (PVOID) (ULONG_PTR)
            (SAFEUPLOAD_POSTCREATE_STAGE |
             (stageWriter ? SAFEUPLOAD_POSTCREATE_STAGE_WRITER : 0));
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }
#endif

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

    monitoredExtension = SafeUploadPolicyMatchesExtension( &targetFileObject->FileName );

    if (!monitoredExtension) {

        // Keep the cheap exit for ordinary files. Only an unmonitored
        // extension written by an already tainted process can reach the
        // destination gate below.
        taintedWriter = (BOOLEAN)
            (FlagOn( securityContext->DesiredAccess,
                     FILE_WRITE_DATA | FILE_APPEND_DATA ) &&
             SafeUploadIsProcessTainted( FltGetRequestorProcessId( Data ) ));

        if (!taintedWriter) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
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
        (taintedWriter ||
         SafeUploadIsProcessTainted( FltGetRequestorProcessId( Data ) )) &&
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

            *CompletionContext = (PVOID) (ULONG_PTR)
                ((ULONG) volumeKind | SAFEUPLOAD_POSTCREATE_OVERRIDE);

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

    // Content inspection is limited to configured formats. Destination
    // blocking above is not: renaming or writing a .bin file into a cloud
    // folder must not bypass a tainted process's egress restriction.
    if (!monitoredExtension) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
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
    BOOLEAN overrideGranted;
    LARGE_INTEGER fileSize;
    LARGE_INTEGER lastWriteTime;
    UINT32 scopeFlags = 0;
    UINT32 verdict = SAFEUPLOAD_VERDICT_ALLOW;
    BOOLEAN answered = FALSE;
    BOOLEAN inspected;
    BOOLEAN stampKnown;
    BOOLEAN cacheEligible;
    LONG policyGeneration;
    LONG currentGeneration;
    NTSTATUS status;

    PAGED_CODE();

#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (((ULONG_PTR) CompletionContext & SAFEUPLOAD_POSTCREATE_STAGE) != 0) {
        BOOLEAN writer = (BOOLEAN)
            (((ULONG_PTR) CompletionContext &
              SAFEUPLOAD_POSTCREATE_STAGE_WRITER) != 0);
        BOOLEAN succeeded = (BOOLEAN)
            (NT_SUCCESS( Data->IoStatus.Status ) &&
             Data->IoStatus.Status != STATUS_REPARSE &&
             !FlagOn( Flags, FLTFL_POST_OPERATION_DRAINING ));
        if (!NT_SUCCESS( Data->IoStatus.Status ) &&
            !FlagOn( Flags, FLTFL_POST_OPERATION_DRAINING ) &&
            SafeUploadData.ClientPort != NULL) {
            PSAFEUPLOAD_PROTOTYPE_STAGE_ECP marker = SafeUploadPrototypeHasRedirectMarker( Data, NULL );
            PSAFEUPLOAD_EXCHANGE diagnostic = marker == NULL ? NULL :
                ExAllocatePool2( POOL_FLAG_NON_PAGED, sizeof( *diagnostic ), SAFEUPLOAD_POOL_TAG );
            if (diagnostic != NULL) {
                UINT32 diagnosticVerdict;
                BOOLEAN diagnosticAnswered;
                diagnostic->Request.Version = SAFEUPLOAD_PROTOCOL_VERSION;
                diagnostic->Request.StructSize = sizeof( SAFEUPLOAD_REQUEST );
                diagnostic->Request.RequestId = (UINT64) InterlockedIncrement64( &SafeUploadData.NextRequestId );
                diagnostic->Request.Operation = SAFEUPLOAD_OPERATION_STAGE_DIAGNOSTIC;
                diagnostic->Request.Flags = 0x40000000 |
                    Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
                diagnostic->Request.Reserved = (UINT32) Data->IoStatus.Status;
                diagnostic->Request.PathLength = marker->StageNameLength;
                RtlCopyMemory( diagnostic->Request.Path, marker->StageName, marker->StageNameLength );
                (VOID) SafeUploadRequestVerdict( diagnostic, &diagnosticVerdict, &diagnosticAnswered );
                ExFreePoolWithTag( diagnostic, SAFEUPLOAD_POOL_TAG );
            }
        }
        if (writer && succeeded) {
            status = SafeUploadMarkHandleForWrite( FltObjects, FALSE );
            if (!NT_SUCCESS( status )) {
                FltCancelFileOpen( FltObjects->Instance,
                                   FltObjects->FileObject );
                Data->IoStatus.Status = status;
                Data->IoStatus.Information = 0;
                succeeded = FALSE;
            }
        }
        if (succeeded) {
            status = SafeUploadAttachStageHandleName( Data, FltObjects );
            if (!NT_SUCCESS( status )) {
                FltCancelFileOpen( FltObjects->Instance, FltObjects->FileObject );
                Data->IoStatus.Status = status;
                Data->IoStatus.Information = 0;
                succeeded = FALSE;
            }
        }
        SafeUploadPrototypeFinishStageOpen( Data, writer, succeeded );
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
#endif

    volumeKind = (SAFEUPLOAD_VOLUME_KIND)
        ((ULONG_PTR) CompletionContext & ~SAFEUPLOAD_POSTCREATE_OVERRIDE);
    overrideGranted = (BOOLEAN)
        (((ULONG_PTR) CompletionContext & SAFEUPLOAD_POSTCREATE_OVERRIDE) != 0);

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

    // A justified create can cover an extension outside the inspection
    // list. It still needs a handle marker so the following write does not
    // consume a second grant or get denied by the write callback.
    if (overrideGranted &&
        !SafeUploadPolicyMatchesExtension( &FltObjects->FileObject->FileName )) {

        if (FltObjects->FileObject->WriteAccess) {
            (VOID) SafeUploadMarkHandleForWrite( FltObjects, TRUE );
        }

        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    stampKnown = SafeUploadReadFileStamp( FltObjects, &fileSize, &lastWriteTime );
    policyGeneration = SafeUploadCurrentPolicyGeneration();

    // Source classification depends on the access requested for this open.
    // A write-only open must not cache an out-of-scope result that a later
    // reader can reuse, nor inherit a reader's sensitive source verdict.
    cacheEligible = (BOOLEAN)
        (Data->Iopb->Parameters.Create.SecurityContext != NULL &&
         FlagOn( Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess,
                 FILE_READ_DATA ) &&
         !SafeUploadPolicyClassifiesAllSources());

    // A newly created or truncated file has no content to classify yet.
    // Reading it from user mode may fail on the just-opened write handle;
    // treating that failure as sensitive taints a clean writer. Keep the
    // write-handle marker so cleanup dirties any previous stream verdict.
    if (stampKnown && fileSize.QuadPart == 0) {

        if (FltObjects->FileObject->WriteAccess) {
            (VOID) SafeUploadMarkHandleForWrite( FltObjects, overrideGranted );
        }

        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    status = STATUS_SUCCESS;
    if (cacheEligible) {
        status = SafeUploadGetOrCreateStreamContext( FltObjects,
                                                     FltObjects->FileObject,
                                                     &streamContext );
    }

    if (NT_SUCCESS( status ) && cacheEligible) {

        FltAcquirePushLockShared( &streamContext->Lock );

        if (streamContext->ScopeEvaluated &&
            streamContext->PolicyGeneration == policyGeneration) {

            if (streamContext->ScopeFlags == 0) {

                //
                //  Known to be out of scope. This is the entry that pays for
                //  itself the most: it skips a name resolution on every
                //  later open of a file the policy does not care about.
                //

                scopeFlags = 0;
                answered = TRUE;

            } else if (streamContext->VerdictValid &&
                       !streamContext->Dirty &&
                       streamContext->FileSize.QuadPart == fileSize.QuadPart &&
                       streamContext->LastWriteTime.QuadPart == lastWriteTime.QuadPart) {

                scopeFlags = streamContext->ScopeFlags;
                verdict = streamContext->Verdict;
                answered = TRUE;
            }
        }

        FltReleasePushLock( &streamContext->Lock );
    }

    currentGeneration = SafeUploadCurrentPolicyGeneration();
    if (currentGeneration != policyGeneration) {
        policyGeneration = currentGeneration;
        answered = FALSE;
        scopeFlags = 0;
        verdict = SAFEUPLOAD_VERDICT_ALLOW;
    }

    if (answered) {
        SafeUploadCount( CacheHits );
    }

    if (!answered) {

        inspected = SafeUploadEvaluate( Data, volumeKind, &scopeFlags, &verdict );

        if (streamContext != NULL && cacheEligible) {

            FltAcquirePushLockExclusive( &streamContext->Lock );

            streamContext->ScopeEvaluated = inspected;
            streamContext->PolicyGeneration = policyGeneration;
            streamContext->ScopeFlags = scopeFlags;
            streamContext->Verdict = verdict;

            //
            //  A verdict earns a place in the cache only when it was
            //  actually checked. An unchecked ALLOW (timeout, no port,
            //  allocation failure) must be retried on the next open, not
            //  reused as if user mode had cleared the file - otherwise a
            //  single failure turns into a standing exemption that lasts
            //  until the file's bytes change.
            //

            streamContext->VerdictValid = (BOOLEAN) (scopeFlags != 0 && inspected);
            streamContext->Dirty = FALSE;
            streamContext->FileSize = fileSize;
            streamContext->LastWriteTime = lastWriteTime;

            FltReleasePushLock( &streamContext->Lock );
        }
    }

    if (streamContext != NULL) {

        FltReleaseContext( streamContext );
    }

    if (scopeFlags == 0 && !overrideGranted) {

        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    //  A handle opened for write invalidates the cached verdict when it
    //  closes, because the content may have changed underneath us.
    //

    if (FltObjects->FileObject->WriteAccess) {

        (VOID) SafeUploadMarkHandleForWrite( FltObjects, overrideGranted );
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

        if (FlagOn( scopeFlags, SAFEUPLOAD_REQUEST_FLAG_SCOPE_DESTINATION ) &&
            !overrideGranted) {

            //
            //  Excecao antes de cancelar, pelo mesmo motivo do pre-create:
            //  este e o caminho que ja decidiu recusar.
            //

            if (SafeUploadOverrideCovers( Data, FltGetRequestorProcessId( Data ) )) {

                if (FltObjects->FileObject->WriteAccess) {
                    (VOID) SafeUploadMarkHandleForWrite( FltObjects, TRUE );
                }

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
SafeUploadPreWrite (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    Closes the already-open-handle gap. A process can open a destination
    before reading sensitive content; the create gate cannot know that it
    will become tainted later. Only a tainted process reaches the destination
    check, so ordinary writes do no name lookup.

    Paging I/O is excluded at registration because it often runs in System's
    context, not the process whose mapped view was modified. A grant consumed
    at create is carried by the stream-handle context for this handle alone.

    IRQL: <= APC_LEVEL.

--*/
{
    PSAFEUPLOAD_INSTANCE_CONTEXT instanceContext = NULL;
    SAFEUPLOAD_VOLUME_KIND volumeKind;
    ULONG processId;
    NTSTATUS status;

    UNREFERENCED_PARAMETER( CompletionContext = NULL );

    PAGED_CODE();

    if (Data->Iopb->Parameters.Write.Length == 0 ||
        SafeUploadData.ClientPort == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    processId = FltGetRequestorProcessId( Data );

    if (SafeUploadIsIgnoredProcess( processId ) ||
        !SafeUploadIsProcessTainted( processId ) ||
        SafeUploadHandleHasOverride( FltObjects )) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetInstanceContext( FltObjects->Instance,
                                    (PFLT_CONTEXT *) &instanceContext );

    if (!NT_SUCCESS( status )) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    volumeKind = instanceContext->VolumeKind;
    FltReleaseContext( instanceContext );

    if (!SafeUploadIsMonitoredDestination( Data, volumeKind )) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (SafeUploadPolicyAuditOnly()) {
        SafeUploadCount( WouldHaveDenied );
        SafeUploadTrace( "AUDITORIA: write seria negado, processo %lu marcado\n",
                         processId );
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    SafeUploadTrace( "write negado: processo %lu marcado\n", processId );
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
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
    when the writing is finished; the write callback exists to enforce a
    process taint acquired after the handle was opened.

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

    UNREFERENCED_PARAMETER( CompletionContext = NULL );

    PAGED_CODE();

#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (SafeUploadHandleWasOpenedForWrite( FltObjects ) &&
        SafeUploadPrototypeCleanupStageWriter( Data, FltObjects )) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
#else
    UNREFERENCED_PARAMETER( Data );
#endif

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

#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (SafeUploadData.ClientPort != NULL &&
        FltGetRequestorProcessId( Data ) == SafeUploadData.InspectorProcessId) {
        PFLT_FILE_NAME_INFORMATION source = NULL;
        PFLT_FILE_NAME_INFORMATION destination = NULL;
        PFILE_RENAME_INFORMATION rename = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        BOOLEAN allowed = FALSE;
        status = FltGetFileNameInformation( Data, FLT_FILE_NAME_NORMALIZED |
            FLT_FILE_NAME_QUERY_DEFAULT, &source );
        if (NT_SUCCESS( status ) && rename != NULL &&
            (informationClass == FileRenameInformation || informationClass == FileRenameInformationEx)) {
            status = FltGetDestinationFileNameInformation( FltObjects->Instance,
                FltObjects->FileObject, rename->RootDirectory, rename->FileName,
                rename->FileNameLength, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                &destination );
            if (NT_SUCCESS( status )) {
                PSAFEUPLOAD_INSTANCE_CONTEXT context = NULL;
                SAFEUPLOAD_VOLUME_KIND kind = SafeUploadVolumeUnknown;
                if (NT_SUCCESS( FltGetInstanceContext( FltObjects->Instance,
                    (PFLT_CONTEXT *) &context ) )) {
                    kind = context->VolumeKind;
                    FltReleaseContext( context );
                }
                allowed = (!SafeUploadPrototypeProtectedName( source, kind ) &&
                           !SafeUploadPrototypeProtectedName( destination, kind )) ||
                    SafeUploadPublicationRename( &source->Name, &destination->Name );
            }
        }
        if (source != NULL) FltReleaseFileNameInformation( source );
        if (destination != NULL) FltReleaseFileNameInformation( destination );
        Data->IoStatus.Status = allowed ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        // Authorized publication must reach the real filesystem rename.
        return allowed ? FLT_PREOP_SUCCESS_NO_CALLBACK : FLT_PREOP_COMPLETE;
    }
    // The reparse probe has no rename transaction yet. A rename or hard
    // link into its test destination would put staged bytes on the real
    // path without inspection. Refuse it even without a service client.
    // This is a temporary safety gate; a transparent implementation must
    // redirect the rename and update the stage mapping atomically.
    status = FltGetFileNameInformation( Data,
        FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo );
    if (!NT_SUCCESS( status ) && SafeUploadData.ClientPort != NULL &&
        FltObjects->FileObject->FileName.Length <= SAFEUPLOAD_MAX_PATH_BYTES) {
        PSAFEUPLOAD_EXCHANGE diagnostic = ExAllocatePool2( POOL_FLAG_NON_PAGED,
            sizeof( *diagnostic ), SAFEUPLOAD_POOL_TAG );
        if (diagnostic != NULL) {
            UINT32 diagnosticVerdict;
            BOOLEAN diagnosticAnswered;
            diagnostic->Request.Version = SAFEUPLOAD_PROTOCOL_VERSION;
            diagnostic->Request.StructSize = sizeof( SAFEUPLOAD_REQUEST );
            diagnostic->Request.RequestId = (UINT64) InterlockedIncrement64( &SafeUploadData.NextRequestId );
            diagnostic->Request.Operation = SAFEUPLOAD_OPERATION_STAGE_DIAGNOSTIC;
            diagnostic->Request.Flags = 10;
            diagnostic->Request.Reserved = (UINT32) status;
            diagnostic->Request.PathLength = FltObjects->FileObject->FileName.Length;
            RtlCopyMemory( diagnostic->Request.Path, FltObjects->FileObject->FileName.Buffer,
                diagnostic->Request.PathLength );
            (VOID) SafeUploadRequestVerdict( diagnostic, &diagnosticVerdict, &diagnosticAnswered );
            ExFreePoolWithTag( diagnostic, SAFEUPLOAD_POOL_TAG );
        }
    }
    if (NT_SUCCESS( status )) {
        UNICODE_STRING stagePrefix = RTL_CONSTANT_STRING(
            L"\\ProgramData\\SafeUpload\\staging\\" );
        UNICODE_STRING relativeName;

        if (NT_SUCCESS( FltParseFileNameInformation( nameInfo ) ) &&
            nameInfo->Name.Length > nameInfo->Volume.Length) {
            relativeName.Buffer = (PWCH) ((PUCHAR) nameInfo->Name.Buffer +
                                          nameInfo->Volume.Length);
            relativeName.Length = nameInfo->Name.Length - nameInfo->Volume.Length;
            relativeName.MaximumLength = relativeName.Length;
            if (RtlPrefixUnicodeString( &stagePrefix, &relativeName, TRUE )) {
                PFILE_RENAME_INFORMATION stageRename = (PFILE_RENAME_INFORMATION)
                    Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
                if (stageRename != NULL &&
                    (informationClass == FileRenameInformation ||
                     informationClass == FileRenameInformationEx)) {
                    FLT_PREOP_CALLBACK_STATUS result = SafeUploadPrototypeRename(
                        Data, FltObjects, &nameInfo->Name, stageRename,
                        informationClass == FileRenameInformationEx );
                    FltReleaseFileNameInformation( nameInfo );
                    return result;
                }
                FltReleaseFileNameInformation( nameInfo );
                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                Data->IoStatus.Information = 0;
                return FLT_PREOP_COMPLETE;
            }
        }
        FltReleaseFileNameInformation( nameInfo );
        nameInfo = NULL;
    }

    renameInformation = (PFILE_RENAME_INFORMATION)
        Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    if (renameInformation != NULL) {
        status = FltGetDestinationFileNameInformation(
            FltObjects->Instance, FltObjects->FileObject,
            renameInformation->RootDirectory,
            renameInformation->FileName,
            renameInformation->FileNameLength,
            FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT,
            &nameInfo );
        if (NT_SUCCESS( status )) {
            UNICODE_STRING testPrefix = RTL_CONSTANT_STRING(
                L"\\SafeUpload\\Escopo Monitorado\\" );
            UNICODE_STRING relativeName;

            if (NT_SUCCESS( FltParseFileNameInformation( nameInfo ) ) &&
                nameInfo->Name.Length > nameInfo->Volume.Length) {
                relativeName.Buffer = (PWCH) ((PUCHAR) nameInfo->Name.Buffer +
                                              nameInfo->Volume.Length);
                relativeName.Length = nameInfo->Name.Length - nameInfo->Volume.Length;
                relativeName.MaximumLength = relativeName.Length;
                if (RtlPrefixUnicodeString( &testPrefix, &relativeName, TRUE )) {
                    FltReleaseFileNameInformation( nameInfo );
                    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                    Data->IoStatus.Information = 0;
                    return FLT_PREOP_COMPLETE;
                }
            }
            FltReleaseFileNameInformation( nameInfo );
            nameInfo = NULL;
        }
    }
#endif

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
