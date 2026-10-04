/* TxF is refused in protected scopes in both production and prototype builds.
 * Transaction tracking itself remains prototype-only in StageWriters.c. */
#ifndef SAFEUPLOAD_STAGING_PROTOTYPE
#define SAFEUPLOAD_STAGING_PROTOTYPE 0
#endif

#include "Filter.h"
#include "Stage.h"

static SAFEUPLOAD_VOLUME_KIND StageTxfVolumeKind(_In_ PFLT_INSTANCE Instance)
{
    PSAFEUPLOAD_INSTANCE_CONTEXT context = NULL;
    SAFEUPLOAD_VOLUME_KIND kind = SafeUploadVolumeUnknown;
    if (NT_SUCCESS(FltGetInstanceContext(Instance, (PFLT_CONTEXT *)&context))) {
        kind = context->VolumeKind;
        FltReleaseContext(context);
    }
    return kind;
}

static UNICODE_STRING StageTxfBaseName(_In_ PFLT_FILE_NAME_INFORMATION Name)
{
    UNICODE_STRING base = Name->Name;
    if (Name->Stream.Length != 0 && Name->Stream.Length < base.Length &&
        (Name->Stream.Length & 1) == 0) {
        base.Length -= Name->Stream.Length;
        base.MaximumLength = base.Length;
    }
    return base;
}

#if SAFEUPLOAD_STAGING_PROTOTYPE
static BOOLEAN StageTxfMatchesBootstrap(_In_ PFLT_FILE_NAME_INFORMATION Name,
    _In_ BOOLEAN IncludeAncestors)
{
    UNICODE_STRING bootstrap = RTL_CONSTANT_STRING(L"\\SafeUpload\\Escopo Monitorado");
    UNICODE_STRING relative;
    USHORT bootstrapChars = bootstrap.Length / sizeof(WCHAR), relativeChars;
    if (Name->Volume.Length > Name->Name.Length || (Name->Volume.Length & 1) != 0) return TRUE;
    relative.Buffer = (PWCH)((PUCHAR)Name->Name.Buffer + Name->Volume.Length);
    relative.Length = Name->Name.Length - Name->Volume.Length;
    relative.MaximumLength = relative.Length;
    relativeChars = relative.Length / sizeof(WCHAR);
    if (RtlPrefixUnicodeString(&bootstrap, &relative, TRUE) &&
        (relative.Length == bootstrap.Length || relative.Buffer[bootstrapChars] == L'\\')) return TRUE;
    if (IncludeAncestors && relative.Length != 0 &&
        RtlPrefixUnicodeString(&relative, &bootstrap, TRUE) &&
        (relative.Length == bootstrap.Length || relative.Buffer[relativeChars - 1] == L'\\' ||
         bootstrap.Buffer[relativeChars] == L'\\')) return TRUE;
    return FALSE;
}
#endif

static BOOLEAN StageTxfNameInScope(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _In_ BOOLEAN IncludeAncestors,
    _In_ SAFEUPLOAD_VOLUME_KIND Kind)
{
    PFLT_FILE_NAME_INFORMATION name = NULL;
    UNICODE_STRING base;
    BOOLEAN inScope = FALSE;
    NTSTATUS status;

    if (KeGetCurrentIrql() > APC_LEVEL) return TRUE;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || IoGetTopLevelIrp() != NULL)
        return SafeUploadPolicyMayMatchVolume(Kind, Objects->Volume);
    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name);
    if (!NT_SUCCESS(status)) return SafeUploadPolicyMayMatchVolume(Kind, Objects->Volume);
    status = FltParseFileNameInformation(name);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(name);
        return SafeUploadPolicyMayMatchVolume(Kind, Objects->Volume);
    }

    base = StageTxfBaseName(name);
#if SAFEUPLOAD_STAGING_PROTOTYPE
    inScope = StageTxfMatchesBootstrap(name, IncludeAncestors);
#endif
    if (!inScope)
        inScope = SafeUploadPolicyMatchesCurrentOrPendingDestination(Kind, &base, IncludeAncestors);
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (!inScope) {
        BOOLEAN protectedAlias = FALSE;
        status = SafeUploadStageCheckNamedAliases(Objects->Instance, name, Kind, &protectedAlias);
        if (!NT_SUCCESS(status)) inScope = SafeUploadPolicyMayMatchVolume(Kind, Objects->Volume);
        else inScope = protectedAlias;
    }
#endif
    FltReleaseFileNameInformation(name);
    return inScope;
}

static BOOLEAN StageTxfCreateMutates(_In_ PFLT_CALLBACK_DATA Data)
{
    PIO_SECURITY_CONTEXT security = Data->Iopb->Parameters.Create.SecurityContext;
    ULONG disposition = Data->Iopb->Parameters.Create.Options >> 24;
    ULONG options = Data->Iopb->Parameters.Create.Options & 0x00ffffff;
    if (FlagOn(options, FILE_DELETE_ON_CLOSE) || disposition == FILE_CREATE ||
        disposition == FILE_OPEN_IF || disposition == FILE_SUPERSEDE ||
        disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF) return TRUE;
    if (security == NULL) return FALSE;
    return BooleanFlagOn(security->DesiredAccess, FILE_WRITE_DATA | FILE_APPEND_DATA |
        FILE_DELETE_CHILD | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC |
        WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL | MAXIMUM_ALLOWED);
}

static BOOLEAN StageTxfCreateMustRefuse(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects)
{
    SAFEUPLOAD_VOLUME_KIND kind;
    if (Objects->Transaction == NULL || !StageTxfCreateMutates(Data)) return FALSE;
    if (KeGetCurrentIrql() > APC_LEVEL) return TRUE;
    kind = StageTxfVolumeKind(Objects->Instance);
    /* A file-ID create has no name to match; fail closed on any scoped volume. */
    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_OPEN_BY_FILE_ID))
        return SafeUploadPolicyMayMatchVolume(kind, Objects->Volume);
    return StageTxfNameInScope(Data, Objects, TRUE, kind);
}

BOOLEAN SafeUploadStageTxfCreateMustRefuse(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects)
{
    return Objects->Transaction != NULL && StageTxfCreateMustRefuse(Data, Objects);
}

static BOOLEAN StageTxfSetInformationMustRefuse(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects)
{
    FILE_INFORMATION_CLASS cls = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    ULONG length = Data->Iopb->Parameters.SetFileInformation.Length;
    SAFEUPLOAD_VOLUME_KIND kind;
    PFILE_RENAME_INFORMATION rename;
    PFLT_FILE_NAME_INFORMATION destination = NULL;
    NTSTATUS status;

    if (Objects->Transaction == NULL) return FALSE;
    if (cls != FileDispositionInformation && (ULONG)cls != 64 &&
        cls != FileRenameInformation && cls != FileRenameInformationEx &&
        cls != FileLinkInformation && cls != FileLinkInformationEx) return FALSE;
    if (KeGetCurrentIrql() > APC_LEVEL) return TRUE;
    kind = StageTxfVolumeKind(Objects->Instance);
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || IoGetTopLevelIrp() != NULL)
        return SafeUploadPolicyMayMatchVolume(kind, Objects->Volume);

    if (cls == FileDispositionInformation) {
        PFILE_DISPOSITION_INFORMATION disposition = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        if (disposition == NULL || length < sizeof(*disposition))
            return SafeUploadPolicyMayMatchVolume(kind, Objects->Volume);
        if (!disposition->DeleteFile) return FALSE;
        return StageTxfNameInScope(Data, Objects, TRUE, kind);
    }
    if ((ULONG)cls == 64) { /* FileDispositionInformationEx */
        PVOID dispositionEx = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        ULONG dispositionFlags = 0;
        if (dispositionEx == NULL || length < sizeof(dispositionFlags))
            return SafeUploadPolicyMayMatchVolume(kind, Objects->Volume);
        RtlCopyMemory(&dispositionFlags, dispositionEx, sizeof(dispositionFlags));
        if (!FlagOn(dispositionFlags, 0x00000001)) return FALSE; /* FILE_DISPOSITION_DELETE */
        return StageTxfNameInScope(Data, Objects, TRUE, kind);
    }

    if (StageTxfNameInScope(Data, Objects, TRUE, kind)) return TRUE;
    rename = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    if (rename == NULL || length < (ULONG)FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName) ||
        rename->FileNameLength == 0 || (rename->FileNameLength & 1) != 0 ||
        rename->FileNameLength > length - (ULONG)FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName))
        return SafeUploadPolicyMayMatchVolume(kind, Objects->Volume);
    status = FltGetDestinationFileNameInformation(Objects->Instance, Objects->FileObject,
        rename->RootDirectory, rename->FileName, rename->FileNameLength,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &destination);
    if (!NT_SUCCESS(status)) return SafeUploadPolicyMayMatchVolume(kind, Objects->Volume);
    status = FltParseFileNameInformation(destination);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(destination);
        return SafeUploadPolicyMayMatchVolume(kind, Objects->Volume);
    }
    {
        UNICODE_STRING base = StageTxfBaseName(destination);
        BOOLEAN inScope = FALSE;
#if SAFEUPLOAD_STAGING_PROTOTYPE
        inScope = StageTxfMatchesBootstrap(destination, TRUE);
#endif
        if (!inScope)
            inScope = SafeUploadPolicyMatchesCurrentOrPendingDestination(kind, &base, TRUE);
#if SAFEUPLOAD_STAGING_PROTOTYPE
        if (!inScope) {
            BOOLEAN protectedAlias = FALSE;
            status = SafeUploadStageCheckNamedAliases(Objects->Instance,
                destination, kind, &protectedAlias);
            if (!NT_SUCCESS(status)) inScope = SafeUploadPolicyMayMatchVolume(kind, Objects->Volume);
            else inScope = protectedAlias;
        }
#endif
        FltReleaseFileNameInformation(destination);
        return inScope;
    }
}

BOOLEAN SafeUploadStageTxfSetInformationMustRefuse(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects)
{
    return Objects->Transaction != NULL && StageTxfSetInformationMustRefuse(Data, Objects);
}

#ifndef FSCTL_SET_ZERO_DATA
#define FSCTL_SET_ZERO_DATA CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 50, METHOD_BUFFERED, FILE_WRITE_DATA)
#endif
#ifndef FSCTL_SET_SPARSE
#define FSCTL_SET_SPARSE CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 49, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#endif
#ifndef FSCTL_SET_COMPRESSION
#define FSCTL_SET_COMPRESSION CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 16, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#endif
#ifndef FSCTL_SET_ENCRYPTION
#define FSCTL_SET_ENCRYPTION CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 53, METHOD_NEITHER, FILE_ANY_ACCESS)
#endif
#ifndef FSCTL_ENCRYPTION_FSCTL_IO
#define FSCTL_ENCRYPTION_FSCTL_IO CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 54, METHOD_NEITHER, FILE_ANY_ACCESS)
#endif
#ifndef FSCTL_SET_OBJECT_ID
#define FSCTL_SET_OBJECT_ID CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 38, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#endif
#ifndef FSCTL_SET_OBJECT_ID_EXTENDED
#define FSCTL_SET_OBJECT_ID_EXTENDED CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 47, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#endif
#ifndef FSCTL_CREATE_OR_GET_OBJECT_ID
#define FSCTL_CREATE_OR_GET_OBJECT_ID CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 48, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#ifndef FSCTL_DELETE_OBJECT_ID
#define FSCTL_DELETE_OBJECT_ID CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 40, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#endif
#ifndef FSCTL_SET_REPARSE_POINT
#define FSCTL_SET_REPARSE_POINT CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 41, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#endif
#ifndef FSCTL_DELETE_REPARSE_POINT
#define FSCTL_DELETE_REPARSE_POINT CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 43, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#endif
#ifndef FSCTL_SET_INTEGRITY_INFORMATION
#define FSCTL_SET_INTEGRITY_INFORMATION CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 160, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#endif
#ifndef FSCTL_DUPLICATE_EXTENTS_TO_FILE
#define FSCTL_DUPLICATE_EXTENTS_TO_FILE CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 209, METHOD_BUFFERED, FILE_WRITE_DATA)
#endif
#ifndef FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX
#define FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 250, METHOD_BUFFERED, FILE_WRITE_DATA)
#endif
#ifndef FSCTL_FILE_LEVEL_TRIM
#define FSCTL_FILE_LEVEL_TRIM CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 130, METHOD_BUFFERED, FILE_WRITE_DATA)
#endif
#ifndef FSCTL_OFFLOAD_WRITE
#define FSCTL_OFFLOAD_WRITE CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 154, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#endif
#ifndef FSCTL_SET_EXTERNAL_BACKING
#define FSCTL_SET_EXTERNAL_BACKING CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 195, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#endif
#ifndef FSCTL_WRITE_RAW_ENCRYPTED
#define FSCTL_WRITE_RAW_ENCRYPTED CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 55, METHOD_NEITHER, FILE_SPECIAL_ACCESS)
#endif
#ifndef FSCTL_SET_ZERO_ON_DEALLOCATION
#define FSCTL_SET_ZERO_ON_DEALLOCATION CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 101, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#endif
#ifndef FSCTL_DELETE_EXTERNAL_BACKING
#define FSCTL_DELETE_EXTERNAL_BACKING CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 197, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#endif

static BOOLEAN StageTxfMutatingFsctl(_In_ ULONG Code)
{
    switch (Code) {
    case FSCTL_SET_ZERO_DATA: case FSCTL_SET_SPARSE: case FSCTL_SET_COMPRESSION: case FSCTL_SET_ENCRYPTION:
    case FSCTL_ENCRYPTION_FSCTL_IO: case FSCTL_SET_OBJECT_ID: case FSCTL_SET_OBJECT_ID_EXTENDED:
    case FSCTL_CREATE_OR_GET_OBJECT_ID: case FSCTL_DELETE_OBJECT_ID: case FSCTL_SET_REPARSE_POINT:
    case FSCTL_DELETE_REPARSE_POINT: case FSCTL_SET_INTEGRITY_INFORMATION: case FSCTL_DUPLICATE_EXTENTS_TO_FILE:
    case FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX: case FSCTL_FILE_LEVEL_TRIM: case FSCTL_OFFLOAD_WRITE:
    case FSCTL_SET_EXTERNAL_BACKING: case FSCTL_WRITE_RAW_ENCRYPTED:
    case FSCTL_SET_ZERO_ON_DEALLOCATION: case FSCTL_DELETE_EXTERNAL_BACKING:
        return TRUE;
    default:
        return FALSE;
    }
}

static BOOLEAN StageTxfReparseFsctl(_In_ ULONG Code)
{
    return Code == FSCTL_SET_REPARSE_POINT || Code == FSCTL_DELETE_REPARSE_POINT;
}

BOOLEAN SafeUploadStageTxfFsctlMustRefuse(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects)
{
    ULONG code;
    if (Objects->Transaction == NULL || Data->Iopb->MajorFunction != IRP_MJ_FILE_SYSTEM_CONTROL ||
        Data->Iopb->MinorFunction != IRP_MN_USER_FS_REQUEST) return FALSE;
    code = Data->Iopb->Parameters.FileSystemControl.Common.FsControlCode;
    return StageTxfMutatingFsctl(code) &&
        StageTxfNameInScope(Data, Objects, StageTxfReparseFsctl(code), StageTxfVolumeKind(Objects->Instance));
}

VOID SafeUploadStageTxfRecordRefused(VOID)
{
#if SAFEUPLOAD_STAGING_PROTOTYPE
    SafeUploadStageWritersRecordTxfRefused();
#endif
}

static FLT_PREOP_CALLBACK_STATUS StageTxfCompleteAccessDenied(_Inout_ PFLT_CALLBACK_DATA Data)
{
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

FLT_PREOP_CALLBACK_STATUS SafeUploadStageTxfFsctlPreOperation(
    _In_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS Objects,
    _Out_ PVOID *CompletionContext)
{
    *CompletionContext = NULL;
    if (!SafeUploadStageTxfFsctlMustRefuse(Data, Objects)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    SafeUploadStageTxfRecordRefused();
    return StageTxfCompleteAccessDenied(Data);
}
