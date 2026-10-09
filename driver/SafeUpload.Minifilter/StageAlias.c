/* Bounded physical NTFS alias classification. A result is a snapshot, never a
 * namespace reservation. Protected aliases are refused, not virtualized here.
 * Use only documented FileHardLinkInformation and 8-byte NTFS parent IDs. */
#include "Stage.h"

#define ALIAS_TAG 'aUpS'
#define ALIAS_BYTES 65536
#define ALIAS_LIMIT 64

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SafeUploadStageCheckNamedAliases)
#pragma alloc_text(PAGE, SafeUploadStageCheckObjectAliases)
#endif

static NTSTATUS StageAliasOpenId(PFLT_INSTANCE Instance, PUNICODE_STRING Volume,
    LONGLONG Id, BOOLEAN Directory, PHANDLE Handle, PFILE_OBJECT *Object)
{
    PWCHAR buffer;
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io = {0};
    ULONG length = Volume->Length + sizeof(WCHAR) + sizeof(Id);
    NTSTATUS status;
    *Handle = NULL; *Object = NULL;
    if (length > SAFEUPLOAD_MAX_PATH_CHARS * sizeof(WCHAR)) return STATUS_NAME_TOO_LONG;
    buffer = ExAllocatePool2(POOL_FLAG_PAGED, length, ALIAS_TAG);
    if (buffer == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(buffer, Volume->Buffer, Volume->Length);
    buffer[Volume->Length / sizeof(WCHAR)] = L'\\';
    RtlCopyMemory((PUCHAR)buffer + Volume->Length + sizeof(WCHAR), &Id, sizeof(Id));
    name.Buffer = buffer; name.Length = name.MaximumLength = (USHORT)length;
    InitializeObjectAttributes(&attributes, &name, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = FltCreateFileEx2(SafeUploadData.Filter, Instance, Handle, Object,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attributes, &io, NULL, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
        FILE_OPEN_BY_FILE_ID | FILE_SYNCHRONOUS_IO_NONALERT | FILE_COMPLETE_IF_OPLOCKED |
            (Directory ? FILE_DIRECTORY_FILE : FILE_NON_DIRECTORY_FILE),
        NULL, 0, IO_IGNORE_SHARE_ACCESS_CHECK, NULL);
    ExFreePoolWithTag(buffer, ALIAS_TAG);
    return status;
}

static NTSTATUS StageAliasEntryProtected(PFLT_INSTANCE Instance,
    PUNICODE_STRING Volume, PFILE_LINK_ENTRY_INFORMATION Entry,
    SAFEUPLOAD_VOLUME_KIND Kind, PBOOLEAN Protected)
{
    HANDLE handle = NULL;
    PFILE_OBJECT object = NULL;
    PFLT_FILE_NAME_INFORMATION parent = NULL;
    PWCHAR buffer = NULL;
    UNICODE_STRING path;
    ULONG length, index;
    NTSTATUS status;
    for (index = 0; index < Entry->FileNameLength; ++index)
        if (Entry->FileName[index] == L'\\' || Entry->FileName[index] == L'/' ||
            Entry->FileName[index] == L'\0' || Entry->FileName[index] == L':')
            return STATUS_DATA_ERROR;
    status = StageAliasOpenId(Instance, Volume, Entry->ParentFileId, TRUE, &handle, &object);
    if (status != STATUS_SUCCESS) goto Exit;
    status = FltGetFileNameInformationUnsafe(object, Instance,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY, &parent);
    if (!NT_SUCCESS(status)) goto Exit;
    status = FltParseFileNameInformation(parent);
    if (!NT_SUCCESS(status)) goto Exit;
    /* Verify that the ID was resolved on the intended original volume. */
    if (!RtlEqualUnicodeString(Volume, &parent->Volume, TRUE)) {
        status = STATUS_NOT_SAME_DEVICE; goto Exit;
    }
    length = parent->Name.Length;
    if (length == 0) { status = STATUS_OBJECT_PATH_INVALID; goto Exit; }
    if (parent->Name.Buffer[length / sizeof(WCHAR) - 1] != L'\\') length += sizeof(WCHAR);
    if (length + Entry->FileNameLength * sizeof(WCHAR) > SAFEUPLOAD_MAX_PATH_CHARS * sizeof(WCHAR)) {
        status = STATUS_NAME_TOO_LONG; goto Exit;
    }
    buffer = ExAllocatePool2(POOL_FLAG_PAGED, length + Entry->FileNameLength * sizeof(WCHAR), ALIAS_TAG);
    if (buffer == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    RtlCopyMemory(buffer, parent->Name.Buffer, parent->Name.Length);
    if (length != parent->Name.Length) buffer[length / sizeof(WCHAR) - 1] = L'\\';
    RtlCopyMemory((PUCHAR)buffer + length, Entry->FileName, Entry->FileNameLength * sizeof(WCHAR));
    path.Buffer = buffer;
    path.Length = path.MaximumLength = (USHORT)(length + Entry->FileNameLength * sizeof(WCHAR));
    *Protected = SafeUploadStageProtectedPath(&path, parent->Volume.Length, Kind);
Exit:
    if (buffer != NULL) ExFreePoolWithTag(buffer, ALIAS_TAG);
    if (parent != NULL) FltReleaseFileNameInformation(parent);
    if (object != NULL) ObDereferenceObject(object);
    if (handle != NULL) FltClose(handle);
    return status;
}

static NTSTATUS StageAliasQuery(PFLT_INSTANCE Instance, PFILE_OBJECT Object,
    PUNICODE_STRING Volume, SAFEUPLOAD_VOLUME_KIND Kind, PBOOLEAN Protected)
{
    PFILE_LINKS_INFORMATION links = NULL;
    PFILE_LINK_ENTRY_INFORMATION entry;
    FILE_STANDARD_INFORMATION standard;
    ULONG returned = 0, offset, index, available, nameBytes;
    NTSTATUS status;
    *Protected = FALSE;
    status = FltQueryInformationFile(Instance, Object, &standard,
        sizeof(standard), FileStandardInformation, NULL);
    if (!NT_SUCCESS(status) || standard.Directory || standard.NumberOfLinks <= 1) return status;
    if (standard.NumberOfLinks > ALIAS_LIMIT) return STATUS_TOO_MANY_LINKS;
    links = ExAllocatePool2(POOL_FLAG_PAGED, ALIAS_BYTES, ALIAS_TAG);
    if (links == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    status = FltQueryInformationFile(Instance, Object, links, ALIAS_BYTES, FileHardLinkInformation, &returned);
    if (status != STATUS_SUCCESS) goto Exit; /* Never interpret a partial enumeration. */
    if (returned > ALIAS_BYTES || returned < (ULONG)FIELD_OFFSET(FILE_LINKS_INFORMATION, Entry) ||
        links->BytesNeeded == 0 || links->BytesNeeded > ALIAS_BYTES || links->EntriesReturned == 0 ||
        links->EntriesReturned > ALIAS_LIMIT || links->EntriesReturned < standard.NumberOfLinks) {
        status = STATUS_DATA_ERROR; goto Exit;
    }
    offset = FIELD_OFFSET(FILE_LINKS_INFORMATION, Entry);
    for (index = 0; index < links->EntriesReturned; ++index) {
        if (offset > returned || returned - offset < (ULONG)FIELD_OFFSET(FILE_LINK_ENTRY_INFORMATION, FileName)) {
            status = STATUS_DATA_ERROR; goto Exit;
        }
        entry = (PFILE_LINK_ENTRY_INFORMATION)((PUCHAR)links + offset);
        available = returned - offset - FIELD_OFFSET(FILE_LINK_ENTRY_INFORMATION, FileName);
        /* WDK FileNameLength is in WCHARs, unlike rename information. */
        if (entry->FileNameLength == 0 || entry->FileNameLength > available / sizeof(WCHAR) ||
            entry->FileNameLength > SAFEUPLOAD_MAX_PATH_CHARS) {
            status = STATUS_DATA_ERROR; goto Exit;
        }
        nameBytes = entry->FileNameLength * sizeof(WCHAR);
        status = StageAliasEntryProtected(Instance, Volume, entry, Kind, Protected);
        if (!NT_SUCCESS(status) || *Protected) goto Exit;
        if (index + 1 == links->EntriesReturned) {
            if (entry->NextEntryOffset != 0) status = STATUS_DATA_ERROR;
        } else if (entry->NextEntryOffset < FIELD_OFFSET(FILE_LINK_ENTRY_INFORMATION, FileName) + nameBytes ||
            entry->NextEntryOffset > returned - offset || (entry->NextEntryOffset & 7)) {
            status = STATUS_DATA_ERROR; goto Exit;
        } else offset += entry->NextEntryOffset;
    }
Exit:
    ExFreePoolWithTag(links, ALIAS_TAG);
    return status;
}

/* The paging, swap and hibernation files at the volume root cannot be hard links of a protected file (NTFS gives them one link
 * and refuses to open them with the access and sharing a probe asks for: the probe answered STATUS_SHARING_VIOLATION and the
 * create was refused). Matching the three names at the root is exact and needs no file system access. */
static BOOLEAN StageAliasIsVolumeSystemFile(_In_ PFLT_FILE_NAME_INFORMATION Name)
{
    static const UNICODE_STRING files[] = {
        RTL_CONSTANT_STRING(L"\\pagefile.sys"), RTL_CONSTANT_STRING(L"\\swapfile.sys"), RTL_CONSTANT_STRING(L"\\hiberfil.sys") };
    UNICODE_STRING relative;
    ULONG index;
    if (Name->Name.Length <= Name->Volume.Length || Name->Stream.Length > Name->Name.Length - Name->Volume.Length) return FALSE;
    relative.Buffer = (PWCH)((PUCHAR)Name->Name.Buffer + Name->Volume.Length);
    relative.Length = (USHORT)(Name->Name.Length - Name->Volume.Length - Name->Stream.Length);
    relative.MaximumLength = relative.Length;
    for (index = 0; index < RTL_NUMBER_OF(files); ++index)
        if (RtlEqualUnicodeString(&relative, &files[index], TRUE)) return TRUE;
    return FALSE;
}

NTSTATUS SafeUploadStageCheckNamedAliases(_In_ PFLT_INSTANCE Instance,
    _In_ PFLT_FILE_NAME_INFORMATION Name, _In_ SAFEUPLOAD_VOLUME_KIND Kind, _Out_ PBOOLEAN Protected)
{
    HANDLE handle = NULL;
    PFILE_OBJECT object = NULL;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io = {0};
    FLT_FILESYSTEM_TYPE fs;
    UNICODE_STRING path = Name->Name;
    NTSTATUS status;
    PAGED_CODE();
    *Protected = FALSE;
    if (IoGetTopLevelIrp() != NULL) return STATUS_ACCESS_DENIED;
    status = FltGetFileSystemType(Instance, &fs);
    if (!NT_SUCCESS(status) || fs != FLT_FSTYPE_NTFS) return status;
    if (StageAliasIsVolumeSystemFile(Name)) return STATUS_SUCCESS;
    /* Classify the base object even when an outside alias names an ADS. */
    if (Name->Stream.Length > path.Length) return STATUS_OBJECT_NAME_INVALID;
    path.Length -= Name->Stream.Length; path.MaximumLength = path.Length;
    InitializeObjectAttributes(&attributes, &path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = FltCreateFileEx2(SafeUploadData.Filter, Instance, &handle, &object,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attributes, &io, NULL, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_COMPLETE_IF_OPLOCKED | FILE_OPEN_REPARSE_POINT,
        NULL, 0, IO_IGNORE_SHARE_ACCESS_CHECK | IO_STOP_ON_SYMLINK, NULL);
    /* FILE_OPEN_REPARSE_POINT: the probe wants the object's identity and link count, not what a reparse point resolves to.
     * Following it failed with STATUS_IO_REPARSE_TAG_NOT_HANDLED for every app-execution alias under WindowsApps (and with
     * STATUS_STOPPED_ON_SYMLINK for a symbolic link), so any writer open of such a name outside every scope was refused. A
     * create that really goes through a symbolic link re-enters this filter under the target's name and is classified there. */
    if (status == STATUS_STOPPED_ON_SYMLINK && io.Information != 0) ExFreePool((PVOID)io.Information);
    if (status == STATUS_SUCCESS) status = StageAliasQuery(Instance, object, &Name->Volume, Kind, Protected);
    else if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND ||
        status == STATUS_FILE_IS_A_DIRECTORY) status = STATUS_SUCCESS;
    if (object != NULL) ObDereferenceObject(object);
    if (handle != NULL) FltClose(handle);
    return status;
}

NTSTATUS SafeUploadStageCheckObjectAliases(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT Object,
    _In_ PUNICODE_STRING Volume, _In_ SAFEUPLOAD_VOLUME_KIND Kind, _Out_ PBOOLEAN Protected)
{
    FILE_STANDARD_INFORMATION standard;
    FILE_INTERNAL_INFORMATION identity;
    HANDLE handle = NULL;
    PFILE_OBJECT queried = NULL;
    FLT_FILESYSTEM_TYPE fs;
    NTSTATUS status;
    PAGED_CODE();
    *Protected = FALSE;
    if (IoGetTopLevelIrp() != NULL) return STATUS_ACCESS_DENIED;
    status = FltGetFileSystemType(Instance, &fs);
    if (!NT_SUCCESS(status) || fs != FLT_FSTYPE_NTFS) return status;
    status = FltQueryInformationFile(Instance, Object, &standard, sizeof(standard), FileStandardInformation, NULL);
    if (!NT_SUCCESS(status) || standard.Directory || standard.NumberOfLinks <= 1) return status;
    status = FltQueryInformationFile(Instance, Object, &identity, sizeof(identity), FileInternalInformation, NULL);
    if (!NT_SUCCESS(status)) return status;
    /* Open the actual source object by ID with READ_ATTRIBUTES. Looking up its
     * current opened path could instead inspect a replacement object. */
    status = StageAliasOpenId(Instance, Volume, identity.IndexNumber.QuadPart, FALSE, &handle, &queried);
    if (status == STATUS_SUCCESS) status = StageAliasQuery(Instance, queried, Volume, Kind, Protected);
    if (queried != NULL) ObDereferenceObject(queried);
    if (handle != NULL) FltClose(handle);
    return status;
}
