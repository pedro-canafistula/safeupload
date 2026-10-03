/* Mapped-writable stream fence (feature build only).
 *
 * A writable section that predates the filter or a policy scope never passes
 * through an admitted file object, so staging cannot redirect its writes.
 * A scan of the protected scopes finds streams whose section object pointers
 * report user-writable mapped views (documented MmDoesFileHaveUserWritableReferences
 * on a file object opened below this instance, or through the volume stack before
 * the filter is attached, with attribute access only) and registers them.
 * Registered streams are fenced in two ways:
 *   - an unowned paging write to the stream's SectionObjectPointer is refused,
 *     so the old view cannot change the protected bytes;
 *   - a protected open of the stream's name is refused, so no other reader is
 *     served the dirty mapped bytes through the filter.
 * Both checks are in memory only: no I/O in the create or write path. Scans run at
 * PASSIVE_LEVEL with special kernel APCs enabled (the documented requirement of
 * FltQueryDirectoryFile and FltCreateFileEx2), serialized by a KMUTEX, never a fast mutex.
 * The fence is ONE immutable table installed atomically: readers of the pointer table
 * (spin lock) and of the name table (push lock) can never see two generations.
 * A scan that cannot prove its scope fails closed: a policy update is rejected, a load is
 * refused, and the previous fence stays.
 *
 * Lifecycle: an entry is dropped ONLY after its dirty pages are gone. "No user-writable mapping
 * remains" is not enough: the Memory Manager still holds the pages the old view dirtied and writes
 * them back later, so refusing writeback only until the next refresh just delays the leak (observed
 * on the debuggee, fence5-lifecycle-verifier). A refresh therefore carries every old entry over
 * unless the stream has no user-writable reference and the documented CcPurgeCacheSection, called
 * with the file held exclusively, discarded its cached and modified pages. A purge that cannot
 * complete keeps the entry (fail closed); the unload guard refuses while any entry remains.
 *
 * Not covered by this slice, and not claimed: removable/network scopes, writable mappings
 * created after a scan through a handle that predates it, mappings of alternate data streams,
 * hard-link alias readers outside the protected prefix, volumes attached after load. */
#include "Stage.h"

#if SAFEUPLOAD_STAGING_PROTOTYPE

#define FENCE_TAG 'fUpS'
#define FENCE_HASH_SLOTS 256          /* power of two; at most FENCE_MAX_STREAMS entries */
#define FENCE_MAX_STREAMS 64
#define FENCE_NAME_CAPACITY 64
#define FENCE_NAME_CHARS 300
#define FENCE_PATH_CHARS 520
#define FENCE_MAX_DEPTH 12
#define FENCE_MAX_DIRECTORIES 512
#define FENCE_MAX_FILES 8192
#define FENCE_DIRECTORY_BUFFER 8192
#define FENCE_MAX_VOLUMES 16
#define FENCE_VOLUME_NAME_CHARS 256
#define FENCE_MAPPED_BIT ((ULONG_PTR)1)

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SafeUploadStageFenceInitialize)
#pragma alloc_text(PAGE, SafeUploadStageFenceFree)
#pragma alloc_text(PAGE, SafeUploadStageFenceRefresh)
#pragma alloc_text(PAGE, SafeUploadStageFencePrepareUnload)
#pragma alloc_text(PAGE, SafeUploadStageFenceTransitionBegin)
#pragma alloc_text(PAGE, SafeUploadStageFenceTransitionEnd)
#endif

/* The installed fence: immutable once published. Slots hold a section pointer, bit 0 set when the
 * stream was mapped writable at the scan. Only mapped streams are registered. */
typedef struct _FENCE_TABLE {
    ULONG StreamCount;
    ULONG NameCount;
    ULONG_PTR Slots[FENCE_HASH_SLOTS];
    PFILE_OBJECT Objects[FENCE_MAX_STREAMS];            /* referenced: keeps each stream (and its pointers) alive */
    PFLT_VOLUME StreamVolume[FENCE_MAX_STREAMS];        /* identity only (never dereferenced): the volume a stream lives on */
    USHORT NameBytes[FENCE_NAME_CAPACITY];
    USHORT NameStream[FENCE_NAME_CAPACITY];             /* index into Objects of the stream the name belongs to */
    WCHAR Names[FENCE_NAME_CAPACITY][FENCE_NAME_CHARS];
} FENCE_TABLE, *PFENCE_TABLE;

typedef struct _FENCE_VOLUME {
    PFLT_VOLUME Volume;
    PFLT_INSTANCE Instance;                             /* NULL before the filter is attached to the volume */
    UNICODE_STRING Name;
    WCHAR NameBuffer[FENCE_VOLUME_NAME_CHARS];
} FENCE_VOLUME, *PFENCE_VOLUME;

typedef struct _FENCE_SCAN {
    NTSTATUS Failure;
    ULONG FailureLine;                 /* source line of the first failure, for diagnosis */
    ULONG Directories;
    ULONG Files;
    ULONG ReparseSkipped;
    ULONG VolumeScopesSkipped;
    ULONG VolumeCount;
    PFENCE_TABLE Table;                /* being built */
    PFLT_VOLUME CurrentVolume;         /* volume being scanned, recorded with each registered stream */
    FENCE_VOLUME Volumes[FENCE_MAX_VOLUMES];
} FENCE_SCAN, *PFENCE_SCAN;

static KMUTEX FenceRefreshMutex;
static KSPIN_LOCK FenceSopLock;
static EX_PUSH_LOCK FenceNameLock;
static PFENCE_TABLE FenceTable;                         /* both locks held to replace; either to read */
static BOOLEAN FenceInitialized;
static volatile LONG FenceGeneration;
static volatile LONG FenceLastStatus;
static volatile LONG FenceFailureLine;
static volatile LONG FenceEntryCount;
static volatile LONG FenceNameCount;
static volatile LONG64 FenceRefreshStarted;
static volatile LONG64 FenceRefreshCompleted;
static volatile LONG64 FenceRefreshFailed;
static volatile LONG64 FencePagingDenied;
static volatile LONG64 FenceOpensRefused;
static volatile LONG64 FenceDirectories;
static volatile LONG64 FenceFiles;
static volatile LONG64 FenceReparseSkipped;
static volatile LONG64 FenceVolumeScopesSkipped;
static volatile LONG64 FenceStreamsReleased;
static volatile LONG64 FenceReleaseRefused;
static volatile LONG64 FenceSectionsDenied;
static volatile LONG64 FenceSectionUnresolved;
static volatile LONG64 FenceFsctlUnresolved;
static volatile LONG64 FenceLateRefreshQueued;
static volatile LONG FenceLateRefreshPending;

static VOID FenceScanDirectory(_In_ PFENCE_SCAN Scan, _In_opt_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING Directory, _In_ ULONG Depth);

#define FENCE_FAIL(S, ST) FenceFail((S), (ULONG)__LINE__, (ST))

static VOID FenceFail(_In_ PFENCE_SCAN Scan, _In_ ULONG Line, _In_ NTSTATUS Status)
{
    if (NT_SUCCESS(Scan->Failure)) {
        Scan->Failure = Status;
        Scan->FailureLine = Line;
    }
}

static ULONG FenceHash(_In_ ULONG_PTR Sop)
{
    return (ULONG)(((Sop >> 4) * 2654435761u) & (FENCE_HASH_SLOTS - 1));
}

/* A fixed local NTFS volume. Works for a volume the filter is not attached to (and before it is
 * started), unlike the instance context. */
static BOOLEAN FenceVolumeIsFixedNtfs(_In_ PFLT_VOLUME Volume)
{
    FLT_VOLUME_PROPERTIES properties;
    FLT_FILESYSTEM_TYPE type;
    ULONG returned = 0;
    NTSTATUS status = FltGetVolumeProperties(Volume, &properties, sizeof(properties), &returned);

    if (NT_ERROR(status)) return FALSE;                 /* STATUS_BUFFER_OVERFLOW is the normal, usable case */
    if (properties.DeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM) return FALSE;
    if (FlagOn(properties.DeviceCharacteristics, FILE_REMOVABLE_MEDIA)) return FALSE;
    return NT_SUCCESS(FltGetFileSystemType(Volume, &type)) && type == FLT_FSTYPE_NTFS;
}

/* Opens below Instance (through the volume stack when Instance is NULL, before the filter is attached)
 * with share checks ignored: scanning must never be refused or delayed by another opener, and
 * attribute/list access conflicts with nothing. */
static NTSTATUS FenceOpen(_In_opt_ PFLT_INSTANCE Instance, _In_ PCUNICODE_STRING Path,
    _In_ ACCESS_MASK Access, _In_ BOOLEAN Directory, _Out_ PHANDLE Handle, _Out_ PFILE_OBJECT *Object)
{
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io = {0};
    UNICODE_STRING name = *Path;

    *Handle = NULL;
    *Object = NULL;
    InitializeObjectAttributes(&attributes, &name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    return FltCreateFileEx2(SafeUploadData.Filter, Instance, Handle, Object, Access, &attributes, &io,
        NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
        (Directory ? FILE_DIRECTORY_FILE : FILE_NON_DIRECTORY_FILE) | FILE_SYNCHRONOUS_IO_NONALERT |
            FILE_OPEN_REPARSE_POINT | FILE_COMPLETE_IF_OPLOCKED,
        NULL, 0, IO_IGNORE_SHARE_ACCESS_CHECK, NULL);
}

static NTSTATUS FenceQueryDirectory(_In_opt_ PFLT_INSTANCE Instance, _In_ HANDLE Handle, _In_ PFILE_OBJECT Object,
    _Out_writes_bytes_(Length) PVOID Buffer, _In_ ULONG Length, _In_ BOOLEAN Restart, _Out_ PULONG Returned)
{
    IO_STATUS_BLOCK io = {0};
    NTSTATUS status;

    *Returned = 0;
    if (Instance != NULL) {
        return FltQueryDirectoryFile(Instance, Object, Buffer, Length, FileIdBothDirectoryInformation,
            FALSE, NULL, Restart, Returned);
    }
    status = ZwQueryDirectoryFile(Handle, NULL, NULL, NULL, &io, Buffer, Length, FileIdBothDirectoryInformation,
        FALSE, NULL, Restart);
    if (NT_SUCCESS(status)) *Returned = (ULONG)io.Information;
    return status;
}

static ULONG FenceFindStream(_In_ PFENCE_TABLE Table, _In_ PSECTION_OBJECT_POINTERS Sop)
{
    ULONG index;

    for (index = 0; index < Table->StreamCount; index += 1) {
        if (Table->Objects[index]->SectionObjectPointer == Sop) return index;
    }
    return MAXULONG;
}

/* Adds a stream to the table being built. Takes ownership of the file object reference ONLY on success
 * (the caller dereferences it on MAXULONG). */
static ULONG FenceAddStream(_In_ PFENCE_SCAN Scan, _In_ PFILE_OBJECT Object, _In_ PSECTION_OBJECT_POINTERS Sop,
    _In_opt_ PFLT_VOLUME Volume)
{
    PFENCE_TABLE table = Scan->Table;
    ULONG slot, probes, index;

    if (((ULONG_PTR)Sop & FENCE_MAPPED_BIT) != 0) { FENCE_FAIL(Scan, STATUS_DATATYPE_MISALIGNMENT); return MAXULONG; }
    if (table->StreamCount >= FENCE_MAX_STREAMS) { FENCE_FAIL(Scan, STATUS_INSUFFICIENT_RESOURCES); return MAXULONG; }
    for (probes = 0, slot = FenceHash((ULONG_PTR)Sop); probes < FENCE_HASH_SLOTS;
         probes += 1, slot = (slot + 1) & (FENCE_HASH_SLOTS - 1)) {
        if ((table->Slots[slot] & ~FENCE_MAPPED_BIT) == 0) break;
    }
    if (probes >= FENCE_HASH_SLOTS) { FENCE_FAIL(Scan, STATUS_INSUFFICIENT_RESOURCES); return MAXULONG; }
    index = table->StreamCount;
    table->Slots[slot] = (ULONG_PTR)Sop | FENCE_MAPPED_BIT;
    table->Objects[index] = Object;
    table->StreamVolume[index] = Volume;
    table->StreamCount += 1;
    return index;
}

/* Quarantines one name of a stream (every hard link found inside the scope is quarantined too). */
static VOID FenceAddName(_In_ PFENCE_SCAN Scan, _In_ ULONG Stream, _In_ PCUNICODE_STRING Path)
{
    PFENCE_TABLE table = Scan->Table;
    UNICODE_STRING entry;
    ULONG index;

    if (Path->Length > FENCE_NAME_CHARS * sizeof(WCHAR)) { FENCE_FAIL(Scan, STATUS_NAME_TOO_LONG); return; }
    for (index = 0; index < table->NameCount; index += 1) {
        entry.Buffer = table->Names[index];
        entry.Length = entry.MaximumLength = table->NameBytes[index];
        if (RtlEqualUnicodeString(Path, &entry, TRUE)) return;                  /* already quarantined */
    }
    if (table->NameCount >= FENCE_NAME_CAPACITY) { FENCE_FAIL(Scan, STATUS_INSUFFICIENT_RESOURCES); return; }
    table->NameBytes[table->NameCount] = Path->Length;
    table->NameStream[table->NameCount] = (USHORT)Stream;
    RtlCopyMemory(table->Names[table->NameCount], Path->Buffer, Path->Length);
    table->NameCount += 1;
}

/* Registers a mapped-writable stream found by the scan. Takes ownership of the file object reference. */
static VOID FenceRegister(_In_ PFENCE_SCAN Scan, _In_ PFILE_OBJECT Object, _In_ PSECTION_OBJECT_POINTERS Sop,
    _In_ PCUNICODE_STRING Path)
{
    ULONG stream = FenceFindStream(Scan->Table, Sop);

    if (stream == MAXULONG) {
        stream = FenceAddStream(Scan, Object, Sop, Scan->CurrentVolume);
        if (stream == MAXULONG) { ObDereferenceObject(Object); return; }
    } else {
        ObDereferenceObject(Object);                    /* the stream is already registered under another name */
    }
    FenceAddName(Scan, stream, Path);
}

/* Discards the cached and modified pages of a stream that no longer has a user-writable reference.
 * Returns TRUE only when they are gone (the stream may be released); FALSE keeps it fenced. The file
 * is held exclusively (FsRtlAcquireFileExclusive, the documented precondition of CcPurgeCacheSection,
 * which also blocks a new section from being created meanwhile) and the writable reference is checked
 * again under that hold. */
static BOOLEAN FenceTryRelease(_In_ PFILE_OBJECT Object)
{
    PSECTION_OBJECT_POINTERS sop = Object->SectionObjectPointer;
    BOOLEAN purged = FALSE;

    if (sop == NULL) return TRUE;
    if (MmDoesFileHaveUserWritableReferences(sop) != 0) return FALSE;
    FsRtlEnterFileSystem();
    FsRtlAcquireFileExclusive(Object);
    if (MmDoesFileHaveUserWritableReferences(sop) == 0) purged = CcPurgeCacheSection(sop, NULL, 0, 0);
    FsRtlReleaseFile(Object);
    FsRtlExitFileSystem();
    return purged;
}

/* Carries every entry of the installed table into the table being built, unless its dirty pages could
 * be discarded. Runs with the refresh mutex held (the installed table only changes under it). */
static VOID FenceCarryOver(_In_ PFENCE_SCAN Scan)
{
    PFENCE_TABLE old = FenceTable;
    UNICODE_STRING name;
    ULONG index, nameIndex;

    if (old == NULL) return;
    for (index = 0; index < old->StreamCount && NT_SUCCESS(Scan->Failure); index += 1) {
        PFILE_OBJECT object = old->Objects[index];
        PSECTION_OBJECT_POINTERS sop = object->SectionObjectPointer;
        ULONG target;

        if (sop == NULL) { InterlockedIncrement64(&FenceStreamsReleased); continue; }     /* no section: nothing to protect */
        target = FenceFindStream(Scan->Table, sop);
        if (target == MAXULONG) {                       /* not mapped writable now: release only after a purge */
            if (FenceTryRelease(object)) { InterlockedIncrement64(&FenceStreamsReleased); continue; }
            InterlockedIncrement64(&FenceReleaseRefused);
            ObReferenceObject(object);
            target = FenceAddStream(Scan, object, sop, old->StreamVolume[index]);
            if (target == MAXULONG) { ObDereferenceObject(object); break; }
        }
        for (nameIndex = 0; nameIndex < old->NameCount && NT_SUCCESS(Scan->Failure); nameIndex += 1) {
            if (old->NameStream[nameIndex] != index) continue;
            name.Buffer = old->Names[nameIndex];
            name.Length = name.MaximumLength = old->NameBytes[nameIndex];
            FenceAddName(Scan, target, &name);
        }
    }
}

static VOID FenceProbeFile(_In_ PFENCE_SCAN Scan, _In_opt_ PFLT_INSTANCE Instance, _In_ PCUNICODE_STRING Path)
{
    HANDLE handle;
    PFILE_OBJECT object;
    NTSTATUS status;

    Scan->Files += 1;
    status = FenceOpen(Instance, Path, FILE_READ_ATTRIBUTES | SYNCHRONIZE, FALSE, &handle, &object);
    if (!NT_SUCCESS(status)) {

        /* A file that vanished during the scan has nothing to prove. Anything else (a sharing or
         * access failure included) is unprovable: fail closed. */
        if (status != STATUS_OBJECT_NAME_NOT_FOUND && status != STATUS_OBJECT_PATH_NOT_FOUND &&
            status != STATUS_FILE_IS_A_DIRECTORY) FENCE_FAIL(Scan, status);
        return;
    }
    if (object->SectionObjectPointer != NULL &&
        MmDoesFileHaveUserWritableReferences(object->SectionObjectPointer) != 0) {
        FenceRegister(Scan, object, object->SectionObjectPointer, Path);     /* consumes the reference */
        object = NULL;
    }
    (VOID)FltClose(handle);
    if (object != NULL) ObDereferenceObject(object);
}

static VOID FenceVisit(_In_ PFENCE_SCAN Scan, _In_opt_ PFLT_INSTANCE Instance, _In_ PCUNICODE_STRING Directory,
    _In_ PFILE_ID_BOTH_DIR_INFORMATION Entry, _In_ ULONG Depth)
{
    UNICODE_STRING name, child;
    PWCHAR buffer;
    ULONG chars;
    BOOLEAN needSeparator;
    NTSTATUS status;

    name.Buffer = Entry->FileName;
    name.Length = name.MaximumLength = (USHORT)Entry->FileNameLength;
    if (name.Length == 0) return;
    if ((name.Length == sizeof(WCHAR) && name.Buffer[0] == L'.') ||
        (name.Length == 2 * sizeof(WCHAR) && name.Buffer[0] == L'.' && name.Buffer[1] == L'.')) return;
    if (FlagOn(Entry->FileAttributes, FILE_ATTRIBUTE_REPARSE_POINT)) { Scan->ReparseSkipped += 1; return; }
    /* "directory", one separator (none when the directory already ends in one, as a volume root does),
     * "name": exactly this many characters, no terminator. */
    needSeparator = (Directory->Length == 0 || Directory->Buffer[Directory->Length / sizeof(WCHAR) - 1] != L'\\');
    chars = ((ULONG)Directory->Length + name.Length) / sizeof(WCHAR);
    if (needSeparator) chars += 1;
    if (chars > FENCE_PATH_CHARS) { FENCE_FAIL(Scan, STATUS_NAME_TOO_LONG); return; }
    buffer = ExAllocatePool2(POOL_FLAG_PAGED, chars * sizeof(WCHAR), FENCE_TAG);
    if (buffer == NULL) { FENCE_FAIL(Scan, STATUS_INSUFFICIENT_RESOURCES); return; }
    child.Buffer = buffer;
    child.Length = 0;
    child.MaximumLength = (USHORT)(chars * sizeof(WCHAR));
    status = RtlAppendUnicodeStringToString(&child, Directory);
    if (NT_SUCCESS(status) && needSeparator) status = RtlAppendUnicodeToString(&child, L"\\");
    if (NT_SUCCESS(status)) status = RtlAppendUnicodeStringToString(&child, &name);
    if (!NT_SUCCESS(status)) {
        FENCE_FAIL(Scan, status);
        ExFreePoolWithTag(buffer, FENCE_TAG);
        return;
    }
    if (FlagOn(Entry->FileAttributes, FILE_ATTRIBUTE_DIRECTORY)) FenceScanDirectory(Scan, Instance, &child, Depth + 1);
    else if (Scan->Files >= FENCE_MAX_FILES) FENCE_FAIL(Scan, STATUS_INSUFFICIENT_RESOURCES);
    else FenceProbeFile(Scan, Instance, &child);
    ExFreePoolWithTag(buffer, FENCE_TAG);
}

static VOID FenceScanDirectory(_In_ PFENCE_SCAN Scan, _In_opt_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING Directory, _In_ ULONG Depth)
{
    HANDLE handle;
    PFILE_OBJECT object;
    PUCHAR buffer;
    BOOLEAN restart = TRUE;
    NTSTATUS status;

    if (!NT_SUCCESS(Scan->Failure)) return;
    if (Depth > FENCE_MAX_DEPTH || Scan->Directories >= FENCE_MAX_DIRECTORIES) {
        FENCE_FAIL(Scan, STATUS_INSUFFICIENT_RESOURCES);
        return;
    }
    Scan->Directories += 1;
    status = FenceOpen(Instance, Directory, FILE_LIST_DIRECTORY | SYNCHRONIZE, TRUE, &handle, &object);
    if (status == STATUS_NOT_A_DIRECTORY && Depth == 0) {

        /* A policy prefix may name a single file: probe it directly. */
        FenceProbeFile(Scan, Instance, Directory);
        return;
    }
    if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND) return;     /* nothing there */
    if (!NT_SUCCESS(status)) { FENCE_FAIL(Scan, status); return; }
    buffer = ExAllocatePool2(POOL_FLAG_PAGED, FENCE_DIRECTORY_BUFFER, FENCE_TAG);
    if (buffer == NULL) { FENCE_FAIL(Scan, STATUS_INSUFFICIENT_RESOURCES); goto Cleanup; }
    for (;;) {
        ULONG returned = 0, offset = 0;

        status = FenceQueryDirectory(Instance, handle, object, buffer, FENCE_DIRECTORY_BUFFER, restart, &returned);
        restart = FALSE;
        if (status == STATUS_NO_MORE_FILES || status == STATUS_NO_SUCH_FILE) break;
        if (!NT_SUCCESS(status)) { FENCE_FAIL(Scan, status); break; }
        for (;;) {
            PFILE_ID_BOTH_DIR_INFORMATION entry = (PFILE_ID_BOTH_DIR_INFORMATION)(buffer + offset);

            if (offset > returned || returned - offset < (ULONG)FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileName) ||
                entry->FileNameLength > 0xFFFE || (entry->FileNameLength & 1) != 0 ||
                entry->FileNameLength > returned - offset - (ULONG)FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileName)) {
                FENCE_FAIL(Scan, STATUS_INFO_LENGTH_MISMATCH);
                break;
            }
            FenceVisit(Scan, Instance, Directory, entry, Depth);
            if (!NT_SUCCESS(Scan->Failure) || entry->NextEntryOffset == 0) break;
            if (entry->NextEntryOffset > returned - offset) { FENCE_FAIL(Scan, STATUS_INFO_LENGTH_MISMATCH); break; }
            offset += entry->NextEntryOffset;
        }
        if (!NT_SUCCESS(Scan->Failure)) break;
    }
Cleanup:
    if (buffer != NULL) ExFreePoolWithTag(buffer, FENCE_TAG);
    (VOID)FltClose(handle);
    ObDereferenceObject(object);
}

/* A volume whose device is gone or not ready cannot hold mapped files: it is skipped, not a scan failure.
 * Any other failure to open its root is unprovable and fails closed. Root names the volume root and ends
 * in a backslash. */
static BOOLEAN FenceVolumeUsable(_In_ PFENCE_SCAN Scan, _In_opt_ PFLT_INSTANCE Instance, _In_ PCUNICODE_STRING Root)
{
    HANDLE handle;
    PFILE_OBJECT object;
    NTSTATUS status = FenceOpen(Instance, Root, FILE_LIST_DIRECTORY | SYNCHRONIZE, TRUE, &handle, &object);

    if (NT_SUCCESS(status)) {
        (VOID)FltClose(handle);
        ObDereferenceObject(object);
        return TRUE;
    }
    if (status == STATUS_NO_SUCH_DEVICE || status == STATUS_DEVICE_NOT_READY || status == STATUS_VOLUME_DISMOUNTED ||
        status == STATUS_NO_MEDIA_IN_DEVICE || status == STATUS_DEVICE_DOES_NOT_EXIST ||
        status == STATUS_UNRECOGNIZED_VOLUME || status == STATUS_FLT_NO_DEVICE_OBJECT ||
        status == STATUS_DEVICE_NOT_CONNECTED || status == STATUS_INVALID_DEVICE_STATE) {
        Scan->VolumeScopesSkipped += 1;
        return FALSE;
    }
    FENCE_FAIL(Scan, status);
    return FALSE;
}

/* Scans <volume>\<Relative>; Relative starts with a backslash. */
static VOID FenceScanUnderVolume(_In_ PFENCE_SCAN Scan, _In_ PFENCE_VOLUME Volume, _In_reads_(RelativeChars) PCWSTR Relative,
    _In_ ULONG RelativeChars)
{
    PWCHAR buffer;
    UNICODE_STRING root, path;
    ULONG nameChars = Volume->Name.Length / sizeof(WCHAR);

    if (nameChars + 1 + RelativeChars > FENCE_PATH_CHARS) { FENCE_FAIL(Scan, STATUS_NAME_TOO_LONG); return; }
    buffer = ExAllocatePool2(POOL_FLAG_PAGED, (nameChars + 1 + RelativeChars) * sizeof(WCHAR), FENCE_TAG);
    if (buffer == NULL) { FENCE_FAIL(Scan, STATUS_INSUFFICIENT_RESOURCES); return; }
    RtlCopyMemory(buffer, Volume->Name.Buffer, Volume->Name.Length);
    buffer[nameChars] = L'\\';
    root.Buffer = buffer;
    root.Length = root.MaximumLength = (USHORT)((nameChars + 1) * sizeof(WCHAR));
    if (FenceVolumeUsable(Scan, Volume->Instance, &root)) {
        Scan->CurrentVolume = Volume->Volume;
        RtlCopyMemory(buffer + nameChars, Relative, RelativeChars * sizeof(WCHAR));
        path.Buffer = buffer;
        path.Length = path.MaximumLength = (USHORT)((nameChars + RelativeChars) * sizeof(WCHAR));
        FenceScanDirectory(Scan, Volume->Instance, &path, 0);
    }
    ExFreePoolWithTag(buffer, FENCE_TAG);
}

/* One destination prefix, an NT path whose first two components name the volume. */
static VOID FenceScanPrefix(_In_ PFENCE_SCAN Scan, _In_reads_(Chars) PWCHAR Prefix, _In_ ULONG Chars)
{
    UNICODE_STRING path, device, deviceRoot = RTL_CONSTANT_STRING(L"\\Device\\");
    ULONG used = Chars, index, volumeIndex;

    while (used > 0 && used <= Chars && Prefix[used - 1] == L'\\') used -= 1;     /* canonical: no doubled separator in names */
    path.Buffer = Prefix;
    path.Length = path.MaximumLength = (USHORT)(used * sizeof(WCHAR));
    if (!RtlPrefixUnicodeString(&deviceRoot, &path, TRUE)) { Scan->VolumeScopesSkipped += 1; return; }
    for (index = deviceRoot.Length / sizeof(WCHAR); index < Chars && index < used && Prefix[index] != L'\\'; index += 1) {}
    device.Buffer = Prefix;
    device.Length = device.MaximumLength = (USHORT)(index * sizeof(WCHAR));
    for (volumeIndex = 0; volumeIndex < Scan->VolumeCount; volumeIndex += 1) {
        if (RtlEqualUnicodeString(&device, &Scan->Volumes[volumeIndex].Name, TRUE)) {
            if (index >= used) {                              /* the prefix is the volume root: the whole volume is in scope */
                FenceScanUnderVolume(Scan, &Scan->Volumes[volumeIndex], L"\\", 1);
                return;
            }
            FenceScanUnderVolume(Scan, &Scan->Volumes[volumeIndex], Prefix + index, used - index);
            return;
        }
    }
    Scan->VolumeScopesSkipped += 1;                           /* not mounted, or not a fixed local NTFS volume */
}

static VOID FenceReleaseVolumes(_In_ PFENCE_SCAN Scan)
{
    ULONG index;

    for (index = 0; index < Scan->VolumeCount; index += 1) {
        if (Scan->Volumes[index].Instance != NULL) FltObjectDereference(Scan->Volumes[index].Instance);
        if (Scan->Volumes[index].Volume != NULL) FltObjectDereference(Scan->Volumes[index].Volume);
    }
    Scan->VolumeCount = 0;
}

/* Collects every fixed local NTFS volume with its name and, when the filter is attached, its instance. */
static VOID FenceCollectVolumes(_In_ PFENCE_SCAN Scan)
{
    PFLT_VOLUME volumes[FENCE_MAX_VOLUMES] = {0};
    ULONG count = 0, index;
    NTSTATUS status = FltEnumerateVolumes(SafeUploadData.Filter, volumes, FENCE_MAX_VOLUMES, &count);

    if (!NT_SUCCESS(status)) { FENCE_FAIL(Scan, status); return; }      /* includes more volumes than the bound: fail closed */
    for (index = 0; index < count && index < FENCE_MAX_VOLUMES; index += 1) {
        PFENCE_VOLUME record = &Scan->Volumes[Scan->VolumeCount];
        ULONG needed = 0;

        if (volumes[index] == NULL) continue;
        if (!FenceVolumeIsFixedNtfs(volumes[index])) { FltObjectDereference(volumes[index]); continue; }
        record->Name.Buffer = record->NameBuffer;
        record->Name.Length = 0;
        record->Name.MaximumLength = sizeof(record->NameBuffer);
        status = FltGetVolumeName(volumes[index], &record->Name, &needed);
        if (!NT_SUCCESS(status) || record->Name.Length == 0 || (record->Name.Length & 1) != 0) {
            FENCE_FAIL(Scan, NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status);
            FltObjectDereference(volumes[index]);
            continue;
        }
        record->Volume = volumes[index];
        record->Instance = NULL;
        if (!NT_SUCCESS(FltGetVolumeInstanceFromName(SafeUploadData.Filter, volumes[index], NULL, &record->Instance))) {
            record->Instance = NULL;                                     /* not attached yet (before FltStartFiltering) */
        }
        Scan->VolumeCount += 1;
    }
}

static VOID FenceFreeTable(_In_opt_ PFENCE_TABLE Table)
{
    ULONG index;

    if (Table == NULL) return;
    for (index = 0; index < Table->StreamCount; index += 1) {
        if (Table->Objects[index] != NULL) ObDereferenceObject(Table->Objects[index]);
    }
    ExFreePoolWithTag(Table, FENCE_TAG);
}

NTSTATUS SafeUploadStageFenceInitialize(VOID)
{
    PAGED_CODE();
    KeInitializeMutex(&FenceRefreshMutex, 0);
    KeInitializeSpinLock(&FenceSopLock);
    FltInitializePushLock(&FenceNameLock);
    FenceInitialized = TRUE;
    return STATUS_SUCCESS;
}

/* Detaches the installed table under both locks (non-paged helper: it raises IRQL). */
static PFENCE_TABLE FenceDetachTable(VOID)
{
    PFENCE_TABLE table;
    KIRQL irql;

    FltAcquirePushLockExclusive(&FenceNameLock);
    KeAcquireSpinLock(&FenceSopLock, &irql);
    table = FenceTable;
    FenceTable = NULL;
    InterlockedExchange(&FenceEntryCount, 0);
    InterlockedExchange(&FenceNameCount, 0);
    KeReleaseSpinLock(&FenceSopLock, irql);
    FltReleasePushLock(&FenceNameLock);
    return table;
}

VOID SafeUploadStageFenceFree(VOID)
{
    PAGED_CODE();
    if (!FenceInitialized) return;
    KeWaitForSingleObject(&FenceRefreshMutex, Executive, KernelMode, FALSE, NULL);
    FenceInitialized = FALSE;
    FenceFreeTable(FenceDetachTable());
    (VOID)KeReleaseMutex(&FenceRefreshMutex, FALSE);
    FltDeletePushLock(&FenceNameLock);
}

static VOID FenceInstall(_In_ PFENCE_SCAN Scan)
{
    PFENCE_TABLE installing = Scan->Table;                /* the table is non-paged; Scan is PAGED pool */
    PFENCE_TABLE old;
    LONG streams = (LONG)installing->StreamCount;
    LONG names = (LONG)installing->NameCount;
    LONG64 directories = (LONG64)Scan->Directories;
    LONG64 files = (LONG64)Scan->Files;
    LONG64 reparse = (LONG64)Scan->ReparseSkipped;
    LONG64 volumeScopes = (LONG64)Scan->VolumeScopesSkipped;
    KIRQL irql;

    /* Everything is read from the paged scan state BEFORE the locks: touching paged pool at DISPATCH_LEVEL
     * (spin lock held) is a DRIVER_IRQL_NOT_LESS_OR_EQUAL when the page is out. The name lock first, then
     * the spin lock: a creator holding the name lock shared can never see the new section-pointer table
     * with the old names, or the reverse. */
    FltAcquirePushLockExclusive(&FenceNameLock);
    KeAcquireSpinLock(&FenceSopLock, &irql);
    old = FenceTable;
    FenceTable = installing;
    InterlockedExchange(&FenceEntryCount, streams);
    InterlockedExchange(&FenceNameCount, names);
    KeReleaseSpinLock(&FenceSopLock, irql);
    FltReleasePushLock(&FenceNameLock);
    Scan->Table = NULL;                                                 /* installed: no longer the scan's */
    FenceFreeTable(old);
    InterlockedIncrement(&FenceGeneration);
    InterlockedExchange64(&FenceDirectories, directories);
    InterlockedExchange64(&FenceFiles, files);
    InterlockedExchange64(&FenceReparseSkipped, reparse);
    InterlockedExchange64(&FenceVolumeScopesSkipped, volumeScopes);
}

/* Rebuilds the whole fence from the bootstrap scope on every fixed NTFS volume plus the prefixes of the
 * CURRENT policy and of Candidate (their union, so a policy expansion or shrink never leaves a window).
 * Callable before the filter starts. On failure the previous fence stays and the failure is returned. */
NTSTATUS SafeUploadStageFenceRefresh(_In_opt_ const SAFEUPLOAD_POLICY *Candidate)
{
    static const WCHAR bootstrap[] = L"\\SafeUpload\\Escopo Monitorado";
    PFENCE_SCAN scan = NULL;
    PSAFEUPLOAD_SCOPE_COPY current = NULL, candidate = NULL;
    NTSTATUS status;
    ULONG index;

    PAGED_CODE();
    if (!FenceInitialized) return STATUS_DEVICE_NOT_READY;
    KeWaitForSingleObject(&FenceRefreshMutex, Executive, KernelMode, FALSE, NULL);
    if (!FenceInitialized) { (VOID)KeReleaseMutex(&FenceRefreshMutex, FALSE); return STATUS_DEVICE_NOT_READY; }
    InterlockedIncrement64(&FenceRefreshStarted);
    scan = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*scan), FENCE_TAG);                  /* zeroed */
    current = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*current), FENCE_TAG);
    candidate = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*candidate), FENCE_TAG);
    if (scan == NULL || current == NULL || candidate == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        if (scan != NULL) scan->FailureLine = (ULONG)__LINE__;
        goto Finish;
    }
    scan->Failure = STATUS_SUCCESS;
    scan->Table = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(FENCE_TABLE), FENCE_TAG);     /* zeroed */
    if (scan->Table == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; scan->FailureLine = (ULONG)__LINE__; goto Finish; }

    status = SafeUploadPolicyCopyScope(NULL, current);
    if (NT_SUCCESS(status) && Candidate != NULL) status = SafeUploadPolicyCopyScope(Candidate, candidate);
    if (!NT_SUCCESS(status)) { scan->FailureLine = (ULONG)__LINE__; goto Finish; }

    FenceCollectVolumes(scan);
    for (index = 0; index < scan->VolumeCount && NT_SUCCESS(scan->Failure); index += 1) {
        FenceScanUnderVolume(scan, &scan->Volumes[index], bootstrap, (ULONG)(sizeof(bootstrap) / sizeof(WCHAR)) - 1);
    }
    for (index = 0; index < current->Count && NT_SUCCESS(scan->Failure); index += 1) {
        FenceScanPrefix(scan, current->Prefix[index], current->Length[index] / sizeof(WCHAR));
    }
    for (index = 0; index < candidate->Count && NT_SUCCESS(scan->Failure); index += 1) {
        FenceScanPrefix(scan, candidate->Prefix[index], candidate->Length[index] / sizeof(WCHAR));
    }
    if (((current->Flags | candidate->Flags) & (SAFEUPLOAD_POLICY_FLAG_REMOVABLE | SAFEUPLOAD_POLICY_FLAG_NETWORK)) != 0) {
        scan->VolumeScopesSkipped += 1;               /* every file on those volumes is in scope; not scanned here */
    }
    if (NT_SUCCESS(scan->Failure)) FenceCarryOver(scan);
    status = scan->Failure;
    if (NT_SUCCESS(status)) FenceInstall(scan);

Finish:
    if (scan != NULL) {
        FenceReleaseVolumes(scan);
        if (!NT_SUCCESS(status)) InterlockedExchange(&FenceFailureLine, (LONG)scan->FailureLine);
        FenceFreeTable(scan->Table);                 /* NULL once installed; releases references of a failed scan */
        ExFreePoolWithTag(scan, FENCE_TAG);
    }
    if (current != NULL) ExFreePoolWithTag(current, FENCE_TAG);
    if (candidate != NULL) ExFreePoolWithTag(candidate, FENCE_TAG);
    InterlockedExchange(&FenceLastStatus, (LONG)status);
    if (NT_SUCCESS(status)) InterlockedIncrement64(&FenceRefreshCompleted);
    else InterlockedIncrement64(&FenceRefreshFailed);
    (VOID)KeReleaseMutex(&FenceRefreshMutex, FALSE);
    return status;
}

/* Voluntary unload: refresh to release entries whose dirty pages could be purged, then refuse while any
 * stream is still fenced (without the filter its dirty pages or old view would write freely). */
NTSTATUS SafeUploadStageFencePrepareUnload(VOID)
{
    PAGED_CODE();
    if (!FenceInitialized || InterlockedCompareExchange(&FenceEntryCount, 0, 0) == 0) return STATUS_SUCCESS;
    if (!NT_SUCCESS(SafeUploadStageFenceRefresh(NULL))) return STATUS_FLT_DO_NOT_DETACH;
    return InterlockedCompareExchange(&FenceEntryCount, 0, 0) == 0 ? STATUS_SUCCESS : STATUS_FLT_DO_NOT_DETACH;
}

/* A policy transition (pre-swap scan, swap, post-swap scan) holds the refresh mutex end to end, so no other
 * refresh can snapshot the old policy and install after the swap. The mutex is recursive: the refreshes made
 * by the same thread inside the transition re-acquire it. */
BOOLEAN SafeUploadStageFenceTransitionBegin(VOID)
{
    PAGED_CODE();
    if (!FenceInitialized) return FALSE;
    KeWaitForSingleObject(&FenceRefreshMutex, Executive, KernelMode, FALSE, NULL);
    if (!FenceInitialized) { (VOID)KeReleaseMutex(&FenceRefreshMutex, FALSE); return FALSE; }
    return TRUE;
}

VOID SafeUploadStageFenceTransitionEnd(VOID)
{
    PAGED_CODE();
    (VOID)KeReleaseMutex(&FenceRefreshMutex, FALSE);
}

/* Whether any registered stream lives on Volume (an unknown volume counts as a hit). Used to scope the
 * refusal of opens that carry no name. */
BOOLEAN SafeUploadStageFenceVolumeHasEntries(_In_opt_ PFLT_VOLUME Volume)
{
    ULONG index;
    BOOLEAN hit = FALSE;

    if (InterlockedCompareExchange(&FenceEntryCount, 0, 0) == 0) return FALSE;
    FltAcquirePushLockShared(&FenceNameLock);
    if (FenceTable != NULL) {
        for (index = 0; index < FenceTable->StreamCount && index < FENCE_MAX_STREAMS; index += 1) {
            if (Volume == NULL || FenceTable->StreamVolume[index] == Volume || FenceTable->StreamVolume[index] == NULL) { hit = TRUE; break; }
        }
    }
    FltReleasePushLock(&FenceNameLock);
    return hit;
}

BOOLEAN SafeUploadStageFenceIsFenced(_In_opt_ PFILE_OBJECT FileObject)
{
    PSECTION_OBJECT_POINTERS sop;
    KIRQL irql;
    ULONG slot, probes;
    BOOLEAN hit = FALSE;

    if (FileObject == NULL || InterlockedCompareExchange(&FenceEntryCount, 0, 0) == 0) return FALSE;
    sop = FileObject->SectionObjectPointer;
    if (sop == NULL) return FALSE;
    KeAcquireSpinLock(&FenceSopLock, &irql);
    if (FenceTable != NULL) {
        for (probes = 0, slot = FenceHash((ULONG_PTR)sop); probes < FENCE_HASH_SLOTS;
             probes += 1, slot = (slot + 1) & (FENCE_HASH_SLOTS - 1)) {
            ULONG_PTR current = FenceTable->Slots[slot] & ~FENCE_MAPPED_BIT;
            if (current == 0) break;
            if (current == (ULONG_PTR)sop) { hit = TRUE; break; }
        }
    }
    KeReleaseSpinLock(&FenceSopLock, irql);
    return hit;
}

BOOLEAN SafeUploadStageFenceNameQuarantined(_In_ PCUNICODE_STRING NormalizedName)
{
    UNICODE_STRING entry;
    ULONG index;
    BOOLEAN hit = FALSE;

    if (InterlockedCompareExchange(&FenceNameCount, 0, 0) == 0) return FALSE;
    FltAcquirePushLockShared(&FenceNameLock);
    if (FenceTable != NULL) {
        for (index = 0; index < FenceTable->NameCount && index < FENCE_NAME_CAPACITY; index += 1) {
            entry.Buffer = FenceTable->Names[index];
            entry.Length = entry.MaximumLength = FenceTable->NameBytes[index];
            if (RtlEqualUnicodeString(NormalizedName, &entry, TRUE)) { hit = TRUE; break; }
        }
    }
    FltReleasePushLock(&FenceNameLock);
    return hit;
}

BOOLEAN SafeUploadStageFenceHasEntries(VOID)
{
    return InterlockedCompareExchange(&FenceEntryCount, 0, 0) != 0;
}

VOID SafeUploadStageFenceCountOpenRefused(VOID) { InterlockedIncrement64(&FenceOpensRefused); }
VOID SafeUploadStageFenceCountPagingDenied(VOID) { InterlockedIncrement64(&FencePagingDenied); }
VOID SafeUploadStageFenceCountSectionDenied(VOID) { InterlockedIncrement64(&FenceSectionsDenied); }
VOID SafeUploadStageFenceCountSectionUnresolved(VOID) { InterlockedIncrement64(&FenceSectionUnresolved); }
/* A volume the filter attaches to after the load (a manual or late attachment, or a newly mounted volume) may already
 * hold a writable mapping inside a protected scope, which no earlier scan could see. InstanceSetup cannot do file I/O,
 * so it queues one coalesced refresh at PASSIVE_LEVEL. The window between the attachment and the refresh is documented,
 * not closed. */
static VOID FenceLateRefreshRoutine(_In_ PFLT_GENERIC_WORKITEM WorkItem, _In_ PVOID FltObject, _In_opt_ PVOID Context)
{
    UNREFERENCED_PARAMETER(FltObject);
    UNREFERENCED_PARAMETER(Context);
    InterlockedExchange(&FenceLateRefreshPending, 0);
    (VOID)SafeUploadStageFenceRefresh(NULL);
    FltFreeGenericWorkItem(WorkItem);
}

VOID SafeUploadStageFenceQueueRefresh(VOID)
{
    PFLT_GENERIC_WORKITEM item;

    if (!FenceInitialized) return;
    if (InterlockedCompareExchange(&FenceLateRefreshPending, 1, 0) != 0) return;     /* one is already queued */
    item = FltAllocateGenericWorkItem();
    if (item == NULL) { InterlockedExchange(&FenceLateRefreshPending, 0); return; }
    if (!NT_SUCCESS(FltQueueGenericWorkItem(item, SafeUploadData.Filter, FenceLateRefreshRoutine, DelayedWorkQueue, NULL))) {
        FltFreeGenericWorkItem(item);
        InterlockedExchange(&FenceLateRefreshPending, 0);
        return;
    }
    InterlockedIncrement64(&FenceLateRefreshQueued);
}

VOID SafeUploadStageFenceCountFsctlUnresolved(VOID) { InterlockedIncrement64(&FenceFsctlUnresolved); }

VOID SafeUploadStageFenceGetStatus(_Out_ PSAFEUPLOAD_FENCE_STATUS Status)
{
    RtlZeroMemory(Status, sizeof(*Status));
    Status->StructSize = sizeof(*Status);
    Status->Entries = (UINT32)InterlockedCompareExchange(&FenceEntryCount, 0, 0);
    Status->Generation = (UINT32)InterlockedCompareExchange(&FenceGeneration, 0, 0);
    Status->LastStatus = (UINT32)InterlockedCompareExchange(&FenceLastStatus, 0, 0);
    Status->FailureLine = (UINT32)InterlockedCompareExchange(&FenceFailureLine, 0, 0);
    Status->RefreshStarted = (UINT64)InterlockedCompareExchange64(&FenceRefreshStarted, 0, 0);
    Status->RefreshCompleted = (UINT64)InterlockedCompareExchange64(&FenceRefreshCompleted, 0, 0);
    Status->RefreshFailed = (UINT64)InterlockedCompareExchange64(&FenceRefreshFailed, 0, 0);
    Status->PagingWritesDenied = (UINT64)InterlockedCompareExchange64(&FencePagingDenied, 0, 0);
    Status->OpensRefused = (UINT64)InterlockedCompareExchange64(&FenceOpensRefused, 0, 0);
    Status->DirectoriesScanned = (UINT64)InterlockedCompareExchange64(&FenceDirectories, 0, 0);
    Status->FilesScanned = (UINT64)InterlockedCompareExchange64(&FenceFiles, 0, 0);
    Status->ReparseSkipped = (UINT64)InterlockedCompareExchange64(&FenceReparseSkipped, 0, 0);
    Status->VolumeScopesSkipped = (UINT64)InterlockedCompareExchange64(&FenceVolumeScopesSkipped, 0, 0);
    Status->StreamsReleased = (UINT64)InterlockedCompareExchange64(&FenceStreamsReleased, 0, 0);
    Status->ReleaseRefused = (UINT64)InterlockedCompareExchange64(&FenceReleaseRefused, 0, 0);
    Status->SectionsDenied = (UINT64)InterlockedCompareExchange64(&FenceSectionsDenied, 0, 0);
    Status->SectionNameUnresolved = (UINT64)InterlockedCompareExchange64(&FenceSectionUnresolved, 0, 0);
    Status->FsctlUnresolved = (UINT64)InterlockedCompareExchange64(&FenceFsctlUnresolved, 0, 0);
    Status->LateRefreshesQueued = (UINT64)InterlockedCompareExchange64(&FenceLateRefreshQueued, 0, 0);
}

#endif
