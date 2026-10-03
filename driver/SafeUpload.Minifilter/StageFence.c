/* Mapped-writable stream fence (feature build only).
 *
 * A writable section that predates the filter or a policy scope never passes
 * through an admitted file object, so staging cannot redirect its writes.
 * A scan of the protected scopes finds streams whose section object pointers
 * report user-writable mapped views (documented MmDoesFileHaveUserWritableReferences
 * on a file object opened below this instance, or through the volume stack before
 * the filter is attached, with attribute access only) and registers them.
 * Registered streams are fenced in two ways:
 *   - while its fence entry remains installed and the filter stays on the stack, an
 *     unowned paging write to the stream's SectionObjectPointer is refused;
 *   - a protected open of the stream's name is refused, so no other reader is
 *     served the dirty mapped bytes through the filter.
 * These checks do not prove safety after an entry is retired or the filter is detached.
 * Both checks are in memory only: no I/O in the create or write path. Scans run at
 * PASSIVE_LEVEL with special kernel APCs enabled (the documented requirement of
 * FltQueryDirectoryFile and FltCreateFileEx2), serialized by a KMUTEX, never a fast mutex.
 * The fence is ONE immutable table installed atomically: readers of the pointer table
 * (spin lock) and of the name table (push lock) can never see two generations.
 * A scan that cannot prove its scope fails closed: a policy update is rejected, a load is
 * refused, and the previous fence stays. Once filtering, a failed scan quarantines covered fixed
 * local NTFS volumes for protected-name opens; it does not deny paging writes for unrelated streams.
 *
 * Lifecycle is unresolved. "No user-writable mapping remains" is not enough: the Memory Manager may
 * still hold dirty pages and write them back later. CcPurgeCacheSection does not purge mapped files
 * and requires exclusive file ownership, but FsRtlAcquireFileExclusive is reserved for system use;
 * this minifilter has no documented supported mechanism to establish that ownership. A successful
 * purge would also not prove that an unmapped but retained section handle cannot create a later view.
 * Do not treat the current FenceTryRelease path as qualified. The unload guard refuses while entries remain.
 *
 * Not covered by this slice, and not claimed: removable/network scopes, writable mappings
 * created after a scan through a handle that predates it, mappings of alternate data streams,
 * or hard-link alias readers outside the protected prefix. Late attachment still has an open
 * admission-to-refresh window; the queued scan and unload gate do not close that window. InstanceSetup
 * does not synchronously wait for the scan because Filter Manager warns against thread synchronization
 * or IPC in that callback. Feature-build manual detach is refused unconditionally; automatic/mandatory
 * teardown and volume dismount cannot be vetoed by QueryTeardown. */
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
#define FENCE_MAX_QUARANTINED_VOLUMES (FENCE_MAX_VOLUMES + 1)
#define FENCE_MAX_SCAN_VOLUMES (FENCE_MAX_VOLUMES + FENCE_MAX_QUARANTINED_VOLUMES)
#define FENCE_VOLUME_NAME_CHARS 256
#define FENCE_RETRY_INITIAL_SECONDS 1
#define FENCE_RETRY_MAX_SECONDS 60
#define FENCE_MAPPED_BIT ((ULONG_PTR)1)

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SafeUploadStageFenceInitialize)
#pragma alloc_text(PAGE, SafeUploadStageFenceFree)
#pragma alloc_text(PAGE, SafeUploadStageFenceRefresh)
#pragma alloc_text(PAGE, SafeUploadStageFencePrepareUnload)
#pragma alloc_text(PAGE, SafeUploadStageFenceTryCommitUnload)
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
    PFLT_VOLUME StreamVolume[FENCE_MAX_STREAMS];        /* table-owned reference: stable volume identity while installed */
    USHORT NameBytes[FENCE_NAME_CAPACITY];
    USHORT NameStream[FENCE_NAME_CAPACITY];             /* index into Objects of the stream the name belongs to */
    WCHAR Names[FENCE_NAME_CAPACITY][FENCE_NAME_CHARS];
} FENCE_TABLE, *PFENCE_TABLE;

typedef struct _FENCE_VOLUME {
    PFLT_VOLUME Volume;
    PFLT_INSTANCE Instance;                             /* NULL before the filter is attached to the volume */
    BOOLEAN ScanRequired;                               /* false only after positively classifying it out of scope */
    BOOLEAN Enumerated;                                 /* true only when returned by this exact volume snapshot */
    BOOLEAN Detached;                                   /* positive live storage-stack query; never a root-error inference */
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
    ULONG CandidateReparseSkipped;
    ULONG CandidateVolumeScopesSkipped;
    ULONG VolumeCount;
    ULONG QuarantineGeneration;
    BOOLEAN EnumerationSucceeded;
    BOOLEAN CandidateScopeActive;
    BOOLEAN CoverageRejected;
    PFENCE_TABLE Table;                /* being built */
    PFLT_VOLUME CurrentVolume;         /* volume being scanned, recorded with each registered stream */
    PFLT_VOLUME FailureVolume;         /* borrowed from this scan or trigger; valid until scan release */
    FENCE_VOLUME Volumes[FENCE_MAX_SCAN_VOLUMES];
} FENCE_SCAN, *PFENCE_SCAN;

static KMUTEX FenceRefreshMutex;
static KSPIN_LOCK FenceSopLock;
static KSPIN_LOCK FenceRetryLock;
static KEVENT FenceLateRefreshIdle;
static KTIMER FenceRetryTimer;
static KDPC FenceRetryDpc;
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
static DECLSPEC_ALIGN(8) volatile LONG64 FenceLateControl;
static volatile LONG FenceRefreshInFlight;
static volatile LONG FenceRetryPending;
static volatile LONG FenceRetryTimerArmed;
static volatile LONG FenceRetryStopping;
static volatile LONG FenceRetryEnabled;
static volatile LONG FenceSetupInFlight;
static volatile LONG FenceLateAttachOutstanding;
static volatile LONG FenceQuarantineGeneration; /* FenceSopLock */
static volatile LONG FenceQuarantineGlobalSticky; /* FenceSopLock; only unload clears an untracked identity */
static ULONG FenceRetryDelaySeconds;
static PETHREAD volatile FenceTransitionOwner;

typedef struct _FENCE_QUARANTINE {
    PFLT_VOLUME Volume;                 /* reference held until a covering refresh or filter teardown */
} FENCE_QUARANTINE;

static FENCE_QUARANTINE FenceQuarantine[FENCE_MAX_QUARANTINED_VOLUMES];
static volatile LONG FenceQuarantineGlobal; /* FenceSopLock */

/* Lock order: the PASSIVE_LEVEL refresh mutex may precede FenceNameLock -> FenceSopLock for publication,
 * or FenceRetryLock -> FenceSopLock while clearing a covered quarantine generation. Retry coordination
 * may nest FenceSopLock for reads/updates (FenceRetryLock -> FenceSopLock). No path acquires the refresh
 * mutex or FenceNameLock while holding FenceRetryLock or FenceSopLock. */

#define FENCE_LATE_GATE_MASK      ((LONG64)0x3)
#define FENCE_LATE_WORK_UNIT      ((LONG64)0x4)
#define FENCE_LATE_GATE_OPEN      ((LONG64)0)
#define FENCE_LATE_GATE_CLOSING   ((LONG64)1)
#define FENCE_LATE_GATE_CLOSED    ((LONG64)2)
#define FENCE_LATE_WORK_COUNT(C)  ((C) & ~FENCE_LATE_GATE_MASK)

_Function_class_(KDEFERRED_ROUTINE)
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
static KDEFERRED_ROUTINE FenceRetryTimerDpc;
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS FenceRefreshInternal(_In_opt_ const SAFEUPLOAD_POLICY *Candidate,
    _In_opt_ PFLT_VOLUME TriggerVolume, _In_ BOOLEAN RequireCompleteCoverage);
static BOOLEAN FenceLateControlReserve(VOID);
static BOOLEAN FenceLateControlReserveAttach(VOID);
static VOID FenceLateControlComplete(VOID);
#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, FenceRefreshInternal)
#endif
static VOID FenceRetryUpdateAfterRefresh(VOID);
static VOID FenceRetryStopForUnload(VOID);
static VOID FenceRetryResume(VOID);
static VOID FenceRetryResetAfterDrain(VOID);
static VOID FenceWaitForLateWorkers(VOID);

static VOID FenceScanDirectory(_In_ PFENCE_SCAN Scan, _In_opt_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING Directory, _In_ ULONG Depth);

#define FENCE_FAIL(S, ST) FenceFail((S), (ULONG)__LINE__, (ST))

static VOID FenceRecordSkippedVolumeScope(_Inout_ PFENCE_SCAN Scan)
{
    Scan->VolumeScopesSkipped += 1;
    if (Scan->CandidateScopeActive) Scan->CandidateVolumeScopesSkipped += 1;
}

static VOID FenceRecordSkippedReparse(_Inout_ PFENCE_SCAN Scan)
{
    Scan->ReparseSkipped += 1;
    if (Scan->CandidateScopeActive) Scan->CandidateReparseSkipped += 1;
}

static VOID FenceFail(_In_ PFENCE_SCAN Scan, _In_ ULONG Line, _In_ NTSTATUS Status)
{
    if (NT_SUCCESS(Scan->Failure)) {
        Scan->Failure = Status;
        Scan->FailureLine = Line;
        Scan->FailureVolume = Scan->CurrentVolume;
    }
}

static ULONG FenceHash(_In_ ULONG_PTR Sop)
{
    return (ULONG)(((Sop >> 4) * 2654435761u) & (FENCE_HASH_SLOTS - 1));
}

/* A fixed local NTFS volume. Works for a volume the filter is not attached to (and before it is
 * started), unlike the instance context. */
static NTSTATUS FenceClassifyVolume(_In_ PFLT_VOLUME Volume, _Out_ PBOOLEAN FixedNtfs)
{
    FLT_VOLUME_PROPERTIES properties;
    FLT_FILESYSTEM_TYPE type;
    ULONG returned = 0;
    NTSTATUS status;

    *FixedNtfs = FALSE;
    status = FltGetVolumeProperties(Volume, &properties, sizeof(properties), &returned);
    if (NT_ERROR(status)) return status;                /* STATUS_BUFFER_OVERFLOW is the normal, usable case */
    if (properties.DeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM ||
        FlagOn(properties.DeviceCharacteristics, FILE_REMOVABLE_MEDIA)) return STATUS_SUCCESS;
    status = FltGetFileSystemType(Volume, &type);
    if (!NT_SUCCESS(status)) return status;
    *FixedNtfs = type == FLT_FSTYPE_NTFS;
    return STATUS_SUCCESS;
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

/* Adds a stream to the table being built. On success the table takes ownership of the supplied file
 * object reference and an independent volume reference; the caller owns both on failure. */
static ULONG FenceAddStream(_In_ PFENCE_SCAN Scan, _In_ PFILE_OBJECT Object, _In_ PSECTION_OBJECT_POINTERS Sop,
    _In_opt_ PFLT_VOLUME Volume)
{
    PFENCE_TABLE table = Scan->Table;
    ULONG slot, probes, index;
    NTSTATUS status;

    if (((ULONG_PTR)Sop & FENCE_MAPPED_BIT) != 0) { FENCE_FAIL(Scan, STATUS_DATATYPE_MISALIGNMENT); return MAXULONG; }
    if (table->StreamCount >= FENCE_MAX_STREAMS) { FENCE_FAIL(Scan, STATUS_INSUFFICIENT_RESOURCES); return MAXULONG; }
    for (probes = 0, slot = FenceHash((ULONG_PTR)Sop); probes < FENCE_HASH_SLOTS;
         probes += 1, slot = (slot + 1) & (FENCE_HASH_SLOTS - 1)) {
        if ((table->Slots[slot] & ~FENCE_MAPPED_BIT) == 0) break;
    }
    if (probes >= FENCE_HASH_SLOTS) { FENCE_FAIL(Scan, STATUS_INSUFFICIENT_RESOURCES); return MAXULONG; }
    if (Volume != NULL) {
        status = FltObjectReference(Volume);
        if (!NT_SUCCESS(status)) { FENCE_FAIL(Scan, status); return MAXULONG; }
    }
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

/* Attempts to discard cached and modified pages before releasing a fence entry. This prototype uses
 * FsRtlAcquireFileExclusive to meet CcPurgeCacheSection's exclusive-file precondition, but Microsoft
 * reserves that routine for system use. The path is unsupported and cannot establish a valid release
 * proof; it also does not rule out a later view from a retained section handle. Keep this routine and
 * its callers explicitly unqualified until a supported lifetime design replaces it. */
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
    if (FlagOn(Entry->FileAttributes, FILE_ATTRIBUTE_REPARSE_POINT)) { FenceRecordSkippedReparse(Scan); return; }
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

/* Detached storage can retain open/mapped file objects. Skip a bootstrap root only after a positive
 * live detached query; preserve installed fences and quarantine. Other unavailable roots remain
 * incomplete coverage. Root names the volume root and ends in a backslash. */
static BOOLEAN FenceVolumeUsable(_In_ PFENCE_SCAN Scan, _Inout_ PFENCE_VOLUME Volume, _In_ PCUNICODE_STRING Root,
    _In_ BOOLEAN Bootstrap)
{
    HANDLE handle;
    PFILE_OBJECT object;
    NTSTATUS status = FenceOpen(Volume->Instance, Root, FILE_LIST_DIRECTORY | SYNCHRONIZE, TRUE, &handle, &object);

    if (NT_SUCCESS(status)) {
        (VOID)FltClose(handle);
        ObDereferenceObject(object);
        return TRUE;
    }
    if (status == STATUS_NO_SUCH_DEVICE || status == STATUS_DEVICE_NOT_READY || status == STATUS_VOLUME_DISMOUNTED ||
        status == STATUS_NO_MEDIA_IN_DEVICE || status == STATUS_DEVICE_DOES_NOT_EXIST ||
        status == STATUS_UNRECOGNIZED_VOLUME || status == STATUS_FLT_NO_DEVICE_OBJECT ||
        status == STATUS_DEVICE_NOT_CONNECTED || status == STATUS_INVALID_DEVICE_STATE) {
        UINT32 flags = 0;
        NTSTATUS volumeStatus = SafeUploadStageVolumeFlags(Volume->Volume, &flags);
        if (volumeStatus == STATUS_SUCCESS && FlagOn(flags, SAFEUPLOAD_VOLUME_DETACHED_FLAG)) {
            Volume->Detached = TRUE;
            Volume->ScanRequired = FALSE;
            if (!Bootstrap) FenceRecordSkippedVolumeScope(Scan);
            return FALSE;
        }
        if (volumeStatus != STATUS_SUCCESS) { FENCE_FAIL(Scan, volumeStatus); return FALSE; }
        FenceRecordSkippedVolumeScope(Scan);
        return FALSE;
    }
    FENCE_FAIL(Scan, status);
    return FALSE;
}

/* Scans <volume>\<Relative>; Relative starts with a backslash. */
static VOID FenceScanUnderVolume(_In_ PFENCE_SCAN Scan, _Inout_ PFENCE_VOLUME Volume, _In_reads_(RelativeChars) PCWSTR Relative,
    _In_ ULONG RelativeChars, _In_ BOOLEAN Bootstrap)
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
    Scan->CurrentVolume = Volume->Volume;
    if (FenceVolumeUsable(Scan, Volume, &root, Bootstrap)) {
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
    ULONG used = Chars, index, volumeIndex, activeIndex = MAXULONG, activeMatches = 0;

    while (used > 0 && used <= Chars && Prefix[used - 1] == L'\\') used -= 1;     /* canonical: no doubled separator in names */
    path.Buffer = Prefix;
    path.Length = path.MaximumLength = (USHORT)(used * sizeof(WCHAR));
    if (!RtlPrefixUnicodeString(&deviceRoot, &path, TRUE)) { FenceRecordSkippedVolumeScope(Scan); return; }
    for (index = deviceRoot.Length / sizeof(WCHAR); index < Chars && index < used && Prefix[index] != L'\\'; index += 1) {}
    device.Buffer = Prefix;
    device.Length = device.MaximumLength = (USHORT)(index * sizeof(WCHAR));
    for (volumeIndex = 0; volumeIndex < Scan->VolumeCount; volumeIndex += 1) {
        if (!Scan->Volumes[volumeIndex].Detached &&
            RtlEqualUnicodeString(&device, &Scan->Volumes[volumeIndex].Name, TRUE)) {
            activeIndex = volumeIndex;
            activeMatches += 1;
        }
    }
    /* Mounted and detached objects may share a device name. Only one active identity
     * establishes coverage; a detached-only or ambiguous active match grants none. */
    if (activeMatches != 1) { FenceRecordSkippedVolumeScope(Scan); return; }
    if (index >= used) {                                      /* the prefix is the volume root */
        FenceScanUnderVolume(Scan, &Scan->Volumes[activeIndex], L"\\", 1, FALSE);
        return;
    }
    FenceScanUnderVolume(Scan, &Scan->Volumes[activeIndex], Prefix + index, used - index, FALSE);
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

/* Quarantine applies at protected-name gates by volume identity. A retained reference prevents pointer reuse;
 * the paging path never consults quarantine. The global bit is reserved for an unknown volume set. */
static __declspec(noinline) VOID FenceQuarantineAll(VOID)
{
    KIRQL irql;
    KeAcquireSpinLock(&FenceSopLock, &irql);
    if (InterlockedExchange(&FenceQuarantineGlobal, TRUE) == FALSE) {
        InterlockedIncrement(&FenceQuarantineGeneration);
    }
    KeReleaseSpinLock(&FenceSopLock, irql);
}

/* Used when a volume identity could not be retained. A later mutable volume snapshot cannot prove
 * that an unremembered volume has gone away, so this protected-name quarantine stays until unload. */
static __declspec(noinline) VOID FenceQuarantineAllSticky(VOID)
{
    KIRQL irql;
    KeAcquireSpinLock(&FenceSopLock, &irql);
    if (InterlockedExchange(&FenceQuarantineGlobal, TRUE) == FALSE) {
        InterlockedIncrement(&FenceQuarantineGeneration);
    }
    if (InterlockedExchange(&FenceQuarantineGlobalSticky, TRUE) == FALSE) {
        InterlockedIncrement(&FenceQuarantineGeneration);
    }
    KeReleaseSpinLock(&FenceSopLock, irql);
}

/* The caller owns Reference on entry. This helper takes only spin locks and can therefore be
 * called while FenceRetryLock serializes attach-failure recording with unload commit. */
static __declspec(noinline) BOOLEAN FenceQuarantineStoreReferenced(_In_ PFLT_VOLUME Volume)
{
    ULONG index, freeIndex = FENCE_MAX_QUARANTINED_VOLUMES;
    BOOLEAN keepReference = FALSE;
    KIRQL irql;

    KeAcquireSpinLock(&FenceSopLock, &irql);
    for (index = 0; index < FENCE_MAX_QUARANTINED_VOLUMES; index += 1) {
        if (FenceQuarantine[index].Volume == Volume) break;
        if (FenceQuarantine[index].Volume == NULL && freeIndex == FENCE_MAX_QUARANTINED_VOLUMES) freeIndex = index;
    }
    if (index < FENCE_MAX_QUARANTINED_VOLUMES) {
        /* Existing entry already owns its reference. */
    } else if (freeIndex < FENCE_MAX_QUARANTINED_VOLUMES) {
        FenceQuarantine[freeIndex].Volume = Volume;
        InterlockedIncrement(&FenceQuarantineGeneration);
        keepReference = TRUE;
    } else {
        /* We cannot remember another identity. Fail closed for protected names and never clear this
         * fallback from a single mutable FltEnumerateVolumes snapshot. */
        if (InterlockedExchange(&FenceQuarantineGlobal, TRUE) == FALSE) {
            InterlockedIncrement(&FenceQuarantineGeneration);
        }
        if (InterlockedExchange(&FenceQuarantineGlobalSticky, TRUE) == FALSE) {
            InterlockedIncrement(&FenceQuarantineGeneration);
        }
    }
    KeReleaseSpinLock(&FenceSopLock, irql);
    return keepReference;
}

static __declspec(noinline) VOID FenceQuarantineVolume(_In_opt_ PFLT_VOLUME Volume)
{
    NTSTATUS status, referenceStatus;
    BOOLEAN stickyBefore;
    BOOLEAN fixedNtfs;

    if (Volume == NULL) return;
    status = FenceClassifyVolume(Volume, &fixedNtfs);
    if (NT_SUCCESS(status) && !fixedNtfs) {
        SafeUploadTrace("not quarantining volume outside fixed NTFS fence coverage\n");
        return;
    }
    referenceStatus = FltObjectReference(Volume);
    if (!NT_SUCCESS(referenceStatus)) {
        FenceQuarantineAllSticky();
        SafeUploadTrace("volume reference failed while quarantining; sticky global protected-name quarantine enabled\n");
        return;
    }
    stickyBefore = InterlockedCompareExchange(&FenceQuarantineGlobalSticky, FALSE, FALSE) != FALSE;
    if (!FenceQuarantineStoreReferenced(Volume)) FltObjectDereference(Volume);
    if (!NT_SUCCESS(status)) {
        SafeUploadTrace("volume classification failed while quarantining; retained identity for retry\n");
        return;
    }
    if (!stickyBefore && InterlockedCompareExchange(&FenceQuarantineGlobalSticky, FALSE, FALSE) != FALSE) {
        SafeUploadTrace("quarantine table overflow; sticky global protected-name quarantine enabled\n");
    }
}

static VOID FenceQuarantineFailedScan(_In_opt_ PFENCE_SCAN Scan, _In_opt_ PFLT_VOLUME TriggerVolume)
{
    ULONG index;

    /* A failed full-table build discards every stream in its partial table, including streams found
     * before the failing directory or carried from the previous generation. Quarantine every fixed
     * NTFS volume this scan enumerated, not only the volume on which the first failure was reported. */
    if (Scan != NULL && Scan->EnumerationSucceeded) {
        for (index = 0; index < Scan->VolumeCount; index += 1) {
            FenceQuarantineVolume(Scan->Volumes[index].Volume);
        }
    } else if (Scan != NULL && Scan->FailureVolume != NULL) {
        FenceQuarantineVolume(Scan->FailureVolume);
    } else if (TriggerVolume == NULL) {
        /* Before enumeration there is no scoped volume set to protect. Preserve fail-open behavior
         * outside policy-protected names, but quarantine protected-name opens until a retry proves
         * coverage. This also covers a scan-state allocation failure before Scan exists. */
        FenceQuarantineAll();
    }
    if (TriggerVolume != NULL) FenceQuarantineVolume(TriggerVolume);
}

static __declspec(noinline) VOID FenceClearQuarantine(VOID)
{
    PFLT_VOLUME release[FENCE_MAX_QUARANTINED_VOLUMES] = {0};
    ULONG index;
    KIRQL irql;

    KeAcquireSpinLock(&FenceSopLock, &irql);
    for (index = 0; index < FENCE_MAX_QUARANTINED_VOLUMES; index += 1) {
        release[index] = FenceQuarantine[index].Volume;
        FenceQuarantine[index].Volume = NULL;
    }
    if (InterlockedExchange(&FenceQuarantineGlobal, FALSE) != FALSE) {
        InterlockedIncrement(&FenceQuarantineGeneration);
    }
    if (InterlockedExchange(&FenceQuarantineGlobalSticky, FALSE) != FALSE) {
        InterlockedIncrement(&FenceQuarantineGeneration);
    }
    KeReleaseSpinLock(&FenceSopLock, irql);
    for (index = 0; index < FENCE_MAX_QUARANTINED_VOLUMES; index += 1) {
        if (release[index] != NULL) FltObjectDereference(release[index]);
    }
}

/* A completed scan can release only identities it enumerated and scanned. The caller checks that
 * no policy scope was skipped; a global quarantine is meaningful only after enumeration succeeded. */
static __declspec(noinline) VOID FenceClearScannedQuarantine(_In_ PFENCE_SCAN Scan)
{
    PFLT_VOLUME release[FENCE_MAX_QUARANTINED_VOLUMES] = {0};
    PFLT_VOLUME scanned[FENCE_MAX_SCAN_VOLUMES] = {0};
    ULONG volumeCount, quarantineGeneration;
    BOOLEAN detachedPresent = FALSE;
    ULONG index, volumeIndex, releaseCount = 0;
    KIRQL irql;

    if (!Scan->EnumerationSucceeded || Scan->VolumeScopesSkipped != 0 || Scan->ReparseSkipped != 0) return;
    /* Scan lives in paged pool. Copy its stable, refresh-mutex-owned identity set before either
     * spin lock raises IRQL; only the stack snapshot may be read while the locks are held. */
    volumeCount = Scan->VolumeCount;
    quarantineGeneration = Scan->QuarantineGeneration;
    for (volumeIndex = 0; volumeIndex < volumeCount; volumeIndex += 1) {
        if (Scan->Volumes[volumeIndex].Detached) detachedPresent = TRUE;
        else scanned[volumeIndex] = Scan->Volumes[volumeIndex].Volume;
    }

    /* Setup admission, late-attach queue ownership, and quarantine insertion use RetryLock. Holding
     * it before SopLock makes clearing a global fallback atomic against a just-admitted setup. */
    KeAcquireSpinLock(&FenceRetryLock, &irql);
    KeAcquireSpinLockAtDpcLevel(&FenceSopLock);
    /* Queue/scan failures may add a quarantine after the remembered set was copied. Keep all
     * quarantine in that generation; the next retry will append and cover the new identity. */
    if ((ULONG)InterlockedCompareExchange(&FenceQuarantineGeneration, 0, 0) != quarantineGeneration) {
        KeReleaseSpinLockFromDpcLevel(&FenceSopLock);
        KeReleaseSpinLock(&FenceRetryLock, irql);
        return;
    }
    for (index = 0; index < FENCE_MAX_QUARANTINED_VOLUMES; index += 1) {
        PFLT_VOLUME quarantined = FenceQuarantine[index].Volume;
        if (quarantined == NULL) continue;
        for (volumeIndex = 0; volumeIndex < volumeCount; volumeIndex += 1) {
            if (scanned[volumeIndex] == quarantined) {
                release[releaseCount++] = quarantined;
                FenceQuarantine[index].Volume = NULL;
                break;
            }
        }
    }
    if (!detachedPresent && InterlockedCompareExchange(&FenceQuarantineGlobalSticky, FALSE, FALSE) == FALSE &&
        InterlockedCompareExchange(&FenceSetupInFlight, 0, 0) == 0 &&
        InterlockedCompareExchange(&FenceLateAttachOutstanding, 0, 0) == 0 &&
        InterlockedExchange(&FenceQuarantineGlobal, FALSE) != FALSE) {
        InterlockedIncrement(&FenceQuarantineGeneration);
    }
    if (releaseCount != 0) InterlockedIncrement(&FenceQuarantineGeneration);
    KeReleaseSpinLockFromDpcLevel(&FenceSopLock);
    KeReleaseSpinLock(&FenceRetryLock, irql);

    for (index = 0; index < releaseCount; index += 1) FltObjectDereference(release[index]);
}

static __declspec(noinline) BOOLEAN FenceVolumeIsQuarantined(_In_opt_ PFLT_VOLUME Volume)
{
    ULONG index;
    KIRQL irql;
    BOOLEAN hit = FALSE;

    KeAcquireSpinLock(&FenceSopLock, &irql);
    hit = InterlockedCompareExchange(&FenceQuarantineGlobal, FALSE, FALSE) != FALSE;
    for (index = 0; !hit && index < FENCE_MAX_QUARANTINED_VOLUMES; index += 1) {
        if (FenceQuarantine[index].Volume != NULL &&
            (Volume == NULL || FenceQuarantine[index].Volume == Volume)) hit = TRUE;
    }
    KeReleaseSpinLock(&FenceSopLock, irql);
    return hit;
}

static BOOLEAN FenceAnyQuarantine(VOID)
{
    return FenceVolumeIsQuarantined(NULL);
}

/* A sticky global quarantine has no retained identity to prove removed. Retry any remembered
 * volume entries once, then stop polling until another scoped entry arrives; the global bit stays. */
static __declspec(noinline) BOOLEAN FenceAnyRetryableQuarantine(VOID)
{
    ULONG index;
    BOOLEAN hit = FALSE;
    KIRQL irql;

    KeAcquireSpinLock(&FenceSopLock, &irql);
    hit = InterlockedCompareExchange(&FenceQuarantineGlobal, FALSE, FALSE) != FALSE &&
        InterlockedCompareExchange(&FenceQuarantineGlobalSticky, FALSE, FALSE) == FALSE;
    for (index = 0; !hit && index < FENCE_MAX_QUARANTINED_VOLUMES; index += 1) {
        if (FenceQuarantine[index].Volume != NULL) hit = TRUE;
    }
    KeReleaseSpinLock(&FenceSopLock, irql);
    return hit;
}

/* Preserve every remembered identity across a mutable FltEnumerateVolumes snapshot. Quarantine owns
 * each source reference; this refresh mutex excludes the only paths that can release those refs while
 * the snapshot is copied, and each appended scan record takes its own reference for cleanup. */
static __declspec(noinline) VOID FenceAppendQuarantinedVolumes(_In_ PFENCE_SCAN Scan)
{
    PFLT_VOLUME remembered[FENCE_MAX_QUARANTINED_VOLUMES] = {0};
    ULONG quarantineGeneration;
    ULONG index, scanIndex, rememberedCount = 0;
    KIRQL irql;

    KeAcquireSpinLock(&FenceSopLock, &irql);
    quarantineGeneration = (ULONG)InterlockedCompareExchange(&FenceQuarantineGeneration, 0, 0);
    for (index = 0; index < FENCE_MAX_QUARANTINED_VOLUMES; index += 1) {
        if (FenceQuarantine[index].Volume != NULL) remembered[rememberedCount++] = FenceQuarantine[index].Volume;
    }
    KeReleaseSpinLock(&FenceSopLock, irql);
    /* The generation and remembered identities came from one locked snapshot. Store into the
     * paged scan only after lowering IRQL; a later insertion still invalidates this generation. */
    Scan->QuarantineGeneration = quarantineGeneration;

    for (index = 0; index < rememberedCount && NT_SUCCESS(Scan->Failure); index += 1) {
        PFENCE_VOLUME record;
        ULONG needed = 0;
        UINT32 flags = 0;
        BOOLEAN fixedNtfs = FALSE;
        NTSTATUS status;
        BOOLEAN present = FALSE;

        for (scanIndex = 0; scanIndex < Scan->VolumeCount; scanIndex += 1) {
            if (Scan->Volumes[scanIndex].Volume == remembered[index]) { present = TRUE; break; }
        }
        if (present) continue;
        if (Scan->VolumeCount >= FENCE_MAX_SCAN_VOLUMES) {
            Scan->CurrentVolume = remembered[index];
            FENCE_FAIL(Scan, STATUS_BUFFER_TOO_SMALL);
            break;
        }
        status = FltObjectReference(remembered[index]);
        if (!NT_SUCCESS(status)) {
            FenceQuarantineAllSticky();
            Scan->CurrentVolume = remembered[index];
            FENCE_FAIL(Scan, status);
            break;
        }

        record = &Scan->Volumes[Scan->VolumeCount];
        record->Volume = remembered[index];
        record->Instance = NULL;
        record->ScanRequired = FALSE;
        record->Enumerated = FALSE;
        record->Detached = FALSE;
        record->Name.Buffer = record->NameBuffer;
        record->Name.Length = 0;
        record->Name.MaximumLength = sizeof(record->NameBuffer);
        Scan->CurrentVolume = remembered[index];
        status = SafeUploadStageVolumeFlags(remembered[index], &flags);
        if (status == STATUS_SUCCESS) {
            record->Detached = (flags & SAFEUPLOAD_VOLUME_DETACHED_FLAG) != 0;
            status = FenceClassifyVolume(remembered[index], &fixedNtfs);
        }
        if (!NT_SUCCESS(status)) {
            Scan->VolumeCount += 1; /* retain the scan reference for FenceReleaseVolumes */
            FENCE_FAIL(Scan, status);
            continue;
        }
        if (!fixedNtfs) {
            /* An active identity positively classified out of scope is covered without scanning.
             * Detached identities retain quarantine even if classification changes. */
            Scan->VolumeCount += 1;
            continue;
        }
        record->ScanRequired = !record->Detached;
        status = FltGetVolumeName(remembered[index], &record->Name, &needed);
        if (!NT_SUCCESS(status) || record->Name.Length == 0 || (record->Name.Length & 1) != 0) {
            Scan->VolumeCount += 1; /* retain the scan reference for FenceReleaseVolumes */
            FenceQuarantineVolume(remembered[index]);
            FENCE_FAIL(Scan, NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status);
            continue;
        }
        if (!NT_SUCCESS(FltGetVolumeInstanceFromName(SafeUploadData.Filter,
                remembered[index], NULL, &record->Instance))) {
            record->Instance = NULL;
        }
        Scan->VolumeCount += 1;
    }
}

static __declspec(noinline) VOID FenceCollectVolumes(_In_ PFENCE_SCAN Scan)
{
    PFLT_VOLUME volumes[FENCE_MAX_VOLUMES] = {0};
    ULONG count = 0, index;
    NTSTATUS status = FltEnumerateVolumes(SafeUploadData.Filter, volumes, FENCE_MAX_VOLUMES, &count);
    BOOLEAN fixedNtfs = FALSE;

    if (!NT_SUCCESS(status) || count > FENCE_MAX_VOLUMES) {
        FenceQuarantineAll(); /* FltEnumerateVolumes failed or exceeded our bound: the volume set is unknown. */
        FENCE_FAIL(Scan, NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status);
        for (index = 0; index < count && index < FENCE_MAX_VOLUMES; index += 1) {
            if (volumes[index] != NULL) FltObjectDereference(volumes[index]);
        }
        return;
    }
    Scan->EnumerationSucceeded = TRUE;
    for (index = 0; index < count; index += 1) {
        PFENCE_VOLUME record = &Scan->Volumes[Scan->VolumeCount];
        ULONG needed = 0;
        UINT32 flags = 0;

        if (volumes[index] == NULL) continue;
        status = SafeUploadStageVolumeFlags(volumes[index], &flags);
        if (status == STATUS_SUCCESS) status = FenceClassifyVolume(volumes[index], &fixedNtfs);
        if (!NT_SUCCESS(status)) {
            Scan->CurrentVolume = volumes[index];
            record->Volume = volumes[index];
            record->Instance = NULL;
            record->ScanRequired = FALSE;
            record->Enumerated = TRUE;
            Scan->VolumeCount += 1;
            FenceQuarantineVolume(volumes[index]);
            FENCE_FAIL(Scan, status);
            continue;
        }
        if (!fixedNtfs) { FltObjectDereference(volumes[index]); continue; }
        Scan->CurrentVolume = volumes[index];
        record->Volume = volumes[index];
        record->Instance = NULL;
        record->Detached = FlagOn(flags, SAFEUPLOAD_VOLUME_DETACHED_FLAG);
        record->ScanRequired = !record->Detached;
        record->Enumerated = TRUE;
        record->Name.Buffer = record->NameBuffer;
        record->Name.Length = 0;
        record->Name.MaximumLength = sizeof(record->NameBuffer);
        status = FltGetVolumeName(volumes[index], &record->Name, &needed);
        if (!NT_SUCCESS(status) || record->Name.Length == 0 || (record->Name.Length & 1) != 0) {
            FenceQuarantineVolume(volumes[index]); /* name failure is local; volume identity is still known */
            FENCE_FAIL(Scan, NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status);
            Scan->VolumeCount += 1; /* retain its reference until FailureVolume has been quarantined */
            continue;
        }
        if (!NT_SUCCESS(FltGetVolumeInstanceFromName(SafeUploadData.Filter, volumes[index], NULL, &record->Instance))) {
            record->Instance = NULL;                                     /* not attached yet (before FltStartFiltering) */
        }
        Scan->VolumeCount += 1;
    }
    if (NT_SUCCESS(Scan->Failure)) FenceAppendQuarantinedVolumes(Scan);
}

static VOID FenceFreeTable(_In_opt_ PFENCE_TABLE Table)
{
    ULONG index;

    if (Table == NULL) return;
    for (index = 0; index < Table->StreamCount; index += 1) {
        if (Table->Objects[index] != NULL) ObDereferenceObject(Table->Objects[index]);
        if (Table->StreamVolume[index] != NULL) FltObjectDereference(Table->StreamVolume[index]);
    }
    ExFreePoolWithTag(Table, FENCE_TAG);
}

NTSTATUS SafeUploadStageFenceInitialize(VOID)
{
    PAGED_CODE();
    KeInitializeMutex(&FenceRefreshMutex, 0);
    KeInitializeSpinLock(&FenceSopLock);
    KeInitializeSpinLock(&FenceRetryLock);
    KeInitializeEvent(&FenceLateRefreshIdle, NotificationEvent, TRUE);
    KeInitializeTimer(&FenceRetryTimer);
    KeInitializeDpc(&FenceRetryDpc, FenceRetryTimerDpc, NULL);
    FltInitializePushLock(&FenceNameLock);
    InterlockedExchange64(&FenceLateControl, FENCE_LATE_GATE_OPEN);
    RtlZeroMemory(FenceQuarantine, sizeof(FenceQuarantine));
    InterlockedExchange(&FenceQuarantineGlobal, FALSE);
    InterlockedExchange(&FenceQuarantineGlobalSticky, FALSE);
    InterlockedExchange(&FenceQuarantineGeneration, 0);
    InterlockedExchange(&FenceRefreshInFlight, 0);
    InterlockedExchange(&FenceRetryPending, FALSE);
    InterlockedExchange(&FenceRetryTimerArmed, FALSE);
    InterlockedExchange(&FenceRetryStopping, FALSE);
    InterlockedExchange(&FenceRetryEnabled, FALSE);
    InterlockedExchange(&FenceSetupInFlight, 0);
    InterlockedExchange(&FenceLateAttachOutstanding, 0);
    FenceRetryDelaySeconds = FENCE_RETRY_INITIAL_SECONDS;
    FenceInitialized = TRUE;
    return STATUS_SUCCESS;
}

/* Detaches the installed table under both locks (non-paged helper: it raises IRQL). */
static __declspec(noinline) PFENCE_TABLE FenceDetachTable(VOID)
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
    FenceRetryStopForUnload();
    FenceWaitForLateWorkers();
    FenceRetryResetAfterDrain();
    KeWaitForSingleObject(&FenceRefreshMutex, Executive, KernelMode, FALSE, NULL);
    FenceInitialized = FALSE;
    FenceFreeTable(FenceDetachTable());
    FenceClearQuarantine();
    (VOID)KeReleaseMutex(&FenceRefreshMutex, FALSE);
    FltDeletePushLock(&FenceNameLock);
}

static __declspec(noinline) VOID FenceInstall(_In_ PFENCE_SCAN Scan)
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
_Use_decl_annotations_
static NTSTATUS FenceRefreshInternal(_In_opt_ const SAFEUPLOAD_POLICY *Candidate,
    _In_opt_ PFLT_VOLUME TriggerVolume, _In_ BOOLEAN RequireCompleteCoverage)
{
    static const WCHAR bootstrap[] = L"\\SafeUpload\\Escopo Monitorado";
    PFENCE_SCAN scan = NULL;
    PSAFEUPLOAD_SCOPE_COPY current = NULL, candidate = NULL;
    NTSTATUS status;
    ULONG index;
    BOOLEAN triggerIncluded = FALSE;

    PAGED_CODE();
    if (!FenceInitialized) return STATUS_DEVICE_NOT_READY;
    InterlockedIncrement(&FenceRefreshInFlight);
    KeWaitForSingleObject(&FenceRefreshMutex, Executive, KernelMode, FALSE, NULL);
    if (!FenceInitialized) {
        (VOID)KeReleaseMutex(&FenceRefreshMutex, FALSE);
        InterlockedDecrement(&FenceRefreshInFlight);
        return STATUS_DEVICE_NOT_READY;
    }
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
    if (NT_SUCCESS(scan->Failure) && TriggerVolume != NULL) {
        for (index = 0; index < scan->VolumeCount; index += 1) {
            if (scan->Volumes[index].Volume == TriggerVolume && scan->Volumes[index].Enumerated) {
                triggerIncluded = TRUE;
                break;
            }
        }
        if (!triggerIncluded) {
            /* FltEnumerateVolumes' set is not stable against concurrent mount/teardown. Do not
             * install a successful generation that omitted the volume whose setup admitted this
             * work item. Keep its identity as the failure target; Finish quarantines it and retry
             * can prove inclusion on a later snapshot. The worker still owns the trigger reference. */
            scan->CurrentVolume = TriggerVolume;
            FENCE_FAIL(scan, STATUS_DEVICE_BUSY);
            SafeUploadTrace("late-attach trigger absent from volume snapshot; refresh deferred for retry\n");
        }
    }
    /* Bootstrap is always a required protected scope. */
    scan->CandidateScopeActive = TRUE;
    for (index = 0; index < scan->VolumeCount && NT_SUCCESS(scan->Failure); index += 1) {
        if (scan->Volumes[index].ScanRequired) {
            FenceScanUnderVolume(scan, &scan->Volumes[index], bootstrap,
                (ULONG)(sizeof(bootstrap) / sizeof(WCHAR)) - 1, TRUE);
        }
    }
    scan->CandidateScopeActive = FALSE;
    for (index = 0; index < current->Count && NT_SUCCESS(scan->Failure); index += 1) {
        FenceScanPrefix(scan, current->Prefix[index], current->Length[index] / sizeof(WCHAR));
    }
    scan->CandidateScopeActive = TRUE;
    for (index = 0; index < candidate->Count && NT_SUCCESS(scan->Failure); index += 1) {
        FenceScanPrefix(scan, candidate->Prefix[index], candidate->Length[index] / sizeof(WCHAR));
    }
    scan->CandidateScopeActive = FALSE;
    if ((current->Flags & (SAFEUPLOAD_POLICY_FLAG_REMOVABLE | SAFEUPLOAD_POLICY_FLAG_NETWORK)) != 0) {
        FenceRecordSkippedVolumeScope(scan);          /* current whole-volume scope is outside fixed-NTFS scan coverage */
    }
    if ((candidate->Flags & (SAFEUPLOAD_POLICY_FLAG_REMOVABLE | SAFEUPLOAD_POLICY_FLAG_NETWORK)) != 0) {
        scan->VolumeScopesSkipped += 1;               /* every candidate file on those volumes is in scope */
        scan->CandidateVolumeScopesSkipped += 1;
    }
    if (NT_SUCCESS(scan->Failure) && Candidate != NULL &&
        (scan->CandidateVolumeScopesSkipped != 0 || scan->CandidateReparseSkipped != 0)) {
        /* This generation is not a proof of the new scope. Preserve the installed fence and reject the
         * policy transition; a successful NTSTATUS from an individual directory is insufficient. */
        scan->CoverageRejected = TRUE;
        FENCE_FAIL(scan, STATUS_NOT_SUPPORTED);
    } else if (NT_SUCCESS(scan->Failure) && RequireCompleteCoverage &&
        (scan->VolumeScopesSkipped != 0 || scan->ReparseSkipped != 0)) {
        /* Candidate-transition and unload-final scans must cover every required scope. */
        scan->CoverageRejected = TRUE;
        FENCE_FAIL(scan, STATUS_NOT_SUPPORTED);
    }
    if (NT_SUCCESS(scan->Failure)) {
        scan->CurrentVolume = NULL; /* carry-over is guarded by the installed fence, not a new volume scan */
        FenceCarryOver(scan);
    }
    status = scan->Failure;
    if (NT_SUCCESS(status)) {
        FenceInstall(scan);
        if (scan->VolumeScopesSkipped == 0) {
            FenceClearScannedQuarantine(scan);
        }
    }

Finish:
    /* A failure before enumeration has no scoped volume set; without an attach trigger it sets the
     * global protected-name quarantine, while a supported trigger scopes quarantine to that volume.
     * Startup still aborts before filtering, policy expansion rejects a failed pre-swap scan, and a
     * later successful retry is required to clear any quarantine created after filtering starts. */
    if (!NT_SUCCESS(status) && (scan == NULL || !scan->CoverageRejected)) {
        FenceQuarantineFailedScan(scan, TriggerVolume);
    }
    if (scan != NULL) {
        FenceReleaseVolumes(scan);
        if (!NT_SUCCESS(status)) {
            InterlockedExchange(&FenceFailureLine, (LONG)scan->FailureLine);
            InterlockedExchange64(&FenceDirectories, scan->Directories);
            InterlockedExchange64(&FenceFiles, scan->Files);
            InterlockedExchange64(&FenceReparseSkipped, scan->ReparseSkipped);
            InterlockedExchange64(&FenceVolumeScopesSkipped, scan->VolumeScopesSkipped);
        }
        FenceFreeTable(scan->Table);                 /* NULL once installed; releases references of a failed scan */
        ExFreePoolWithTag(scan, FENCE_TAG);
    }
    if (current != NULL) ExFreePoolWithTag(current, FENCE_TAG);
    if (candidate != NULL) ExFreePoolWithTag(candidate, FENCE_TAG);
    InterlockedExchange(&FenceLastStatus, (LONG)status);
    if (NT_SUCCESS(status)) InterlockedIncrement64(&FenceRefreshCompleted);
    else InterlockedIncrement64(&FenceRefreshFailed);
    (VOID)KeReleaseMutex(&FenceRefreshMutex, FALSE);
    InterlockedDecrement(&FenceRefreshInFlight);
    /* A policy transition can still own its outer recursive mutex acquisition here. */
    if (KeReadStateMutex(&FenceRefreshMutex)) FenceRetryUpdateAfterRefresh();
    return status;
}

_Use_decl_annotations_
NTSTATUS SafeUploadStageFenceRefresh(_In_opt_ const SAFEUPLOAD_POLICY *Candidate)
{
    BOOLEAN transitionReservation;
    BOOLEAN reservedHere = FALSE;
    NTSTATUS status;

    PAGED_CODE();
    transitionReservation = (PETHREAD)InterlockedCompareExchangePointer(
        (PVOID volatile *)&FenceTransitionOwner, NULL, NULL) == PsGetCurrentThread();
    if (!transitionReservation) {
        if (!FenceLateControlReserve()) {
            status = STATUS_DEVICE_BUSY;
            InterlockedExchange(&FenceLastStatus, (LONG)status);
            SafeUploadTrace("public fence refresh rejected after unload admission closed\n");
            return status;
        }
        reservedHere = TRUE;
    }
    status = FenceRefreshInternal(Candidate, NULL, Candidate != NULL || transitionReservation);
    if (reservedHere) FenceLateControlComplete();
    return status;
}

static LONG64 FenceLateControlRead(VOID)
{
    return InterlockedCompareExchange64(&FenceLateControl, 0, 0);
}

static BOOLEAN FenceLateControlReserve(VOID)
{
    LONG64 oldValue, newValue;
    for (;;) {
        oldValue = FenceLateControlRead();
        if ((oldValue & FENCE_LATE_GATE_MASK) != FENCE_LATE_GATE_OPEN ||
            FENCE_LATE_WORK_COUNT(oldValue) > MAXLONGLONG - FENCE_LATE_WORK_UNIT) return FALSE;
        newValue = oldValue + FENCE_LATE_WORK_UNIT;
        if (InterlockedCompareExchange64(&FenceLateControl, newValue, oldValue) == oldValue) {
            KeClearEvent(&FenceLateRefreshIdle);
            return TRUE;
        }
    }
}

/* InstanceSetup stays nonblocking, but accepts work during CLOSING. That reservation must either be
 * drained before the unload final scan/commit or cause a voluntary unload veto. CLOSED is the only
 * state in which a new setup may be declined; CLOSED is published only by the final unload commit. */
static BOOLEAN FenceLateControlReserveAttach(VOID)
{
    LONG64 oldValue, newValue;
    for (;;) {
        oldValue = FenceLateControlRead();
        if ((oldValue & FENCE_LATE_GATE_MASK) == FENCE_LATE_GATE_CLOSED ||
            FENCE_LATE_WORK_COUNT(oldValue) > MAXLONGLONG - FENCE_LATE_WORK_UNIT) return FALSE;
        newValue = oldValue + FENCE_LATE_WORK_UNIT;
        if (InterlockedCompareExchange64(&FenceLateControl, newValue, oldValue) == oldValue) {
            KeClearEvent(&FenceLateRefreshIdle);
            return TRUE;
        }
    }
}

static VOID FenceLateControlComplete(VOID)
{
    LONG64 oldValue, newValue;
    for (;;) {
        oldValue = FenceLateControlRead();
        if (FENCE_LATE_WORK_COUNT(oldValue) == 0) return;
        newValue = oldValue - FENCE_LATE_WORK_UNIT;
        if (InterlockedCompareExchange64(&FenceLateControl, newValue, oldValue) == oldValue) {
            if (FENCE_LATE_WORK_COUNT(newValue) == 0) KeSetEvent(&FenceLateRefreshIdle, IO_NO_INCREMENT, FALSE);
            return;
        }
    }
}

/* RetryPending covers the timer, its DPC, and its work item. A parked timer owns no late-work unit;
 * the DPC reserves a unit only immediately before it queues the generic work item. */
static VOID FenceRetryArmLocked(VOID)
{
    LARGE_INTEGER dueTime;
    ULONG delay;

    if (InterlockedCompareExchange(&FenceRetryStopping, FALSE, FALSE) != FALSE ||
        InterlockedCompareExchange(&FenceRetryEnabled, FALSE, FALSE) == FALSE ||
        (FenceLateControlRead() & FENCE_LATE_GATE_MASK) != FENCE_LATE_GATE_OPEN ||
        !FenceAnyRetryableQuarantine()) {
        InterlockedExchange(&FenceRetryPending, FALSE);
        InterlockedExchange(&FenceRetryTimerArmed, FALSE);
        if (!FenceAnyRetryableQuarantine()) FenceRetryDelaySeconds = FENCE_RETRY_INITIAL_SECONDS;
        return;
    }
    if (InterlockedCompareExchange(&FenceRetryTimerArmed, FALSE, FALSE) != FALSE) return;

    delay = FenceRetryDelaySeconds;
    if (delay == 0) delay = FENCE_RETRY_INITIAL_SECONDS;
    dueTime.QuadPart = -((LONGLONG)delay * 10 * 1000 * 1000);
    InterlockedExchange(&FenceRetryPending, TRUE);
    InterlockedExchange(&FenceRetryTimerArmed, TRUE);
    (VOID)KeSetTimer(&FenceRetryTimer, dueTime, &FenceRetryDpc);
    FenceRetryDelaySeconds = delay >= FENCE_RETRY_MAX_SECONDS / 2 ?
        FENCE_RETRY_MAX_SECONDS : delay * 2;
}

static VOID FenceRetryFinish(VOID)
{
    KIRQL irql;
    KeAcquireSpinLock(&FenceRetryLock, &irql);
    if (!FenceAnyRetryableQuarantine()) {
        FenceRetryDelaySeconds = FENCE_RETRY_INITIAL_SECONDS;
        InterlockedExchange(&FenceRetryPending, FALSE);
        InterlockedExchange(&FenceRetryTimerArmed, FALSE);
    } else {
        FenceRetryArmLocked();
    }
    KeReleaseSpinLock(&FenceRetryLock, irql);
}

/* Reconcile once refresh serialization is released. A later failure may have re-added quarantine
 * before this routine gets the retry lock, so inspect the current state before cancelling a retry. */
/* Keep the spin-lock critical section out of pageable refresh/unload callers. */
static __declspec(noinline) VOID FenceRetryUpdateAfterRefresh(VOID)
{
    BOOLEAN quarantined;
    KIRQL irql;
    KeAcquireSpinLock(&FenceRetryLock, &irql);
    quarantined = FenceAnyRetryableQuarantine();
    if (quarantined) {
        if (InterlockedCompareExchange(&FenceRetryPending, FALSE, FALSE) == FALSE) FenceRetryArmLocked();
    } else {
        FenceRetryDelaySeconds = FENCE_RETRY_INITIAL_SECONDS;
    }
    if (!quarantined && InterlockedCompareExchange(&FenceRetryTimerArmed, FALSE, FALSE) != FALSE) {
        if (KeCancelTimer(&FenceRetryTimer)) {
            InterlockedExchange(&FenceRetryTimerArmed, FALSE);
            InterlockedExchange(&FenceRetryPending, FALSE);
        } else {
            /* The DPC already owns the pending state and will observe the cleared quarantine. */
            InterlockedExchange(&FenceRetryTimerArmed, FALSE);
        }
    }
    KeReleaseSpinLock(&FenceRetryLock, irql);
}

static __declspec(noinline) VOID FenceRetryStopForUnload(VOID)
{
    KIRQL irql;
    KeAcquireSpinLock(&FenceRetryLock, &irql);
    InterlockedExchange(&FenceRetryStopping, TRUE);
    if (InterlockedCompareExchange(&FenceRetryTimerArmed, FALSE, FALSE) != FALSE) {
        if (KeCancelTimer(&FenceRetryTimer)) {
            InterlockedExchange(&FenceRetryPending, FALSE);
        }
        InterlockedExchange(&FenceRetryTimerArmed, FALSE);
    }
    KeReleaseSpinLock(&FenceRetryLock, irql);
    /* KeCancelTimer cannot retire a DPC that has already been queued or started. */
    KeFlushQueuedDpcs();
}

static __declspec(noinline) VOID FenceRetryResetAfterDrain(VOID)
{
    KIRQL irql;
    KeAcquireSpinLock(&FenceRetryLock, &irql);
    InterlockedExchange(&FenceRetryPending, FALSE);
    InterlockedExchange(&FenceRetryTimerArmed, FALSE);
    KeReleaseSpinLock(&FenceRetryLock, irql);
}

static __declspec(noinline) VOID FenceRetryResume(VOID)
{
    KIRQL irql;
    KeAcquireSpinLock(&FenceRetryLock, &irql);
    InterlockedExchange(&FenceRetryStopping, FALSE);
    if (InterlockedCompareExchange(&FenceRetryPending, FALSE, FALSE) == FALSE) FenceRetryArmLocked();
    KeReleaseSpinLock(&FenceRetryLock, irql);
}

VOID SafeUploadStageFenceStartRetries(VOID)
{
    KIRQL irql;
    if (!FenceInitialized) return;
    KeAcquireSpinLock(&FenceRetryLock, &irql);
    InterlockedExchange(&FenceRetryEnabled, TRUE);
    FenceRetryArmLocked();
    KeReleaseSpinLock(&FenceRetryLock, irql);
}

static VOID FenceRetryRefreshRoutine(_In_ PFLT_GENERIC_WORKITEM WorkItem,
    _In_ PVOID FltObject, _In_opt_ PVOID Context)
{
    NTSTATUS status = STATUS_DEVICE_NOT_READY;
    UNREFERENCED_PARAMETER(FltObject);
    UNREFERENCED_PARAMETER(Context);

    if ((FenceLateControlRead() & FENCE_LATE_GATE_MASK) == FENCE_LATE_GATE_OPEN &&
        InterlockedCompareExchange(&FenceRetryStopping, FALSE, FALSE) == FALSE && FenceAnyRetryableQuarantine()) {
        status = FenceRefreshInternal(NULL, NULL, FALSE);
    }
    if (!NT_SUCCESS(status) && status != STATUS_DEVICE_NOT_READY) {
        SafeUploadTrace("quarantine retry scan did not complete, status 0x%08X\n", status);
    }
    FltFreeGenericWorkItem(WorkItem);
    FenceRetryFinish();
    FenceLateControlComplete();
}

/* DISPATCH_LEVEL DPC: admission and queueing only. The PASSIVE_LEVEL work item owns the scan. */
_Use_decl_annotations_
static VOID FenceRetryTimerDpc(_In_ PKDPC Dpc, _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2)
{
    PFLT_GENERIC_WORKITEM item;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    KeAcquireSpinLockAtDpcLevel(&FenceRetryLock);
    InterlockedExchange(&FenceRetryTimerArmed, FALSE);
    if (InterlockedCompareExchange(&FenceRetryPending, FALSE, FALSE) == FALSE ||
        InterlockedCompareExchange(&FenceRetryStopping, FALSE, FALSE) != FALSE ||
        InterlockedCompareExchange(&FenceRetryEnabled, FALSE, FALSE) == FALSE ||
        (FenceLateControlRead() & FENCE_LATE_GATE_MASK) != FENCE_LATE_GATE_OPEN ||
        !FenceAnyRetryableQuarantine()) {
        if (!FenceAnyRetryableQuarantine()) FenceRetryDelaySeconds = FENCE_RETRY_INITIAL_SECONDS;
        InterlockedExchange(&FenceRetryPending, FALSE);
        KeReleaseSpinLockFromDpcLevel(&FenceRetryLock);
        return;
    }
    KeReleaseSpinLockFromDpcLevel(&FenceRetryLock);

    item = FltAllocateGenericWorkItem();
    KeAcquireSpinLockAtDpcLevel(&FenceRetryLock);
    if (item == NULL ||
        InterlockedCompareExchange(&FenceRetryStopping, FALSE, FALSE) != FALSE ||
        InterlockedCompareExchange(&FenceRetryEnabled, FALSE, FALSE) == FALSE ||
        (FenceLateControlRead() & FENCE_LATE_GATE_MASK) != FENCE_LATE_GATE_OPEN ||
        !FenceAnyRetryableQuarantine()) {
        if (!FenceAnyRetryableQuarantine()) FenceRetryDelaySeconds = FENCE_RETRY_INITIAL_SECONDS;
        if (InterlockedCompareExchange(&FenceRetryStopping, FALSE, FALSE) != FALSE ||
            (FenceLateControlRead() & FENCE_LATE_GATE_MASK) != FENCE_LATE_GATE_OPEN ||
            !FenceAnyRetryableQuarantine()) {
            InterlockedExchange(&FenceRetryPending, FALSE);
        } else {
            FenceRetryArmLocked();
        }
        KeReleaseSpinLockFromDpcLevel(&FenceRetryLock);
        if (item != NULL) FltFreeGenericWorkItem(item);
        return;
    }

    /* FenceLateControlClose also takes FenceRetryLock, so this item is either queued before
     * the gate closes or rejected here; it cannot be queued after a CLOSED gate. */
    if (!FenceLateControlReserve()) {
        FenceRetryArmLocked();
        KeReleaseSpinLockFromDpcLevel(&FenceRetryLock);
        FltFreeGenericWorkItem(item);
        return;
    }
    status = FltQueueGenericWorkItem(item, SafeUploadData.Filter,
        FenceRetryRefreshRoutine, DelayedWorkQueue, NULL);
    if (!NT_SUCCESS(status)) {
        FenceLateControlComplete();
        FenceRetryArmLocked();
        KeReleaseSpinLockFromDpcLevel(&FenceRetryLock);
        FltFreeGenericWorkItem(item);
        return;
    }
    KeReleaseSpinLockFromDpcLevel(&FenceRetryLock);
}

static __declspec(noinline) BOOLEAN FenceLateControlClose(VOID)
{
    LONG64 oldValue, newValue;
    KIRQL irql;
    KeAcquireSpinLock(&FenceRetryLock, &irql);
    for (;;) {
        oldValue = FenceLateControlRead();
        if ((oldValue & FENCE_LATE_GATE_MASK) != FENCE_LATE_GATE_OPEN) {
            KeReleaseSpinLock(&FenceRetryLock, irql);
            return FALSE;
        }
        newValue = (oldValue & ~FENCE_LATE_GATE_MASK) | FENCE_LATE_GATE_CLOSING;
        if (InterlockedCompareExchange64(&FenceLateControl, newValue, oldValue) == oldValue) {
            KeReleaseSpinLock(&FenceRetryLock, irql);
            return TRUE;
        }
    }
}

static __declspec(noinline) VOID FenceLateControlOpen(VOID)
{
    LONG64 oldValue, newValue;
    KIRQL irql;
    KeAcquireSpinLock(&FenceRetryLock, &irql);
    for (;;) {
        oldValue = FenceLateControlRead();
        if ((oldValue & FENCE_LATE_GATE_MASK) != FENCE_LATE_GATE_CLOSING) {
            KeReleaseSpinLock(&FenceRetryLock, irql);
            return;
        }
        newValue = oldValue & ~FENCE_LATE_GATE_MASK;
        if (InterlockedCompareExchange64(&FenceLateControl, newValue, oldValue) == oldValue) {
            KeReleaseSpinLock(&FenceRetryLock, irql);
            return;
        }
    }
}

__declspec(noinline) VOID SafeUploadStageFenceCommitUnload(VOID)
{
    LONG64 oldValue, newValue;
    KIRQL irql;
    (VOID)FenceLateControlClose();
    FenceRetryStopForUnload();
    KeAcquireSpinLock(&FenceRetryLock, &irql);
    for (;;) {
        oldValue = FenceLateControlRead();
        if ((oldValue & FENCE_LATE_GATE_MASK) == FENCE_LATE_GATE_CLOSED) break;
        newValue = (oldValue & ~FENCE_LATE_GATE_MASK) | FENCE_LATE_GATE_CLOSED;
        if (InterlockedCompareExchange64(&FenceLateControl, newValue, oldValue) == oldValue) break;
    }
    KeReleaseSpinLock(&FenceRetryLock, irql);
}

static VOID FenceWaitForLateWorkers(VOID)
{
    for (;;) {
        if (FENCE_LATE_WORK_COUNT(FenceLateControlRead()) == 0) {
            KeSetEvent(&FenceLateRefreshIdle, IO_NO_INCREMENT, FALSE);
            return;
        }
        KeClearEvent(&FenceLateRefreshIdle);
        if (FENCE_LATE_WORK_COUNT(FenceLateControlRead()) == 0) continue;
        KeWaitForSingleObject(&FenceLateRefreshIdle, Executive, KernelMode, FALSE, NULL);
    }
}

/* Final commit is the point after which FilterUnload cannot return DO_NOT_DETACH. Queue admission
 * races this exact state transition with a CAS; attach-failure quarantine takes FenceRetryLock, so
 * the commit observes either its work reservation or its quarantine before closing the gate. */
/* Keep spin-lock/CAS work out of PAGE: KeAcquireSpinLock raises execution to DISPATCH_LEVEL. */
_IRQL_requires_(PASSIVE_LEVEL)
static __declspec(noinline) BOOLEAN FenceTryCommitUnloadNonPaged(VOID)
{
    LONG64 oldValue, newValue;
    KIRQL irql;
    BOOLEAN committed = FALSE;

    KeAcquireSpinLock(&FenceRetryLock, &irql);
    oldValue = FenceLateControlRead();
    if ((oldValue & FENCE_LATE_GATE_MASK) == FENCE_LATE_GATE_CLOSING &&
        FENCE_LATE_WORK_COUNT(oldValue) == 0 &&
        InterlockedCompareExchange(&FenceSetupInFlight, 0, 0) == 0 &&
        InterlockedCompareExchange(&FenceLateAttachOutstanding, 0, 0) == 0 &&
        InterlockedCompareExchange(&FenceEntryCount, 0, 0) == 0 &&
        !FenceAnyQuarantine() &&
        InterlockedCompareExchange64(&FenceVolumeScopesSkipped, 0, 0) == 0 &&
        InterlockedCompareExchange64(&FenceReparseSkipped, 0, 0) == 0 &&
        InterlockedCompareExchange(&FenceRetryPending, FALSE, FALSE) == FALSE &&
        InterlockedCompareExchange(&FenceRetryTimerArmed, FALSE, FALSE) == FALSE) {
        newValue = (oldValue & ~FENCE_LATE_GATE_MASK) | FENCE_LATE_GATE_CLOSED;
        committed = InterlockedCompareExchange64(&FenceLateControl, newValue, oldValue) == oldValue;
    }
    KeReleaseSpinLock(&FenceRetryLock, irql);
    return committed;
}

_Use_decl_annotations_
BOOLEAN SafeUploadStageFenceTryCommitUnload(VOID)
{
    PAGED_CODE();
    if (!FenceInitialized) return TRUE;
    return FenceTryCommitUnloadNonPaged();
}

BOOLEAN SafeUploadStageFenceSetupBegin(VOID)
{
    KIRQL irql;
    BOOLEAN admitted;
    KeAcquireSpinLock(&FenceRetryLock, &irql);
    admitted = FenceLateControlReserveAttach();
    if (admitted) InterlockedIncrement(&FenceSetupInFlight);
    KeReleaseSpinLock(&FenceRetryLock, irql);
    return admitted;
}

VOID SafeUploadStageFenceSetupEnd(VOID)
{
    KIRQL irql;
    KeAcquireSpinLock(&FenceRetryLock, &irql);
    if (InterlockedCompareExchange(&FenceSetupInFlight, 0, 0) > 0) {
        InterlockedDecrement(&FenceSetupInFlight);
    }
    KeReleaseSpinLock(&FenceRetryLock, irql);
    FenceLateControlComplete();
}

/* Voluntary unload: close admission atomically, drain each accepted worker, then scan synchronously even
 * when the installed table is empty. FilterUnload commits or cancels this gate after the stage guard. */
_Use_decl_annotations_
NTSTATUS SafeUploadStageFencePrepareUnload(VOID)
{
    NTSTATUS status;
    PAGED_CODE();
    if (!FenceInitialized) return STATUS_SUCCESS;
    if (!FenceLateControlClose()) return STATUS_FLT_DO_NOT_DETACH;
    FenceRetryStopForUnload();
    FenceWaitForLateWorkers();
    FenceRetryResetAfterDrain();
    /* Private final pass: public refresh admission is closed, and all pre-close reservations drained. */
    status = FenceRefreshInternal(NULL, NULL, TRUE);
    if (!NT_SUCCESS(status) || SafeUploadStageFenceHasEntries() ||
        InterlockedCompareExchange64(&FenceVolumeScopesSkipped, 0, 0) != 0 ||
        InterlockedCompareExchange64(&FenceReparseSkipped, 0, 0) != 0) {
        return STATUS_FLT_DO_NOT_DETACH;
    }
    return STATUS_SUCCESS; /* retain CLOSING while higher-level guards run */
}

/* StagePrepareUnload can still refuse after the fence scan. Reopen then so future attachments can be admitted. */
VOID SafeUploadStageFenceCancelUnload(VOID)
{
    FenceLateControlOpen();
    FenceRetryResume();
}

/* A policy transition holds the refresh mutex across both pre-publication scans and the policy swap, so no
 * other refresh can interpose a fence install. The mutex is recursive: refreshes made by the same thread
 * inside the transition re-acquire it. This does not synchronize section creation or future view mapping. */
_Use_decl_annotations_
BOOLEAN SafeUploadStageFenceTransitionBegin(VOID)
{
    PAGED_CODE();
    if (!FenceInitialized || !FenceLateControlReserve()) return FALSE;
    KeWaitForSingleObject(&FenceRefreshMutex, Executive, KernelMode, FALSE, NULL);
    if (!FenceInitialized) {
        (VOID)KeReleaseMutex(&FenceRefreshMutex, FALSE);
        FenceLateControlComplete();
        return FALSE;
    }
    InterlockedExchangePointer((PVOID volatile *)&FenceTransitionOwner, PsGetCurrentThread());
    return TRUE;
}

_Use_decl_annotations_
VOID SafeUploadStageFenceTransitionEnd(VOID)
{
    PAGED_CODE();
    NT_ASSERT((PETHREAD)InterlockedCompareExchangePointer(
        (PVOID volatile *)&FenceTransitionOwner, NULL, NULL) == PsGetCurrentThread());
    InterlockedExchangePointer((PVOID volatile *)&FenceTransitionOwner, NULL);
    (VOID)KeReleaseMutex(&FenceRefreshMutex, FALSE);
    if (KeReadStateMutex(&FenceRefreshMutex)) FenceRetryUpdateAfterRefresh();
    FenceLateControlComplete();
}

/* Whether any registered stream lives on Volume (an unknown volume counts as a hit). Used to scope the
 * refusal of opens that carry no name. */
BOOLEAN SafeUploadStageFenceVolumeHasEntries(_In_opt_ PFLT_VOLUME Volume)
{
    ULONG index;
    BOOLEAN hit = FenceVolumeIsQuarantined(Volume);
    if (hit || InterlockedCompareExchange(&FenceEntryCount, 0, 0) == 0) return hit;
    FltAcquirePushLockShared(&FenceNameLock);
    if (FenceTable != NULL) {
        for (index = 0; index < FenceTable->StreamCount && index < FENCE_MAX_STREAMS; index += 1) {
            if (Volume == NULL || FenceTable->StreamVolume[index] == Volume || FenceTable->StreamVolume[index] == NULL) { hit = TRUE; break; }
        }
    }
    FltReleasePushLock(&FenceNameLock);
    return hit;
}

BOOLEAN SafeUploadStageFenceVolumeBlocksDetach(_In_opt_ PFLT_VOLUME Volume)
{
    LONG64 control = FenceLateControlRead();
    return (control & FENCE_LATE_GATE_MASK) != FENCE_LATE_GATE_OPEN ||
        FENCE_LATE_WORK_COUNT(control) != 0 ||
        InterlockedCompareExchange(&FenceRefreshInFlight, 0, 0) != 0 ||
        InterlockedCompareExchange(&FenceRetryPending, FALSE, FALSE) != FALSE ||
        SafeUploadStageFenceVolumeHasEntries(Volume);
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

BOOLEAN SafeUploadStageFenceVolumeQuarantined(_In_opt_ PFLT_VOLUME Volume)
{
    return FenceVolumeIsQuarantined(Volume);
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
    return InterlockedCompareExchange(&FenceEntryCount, 0, 0) != 0 || FenceAnyQuarantine();
}

VOID SafeUploadStageFenceCountOpenRefused(VOID) { InterlockedIncrement64(&FenceOpensRefused); }
VOID SafeUploadStageFenceCountPagingDenied(VOID) { InterlockedIncrement64(&FencePagingDenied); }
VOID SafeUploadStageFenceCountSectionDenied(VOID) { InterlockedIncrement64(&FenceSectionsDenied); }
VOID SafeUploadStageFenceCountSectionUnresolved(VOID) { InterlockedIncrement64(&FenceSectionUnresolved); }
/* Every accepted attachment gets one work item; serialization in FenceRefreshMutex ensures each
 * arrival is covered by a scan even when it occurs after an earlier scan enumerated volumes. */
static VOID FenceLateRefreshRoutine(_In_ PFLT_GENERIC_WORKITEM WorkItem, _In_ PVOID FltObject, _In_opt_ PVOID Context)
{
    NTSTATUS status;
    KIRQL irql;
    UNREFERENCED_PARAMETER(FltObject);
    status = FenceRefreshInternal(NULL, (PFLT_VOLUME)Context, FALSE);
    if (!NT_SUCCESS(status)) {
        SafeUploadTrace("late-attach fence refresh failed, status 0x%08X\n", status);
    }
    if (Context != NULL) FltObjectDereference(Context);
    FltFreeGenericWorkItem(WorkItem);
    KeAcquireSpinLock(&FenceRetryLock, &irql);
    if (InterlockedCompareExchange(&FenceLateAttachOutstanding, 0, 0) > 0) {
        InterlockedDecrement(&FenceLateAttachOutstanding);
    }
    KeReleaseSpinLock(&FenceRetryLock, irql);
    FenceRetryUpdateAfterRefresh();
    FenceLateControlComplete();
}

/* Record an attach that could not reserve/queue its scan without ever making InstanceSetup wait.
 * FenceRetryLock serializes this record with the final CLOSING->CLOSED commit. */
static __declspec(noinline) BOOLEAN FenceLateAttachQuarantine(_In_ PFLT_VOLUME Volume)
{
    NTSTATUS status = FltObjectReference(Volume);
    BOOLEAN keepReference = FALSE;
    BOOLEAN admitted = FALSE;
    LONG64 control;
    KIRQL irql;

    KeAcquireSpinLock(&FenceRetryLock, &irql);
    control = FenceLateControlRead();
    if ((control & FENCE_LATE_GATE_MASK) != FENCE_LATE_GATE_CLOSED) {
        admitted = TRUE;
        if (NT_SUCCESS(status)) keepReference = FenceQuarantineStoreReferenced(Volume);
        else FenceQuarantineAllSticky();
    }
    KeReleaseSpinLock(&FenceRetryLock, irql);

    if (NT_SUCCESS(status) && !keepReference) FltObjectDereference(Volume);
    if (admitted && (control & FENCE_LATE_GATE_MASK) == FENCE_LATE_GATE_OPEN) {
        FenceRetryUpdateAfterRefresh();
    }
    return admitted;
}

BOOLEAN SafeUploadStageFenceQueueRefresh(_In_ PFLT_VOLUME Volume)
{
    PFLT_GENERIC_WORKITEM item;
    NTSTATUS status;
    BOOLEAN quarantined;
    BOOLEAN fixedNtfs;
    KIRQL irql;

    if (Volume == NULL) return FALSE;
    /* Do not wait for work here: Filter Manager cautions against synchronization in InstanceSetup.
     * That leaves an explicit attachment-to-scan paging-write window for covered volumes. The fence
     * scanner has an intentionally narrow scope. Do not make a transient work-item or
     * unload-gate failure detach SafeUpload from network, removable, or non-NTFS volumes: those
     * attachments still carry the ordinary policy callbacks, while this feature reports that the
     * volume is outside its mapped-stream fence coverage. */
    status = FenceClassifyVolume(Volume, &fixedNtfs);
    if (!NT_SUCCESS(status)) {
        quarantined = FenceLateAttachQuarantine(Volume);
        InterlockedExchange(&FenceLastStatus, (LONG)status);
        InterlockedIncrement64(&FenceRefreshFailed);
        SafeUploadTrace("late-attach volume classification failed, status 0x%08X; %s attachment with quarantine\n",
            status, quarantined ? "retaining SafeUpload" : "unload commit already closed; declining");
        return quarantined;
    }
    if (!fixedNtfs) {
        SafeUploadTrace("late-attach fence refresh skipped: volume outside fixed NTFS coverage; retaining SafeUpload attachment\n");
        return TRUE;
    }
    if (!FenceInitialized) return FALSE;

    /* Reserve before any fallible allocation or reference so a closing unload either drains this
     * setup's scan or observes its quarantine and vetoes. CLOSED is published only after the
     * unload's final, non-fallible commit point. */
    if (!FenceLateControlReserveAttach()) {
        quarantined = FenceLateAttachQuarantine(Volume);
        if (quarantined) {
            InterlockedExchange(&FenceLastStatus, (LONG)STATUS_DEVICE_BUSY);
            InterlockedIncrement64(&FenceRefreshFailed);
            SafeUploadTrace("late-attach refresh could not reserve work; protected-name quarantine recorded, retaining attachment\n");
        }
        return quarantined;
    }

    item = FltAllocateGenericWorkItem();
    if (item == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        quarantined = FenceLateAttachQuarantine(Volume);
        FenceLateControlComplete();
        InterlockedExchange(&FenceLastStatus, (LONG)STATUS_INSUFFICIENT_RESOURCES);
        InterlockedIncrement64(&FenceRefreshFailed);
        SafeUploadTrace("late-attach fence work-item allocation failed, status 0x%08X; %s attachment\n",
            status, quarantined ? "retaining SafeUpload" : "unload commit already closed; declining");
        return quarantined;
    }
    status = FltObjectReference(Volume);
    if (!NT_SUCCESS(status)) {
        quarantined = FenceLateAttachQuarantine(Volume);
        FenceLateControlComplete();
        FltFreeGenericWorkItem(item);
        InterlockedExchange(&FenceLastStatus, (LONG)status);
        InterlockedIncrement64(&FenceRefreshFailed);
        SafeUploadTrace("late-attach fence volume reference failed, status 0x%08X; %s attachment\n",
            status, quarantined ? "retaining SafeUpload" : "unload commit already closed; declining");
        return quarantined;
    }
    KeAcquireSpinLock(&FenceRetryLock, &irql);
    InterlockedIncrement(&FenceLateAttachOutstanding);
    KeReleaseSpinLock(&FenceRetryLock, irql);
    status = FltQueueGenericWorkItem(item, SafeUploadData.Filter, FenceLateRefreshRoutine, DelayedWorkQueue, Volume);
    if (!NT_SUCCESS(status)) {
        KeAcquireSpinLock(&FenceRetryLock, &irql);
        InterlockedDecrement(&FenceLateAttachOutstanding);
        KeReleaseSpinLock(&FenceRetryLock, irql);
        FltObjectDereference(Volume);
        FltFreeGenericWorkItem(item);
        quarantined = FenceLateAttachQuarantine(Volume);
        FenceLateControlComplete();
        InterlockedExchange(&FenceLastStatus, (LONG)status);
        InterlockedIncrement64(&FenceRefreshFailed);
        SafeUploadTrace("late-attach fence work-item queue failed, status 0x%08X; %s attachment\n",
            status, quarantined ? "retaining SafeUpload" : "unload commit already closed; declining");
        return quarantined;
    }
    InterlockedIncrement64(&FenceLateRefreshQueued);
    return TRUE;
}

VOID SafeUploadStageFenceCountFsctlUnresolved(VOID) { InterlockedIncrement64(&FenceFsctlUnresolved); }

VOID SafeUploadStageFenceGetStatus(_Out_ PSAFEUPLOAD_FENCE_STATUS Status)
{
    LONG64 lateControl;

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
    Status->StateFlags = 0;
    lateControl = FenceLateControlRead();
    if (FENCE_LATE_WORK_COUNT(lateControl) != 0) {
        Status->StateFlags |= SAFEUPLOAD_FENCE_STATUS_FLAG_LATE_REFRESH_PENDING;
    }
    if ((lateControl & FENCE_LATE_GATE_MASK) != FENCE_LATE_GATE_OPEN) {
        Status->StateFlags |= SAFEUPLOAD_FENCE_STATUS_FLAG_UNLOAD_GATE_CLOSED;
    }
    if (FenceAnyQuarantine()) {
        Status->StateFlags |= SAFEUPLOAD_FENCE_STATUS_FLAG_QUARANTINED;
    }
    if (InterlockedCompareExchange(&FenceRefreshInFlight, 0, 0) != 0) {
        Status->StateFlags |= SAFEUPLOAD_FENCE_STATUS_FLAG_REFRESH_ACTIVE;
    }
    if (InterlockedCompareExchange(&FenceRetryPending, FALSE, FALSE) != FALSE) {
        Status->StateFlags |= SAFEUPLOAD_FENCE_STATUS_FLAG_RETRY_PENDING;
    }
}

#endif
