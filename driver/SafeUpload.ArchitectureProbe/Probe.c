/*
 * Bounded, separately built same-stack isolation experiment. This is not the
 * staged feature or a publishable driver. It owns otherwise-unopened upper
 * file objects; it never changes another filesystem's contexts or VPB/device.
 * Only new top-level files under \\SafeUpload\\Architecture Probe are handled.
 * Ordinary filesystem requests outside that fixture pass through unchanged.
 * Unapproved bytes have an independent upper cache and private local backing.
 * Unsupported requests on an owned object are completed, never passed to NTFS.
 */
#include "../SafeUpload.Minifilter/Filter.h"
#include "../SafeUpload.Minifilter/StageSecurity.h"
#include <ntstrsafe.h>

#define PROBE_TAG 'aUpS'
#define PROBE_LIMIT 16
#define PROBE_MAX_BYTES (16 * 1024 * 1024)

SAFEUPLOAD_DATA SafeUploadData; /* Reuse the original-caller security helper. */

typedef struct _PROBE_STREAM {
    FSRTL_ADVANCED_FCB_HEADER Header;
    FAST_MUTEX HeaderMutex;
    ERESOURCE Resource;
    ERESOURCE PagingResource;
    SECTION_OBJECT_POINTERS Sections;
    LIST_ENTRY Link;
    SHARE_ACCESS ShareAccess;
    PEPROCESS Owner;
    PFLT_INSTANCE OriginalInstance;
    PFLT_INSTANCE BackingInstance;
    HANDLE BackingHandle;
    PFILE_OBJECT BackingObject;
    PSECURITY_DESCRIPTOR Security;
    ULONG SectorSize;
    BOOLEAN AssignedSecurity;
    BOOLEAN ResourceInitialized;
    BOOLEAN PagingInitialized;
    USHORT VolumeLength;
    UNICODE_STRING Name;
    WCHAR NameBuffer[SAFEUPLOAD_MAX_PATH_CHARS];
} PROBE_STREAM, *PPROBE_STREAM;

typedef struct _PROBE_HANDLE {
    PPROBE_STREAM Stream;
    ACCESS_MASK GrantedAccess;
    BOOLEAN Cleaned;
} PROBE_HANDLE, *PPROBE_HANDLE;

static LIST_ENTRY ProbeStreams;
static KSPIN_LOCK ProbeListLock;
static ERESOURCE ProbeNamespaceResource;
static ULONG ProbeStreamCount;
static volatile LONG ProbeFileObjects;
static BOOLEAN ProbeStopping;
static UNICODE_STRING ProbePrefix = RTL_CONSTANT_STRING(L"\\SafeUpload\\Architecture Probe\\");

static FLT_PREOP_CALLBACK_STATUS ProbePreOperation(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, PVOID *CompletionContext);

static PPROBE_STREAM ProbeStreamForObject(PFILE_OBJECT FileObject)
{
    PLIST_ENTRY link;
    KIRQL irql;
    PPROBE_STREAM found = NULL;
    if (FileObject == NULL || FileObject->FsContext == NULL) return NULL;
    KeAcquireSpinLock(&ProbeListLock, &irql);
    for (link = ProbeStreams.Flink; link != &ProbeStreams; link = link->Flink) {
        PPROBE_STREAM stream = CONTAINING_RECORD(link, PROBE_STREAM, Link);
        if (FileObject->FsContext == &stream->Header) { found = stream; break; }
    }
    KeReleaseSpinLock(&ProbeListLock, irql);
    /* Streams remain allocated until unregister has drained all callbacks. */
    return found;
}

static VOID ProbeAcquire(PERESOURCE Resource)
{
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(Resource, TRUE);
}

static VOID ProbeRelease(PERESOURCE Resource)
{
    ExReleaseResourceLite(Resource);
    KeLeaveCriticalRegion();
}

static BOOLEAN ProbeCacheAcquire(PVOID Context, BOOLEAN Wait)
{
    PPROBE_STREAM stream = Context;
    KeEnterCriticalRegion();
    if (!ExAcquireResourceSharedLite(&stream->PagingResource, Wait)) {
        KeLeaveCriticalRegion();
        return FALSE;
    }
    return TRUE;
}

static VOID ProbeCacheRelease(PVOID Context)
{
    PPROBE_STREAM stream = Context;
    ProbeRelease(&stream->PagingResource);
}

static CACHE_MANAGER_CALLBACKS ProbeCacheCallbacks = {
    ProbeCacheAcquire, ProbeCacheRelease, ProbeCacheAcquire, ProbeCacheRelease
};

static VOID ProbeInitializeCache(PPROBE_STREAM Stream, PFILE_OBJECT FileObject)
{
    CC_FILE_SIZES sizes;
    if (FileObject->PrivateCacheMap != NULL) return;
    sizes.AllocationSize = Stream->Header.AllocationSize;
    sizes.FileSize = Stream->Header.FileSize;
    sizes.ValidDataLength = Stream->Header.ValidDataLength;
    CcInitializeCacheMap(FileObject, &sizes, FALSE, &ProbeCacheCallbacks, Stream);
}

static NTSTATUS ProbeFlush(PPROBE_STREAM Stream)
{
    IO_STATUS_BLOCK io = {0};
    if (Stream->Sections.DataSectionObject != NULL) {
        CcFlushCache(&Stream->Sections, NULL, 0, &io);
        if (!NT_SUCCESS(io.Status)) return io.Status;
    }
    return FltFlushBuffers(Stream->BackingInstance, Stream->BackingObject);
}

static VOID ProbeFreeStream(PPROBE_STREAM Stream)
{
    if (Stream->BackingObject != NULL) ObDereferenceObject(Stream->BackingObject);
    if (Stream->BackingHandle != NULL) FltClose(Stream->BackingHandle);
    if (Stream->BackingInstance != NULL) FltObjectDereference(Stream->BackingInstance);
    if (Stream->OriginalInstance != NULL) FltObjectDereference(Stream->OriginalInstance);
    if (Stream->Owner != NULL) ObDereferenceObject(Stream->Owner);
    SafeUploadStageFreeSecurity(Stream->Security, Stream->AssignedSecurity);
    if (Stream->PagingInitialized) ExDeleteResourceLite(&Stream->PagingResource);
    if (Stream->ResourceInitialized) ExDeleteResourceLite(&Stream->Resource);
    ExFreePoolWithTag(Stream, PROBE_TAG);
}

/* The harness creates this root as SYSTEM, with a protected SYSTEM-only DACL.
 * A file also gets its own explicit SYSTEM-only descriptor, independently of
 * parent inheritance. No user-mode path or access grant is accepted here. */
static NTSTATUS ProbeOpenBacking(PPROBE_STREAM Stream)
{
    UNICODE_STRING drive = RTL_CONSTANT_STRING(L"\\??\\C:");
    UNICODE_STRING path;
    PWCHAR pathBuffer = NULL;
    GUID id;
    UNICODE_STRING idString = {0};
    PFLT_VOLUME volume = NULL;
    PDEVICE_OBJECT sourceDevice = NULL, backingDevice = NULL;
    PFLT_VOLUME sourceVolume = NULL;
    FLT_VOLUME_PROPERTIES properties;
    ULONG propertiesLength;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io;
    SECURITY_DESCRIPTOR descriptor;
    DECLSPEC_ALIGN(4) UCHAR aclBuffer[128];
    PACL acl = (PACL)aclBuffer;
    NTSTATUS status;

    pathBuffer = ExAllocatePool2(POOL_FLAG_PAGED,
        SAFEUPLOAD_MAX_PATH_CHARS * sizeof(WCHAR), PROBE_TAG);
    if (pathBuffer == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    status = FltGetVolumeFromName(SafeUploadData.Filter, &drive, &volume);
    if (!NT_SUCCESS(status)) goto Exit;
    status = FltGetVolumeProperties(volume, &properties, sizeof(properties), &propertiesLength);
    if (status != STATUS_BUFFER_OVERFLOW && !NT_SUCCESS(status)) goto Exit;
    Stream->SectorSize = properties.SectorSize;
    if (Stream->SectorSize < 512 || Stream->SectorSize > 65536 ||
        (Stream->SectorSize & (Stream->SectorSize - 1)) != 0) {
        status = STATUS_NOT_SUPPORTED;
        goto Exit;
    }
    status = FltGetVolumeInstanceFromName(SafeUploadData.Filter, volume, NULL,
        &Stream->BackingInstance);
    if (!NT_SUCCESS(status)) goto Exit;
    status = FltGetVolumeFromInstance(Stream->OriginalInstance, &sourceVolume);
    if (!NT_SUCCESS(status)) goto Exit;
    status = FltGetDeviceObject(sourceVolume, &sourceDevice);
    if (!NT_SUCCESS(status)) goto Exit;
    status = FltGetDeviceObject(volume, &backingDevice);
    if (!NT_SUCCESS(status)) goto Exit;
    /* Required by the documented TargetInstance redirection contract. */
    if (backingDevice->StackSize < sourceDevice->StackSize) {
        status = STATUS_NOT_SUPPORTED;
        goto Exit;
    }
    status = ExUuidCreate(&id);
    if (!NT_SUCCESS(status)) goto Exit;
    status = RtlStringFromGUID(&id, &idString);
    if (!NT_SUCCESS(status)) goto Exit;
    status = RtlStringCchPrintfW(pathBuffer, SAFEUPLOAD_MAX_PATH_CHARS,
        L"\\??\\C:\\ProgramData\\SafeUpload\\architecture-probe\\%wZ.bin", &idString);
    if (!NT_SUCCESS(status)) goto Exit;
    RtlInitUnicodeString(&path, pathBuffer);
    status = RtlCreateSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status)) goto Exit;
    status = RtlCreateAcl(acl, sizeof(aclBuffer), ACL_REVISION);
    if (!NT_SUCCESS(status)) goto Exit;
    status = RtlAddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS,
        SeExports->SeLocalSystemSid);
    if (!NT_SUCCESS(status)) goto Exit;
    status = RtlSetDaclSecurityDescriptor(&descriptor, TRUE, acl, FALSE);
    if (!NT_SUCCESS(status)) goto Exit;
    status = RtlSetOwnerSecurityDescriptor(&descriptor, SeExports->SeLocalSystemSid, FALSE);
    if (!NT_SUCCESS(status)) goto Exit;
    descriptor.Control |= SE_DACL_PROTECTED;
    InitializeObjectAttributes(&attributes, &path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL, &descriptor);
    status = FltCreateFileEx2(SafeUploadData.Filter, Stream->BackingInstance,
        &Stream->BackingHandle, &Stream->BackingObject,
        FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES |
        SYNCHRONIZE, &attributes, &io, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_CREATE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_NO_INTERMEDIATE_BUFFERING, NULL, 0,
        IO_STOP_ON_SYMLINK, NULL);
    if (status == STATUS_STOPPED_ON_SYMLINK && io.Information != 0)
        ExFreePool((PVOID)io.Information);
Exit:
    if (sourceDevice != NULL) ObDereferenceObject(sourceDevice);
    if (backingDevice != NULL) ObDereferenceObject(backingDevice);
    if (sourceVolume != NULL) FltObjectDereference(sourceVolume);
    if (volume != NULL) FltObjectDereference(volume);
    if (idString.Buffer != NULL) RtlFreeUnicodeString(&idString);
    if (pathBuffer != NULL) ExFreePoolWithTag(pathBuffer, PROBE_TAG);
    return status;
}

static NTSTATUS ProbeCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS Objects,
    PFLT_FILE_NAME_INFORMATION Name)
{
    PPROBE_STREAM stream = NULL;
    PPROBE_HANDLE handle = NULL;
    PFILE_OBJECT file = Data->Iopb->TargetFileObject;
    ACCESS_MASK desired = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    ACCESS_MASK granted = 0;
    ULONG disposition = Data->Iopb->Parameters.Create.Options >> 24;
    PLIST_ENTRY link;
    KIRQL irql;
    BOOLEAN created = FALSE, exists = FALSE;
    NTSTATUS status;

    /* These constraints keep the experiment bounded. They are not the final
     * filesystem contract; in particular it does not rotate or replace files. */
    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE |
        FILE_OPEN_BY_FILE_ID | FILE_DELETE_ON_CLOSE | FILE_NO_INTERMEDIATE_BUFFERING) ||
        Name->Name.Length > sizeof(stream->NameBuffer) ||
        file->FsContext != NULL || file->FsContext2 != NULL)
        return STATUS_NOT_SUPPORTED;
    if (Name->Stream.Length != 0 ||
        !RtlEqualUnicodeString(&Name->ParentDir, &ProbePrefix, TRUE)) return STATUS_NOT_SUPPORTED;
    ProbeAcquire(&ProbeNamespaceResource);
    if (ProbeStopping) { status = STATUS_DEVICE_NOT_READY; goto Exit; }
    for (link = ProbeStreams.Flink; link != &ProbeStreams; link = link->Flink) {
        PPROBE_STREAM candidate = CONTAINING_RECORD(link, PROBE_STREAM, Link);
        if (candidate->Owner == FltGetRequestorProcess(Data) &&
            RtlEqualUnicodeString(&candidate->Name, &Name->Name, TRUE)) {
            stream = candidate;
            break;
        }
    }
    if (stream == NULL) {
        if (disposition == FILE_OPEN || disposition == FILE_OVERWRITE) {
            status = STATUS_OBJECT_NAME_NOT_FOUND;
            goto Exit;
        }
        if (ProbeStreamCount == PROBE_LIMIT) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
        stream = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*stream), PROBE_TAG);
        if (stream == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
        created = TRUE;
        status = ExInitializeResourceLite(&stream->Resource);
        if (!NT_SUCCESS(status)) goto Exit;
        stream->ResourceInitialized = TRUE;
        status = ExInitializeResourceLite(&stream->PagingResource);
        if (!NT_SUCCESS(status)) goto Exit;
        stream->PagingInitialized = TRUE;
        ExInitializeFastMutex(&stream->HeaderMutex);
        FsRtlSetupAdvancedHeader(&stream->Header, &stream->HeaderMutex);
        stream->Header.NodeTypeCode = 0x5349;
        stream->Header.NodeByteSize = sizeof(*stream);
        stream->Header.Resource = &stream->Resource;
        stream->Header.PagingIoResource = &stream->PagingResource;
        stream->Header.IsFastIoPossible = FastIoIsNotPossible;
        status = SafeUploadStageCaptureSecurity(Data, Objects->Instance, &Name->Name,
            &stream->Security, &stream->AssignedSecurity, &exists, &granted);
        if (!NT_SUCCESS(status)) goto Exit;
        if (exists) { status = STATUS_NOT_SUPPORTED; goto Exit; }
        stream->Owner = FltGetRequestorProcess(Data);
        if (stream->Owner == NULL) { status = STATUS_ACCESS_DENIED; goto Exit; }
        ObReferenceObject(stream->Owner);
        status = FltObjectReference(Objects->Instance);
        if (!NT_SUCCESS(status)) goto Exit;
        stream->OriginalInstance = Objects->Instance;
        stream->VolumeLength = Name->Volume.Length;
        stream->Name.Buffer = stream->NameBuffer;
        stream->Name.MaximumLength = sizeof(stream->NameBuffer);
        stream->Name.Length = Name->Name.Length;
        RtlCopyMemory(stream->Name.Buffer, Name->Name.Buffer, Name->Name.Length);
        status = ProbeOpenBacking(stream);
        if (!NT_SUCCESS(status)) goto Exit;
    } else {
        if (disposition == FILE_CREATE) { status = STATUS_OBJECT_NAME_COLLISION; goto Exit; }
        if (disposition != FILE_OPEN && disposition != FILE_OPEN_IF) {
            status = STATUS_NOT_SUPPORTED;
            goto Exit;
        }
        status = SafeUploadStageCheckAccess(Data, stream->Security, desired, &granted);
        if (!NT_SUCCESS(status)) goto Exit;
    }
    handle = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*handle), PROBE_TAG);
    if (handle == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    ProbeAcquire(&stream->Resource);
    status = IoCheckShareAccess(granted, Data->Iopb->Parameters.Create.ShareAccess,
        file, &stream->ShareAccess, TRUE);
    if (NT_SUCCESS(status)) {
        handle->Stream = stream;
        handle->GrantedAccess = granted;
        /* We own the successful CREATE. The original DeviceObject and VPB
         * stay untouched. Neither upper context points into NTFS's backing FCB. */
        file->FsContext = &stream->Header;
        file->FsContext2 = handle;
        file->SectionObjectPointer = &stream->Sections;
        SetFlag(file->Flags, FO_CACHE_SUPPORTED);
        InterlockedIncrement(&ProbeFileObjects);
        Data->Iopb->Parameters.Create.SecurityContext->AccessState->PreviouslyGrantedAccess |= granted;
        Data->Iopb->Parameters.Create.SecurityContext->AccessState->RemainingDesiredAccess &=
            ~(granted | MAXIMUM_ALLOWED);
        Data->IoStatus.Information = created ? FILE_CREATED : FILE_OPENED;
    }
    ProbeRelease(&stream->Resource);
    if (!NT_SUCCESS(status)) goto Exit;
    if (created) {
        KeAcquireSpinLock(&ProbeListLock, &irql);
        InsertTailList(&ProbeStreams, &stream->Link);
        KeReleaseSpinLock(&ProbeListLock, irql);
        ProbeStreamCount++;
    }
Exit:
    if (!NT_SUCCESS(status)) {
        if (handle != NULL) ExFreePoolWithTag(handle, PROBE_TAG);
        if (created) ProbeFreeStream(stream);
    }
    ProbeRelease(&ProbeNamespaceResource);
    return status;
}

/* Materialize the extended range with ordinary noncached backing writes.
 * Paging writes do not advance NTFS's valid data length. Claiming a larger
 * upper VDL without zeroing could expose old disk contents when Cc advances it.
 * Preserve an existing partial sector; the backing has no second data cache. */
static NTSTATUS ProbeZeroGrowth(PPROBE_STREAM Stream, LARGE_INTEGER Size)
{
    PVOID buffer;
    LARGE_INTEGER offset;
    LONGLONG rounded = (Size.QuadPart + Stream->SectorSize - 1) & ~((LONGLONG)Stream->SectorSize - 1);
    ULONG length, transferred, tail;
    NTSTATUS status;
    if (Size.QuadPart <= Stream->Header.FileSize.QuadPart) return STATUS_SUCCESS;
    status = ProbeFlush(Stream);
    if (!NT_SUCCESS(status)) return status;
    buffer = FltAllocatePoolAlignedWithTag(Stream->BackingInstance, NonPagedPoolNx, 65536, PROBE_TAG);
    if (buffer == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(buffer, 65536);
    offset.QuadPart = Stream->Header.FileSize.QuadPart & ~((LONGLONG)Stream->SectorSize - 1);
    tail = (ULONG)(Stream->Header.FileSize.QuadPart - offset.QuadPart);
    if (tail != 0) {
        status = FltReadFile(Stream->BackingInstance, Stream->BackingObject, &offset,
            Stream->SectorSize, buffer, FLTFL_IO_OPERATION_NON_CACHED |
            FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, &transferred, NULL, NULL);
        if (!NT_SUCCESS(status) || transferred < tail) {
            if (NT_SUCCESS(status)) status = STATUS_UNEXPECTED_IO_ERROR;
            goto Exit;
        }
        RtlZeroMemory((PUCHAR)buffer + tail, 65536 - tail);
    }
    while (offset.QuadPart < rounded) {
        length = (ULONG)min(65536LL, rounded - offset.QuadPart);
        status = FltWriteFile(Stream->BackingInstance, Stream->BackingObject, &offset,
            length, buffer, FLTFL_IO_OPERATION_NON_CACHED |
            FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, &transferred, NULL, NULL);
        if (!NT_SUCCESS(status) || transferred != length) {
            if (NT_SUCCESS(status)) status = STATUS_UNEXPECTED_IO_ERROR;
            goto Exit;
        }
        offset.QuadPart += length;
        if (tail != 0) { RtlZeroMemory(buffer, 65536); tail = 0; }
    }
Exit:
    FltFreePoolAlignedWithTag(Stream->BackingInstance, buffer, PROBE_TAG);
    return status;
}

static NTSTATUS ProbeResize(PPROBE_STREAM Stream, PFILE_OBJECT FileObject, LARGE_INTEGER Size)
{
    FILE_END_OF_FILE_INFORMATION end;
    CC_FILE_SIZES sizes;
    NTSTATUS status;
    if (Size.QuadPart < 0 || Size.QuadPart > PROBE_MAX_BYTES) return STATUS_FILE_TOO_LARGE;
    if (Size.QuadPart < Stream->Header.FileSize.QuadPart &&
        !MmCanFileBeTruncated(&Stream->Sections, &Size)) return STATUS_USER_MAPPED_FILE;
    status = ProbeZeroGrowth(Stream, Size);
    if (!NT_SUCCESS(status)) return status;
    end.EndOfFile = Size;
    status = FltSetInformationFile(Stream->BackingInstance, Stream->BackingObject,
        &end, sizeof(end), FileEndOfFileInformation);
    if (!NT_SUCCESS(status)) return status;
    Stream->Header.FileSize = Size;
    Stream->Header.AllocationSize.QuadPart = (Size.QuadPart + PAGE_SIZE - 1) & ~((LONGLONG)PAGE_SIZE - 1);
    Stream->Header.ValidDataLength = Size; /* Every extended byte was materialized. */
    if (Stream->Sections.SharedCacheMap != NULL) {
        ProbeInitializeCache(Stream, FileObject);
        sizes.AllocationSize = Stream->Header.AllocationSize;
        sizes.FileSize = Size;
        sizes.ValidDataLength = Size;
        CcSetFileSizes(FileObject, &sizes);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS ProbeReadWrite(PFLT_CALLBACK_DATA Data, PPROBE_STREAM Stream)
{
    BOOLEAN write = Data->Iopb->MajorFunction == IRP_MJ_WRITE;
    ULONG length = write ? Data->Iopb->Parameters.Write.Length : Data->Iopb->Parameters.Read.Length;
    LARGE_INTEGER offset = write ? Data->Iopb->Parameters.Write.ByteOffset : Data->Iopb->Parameters.Read.ByteOffset;
    PFILE_OBJECT file = Data->Iopb->TargetFileObject;
    PMDL mdl = write ? Data->Iopb->Parameters.Write.MdlAddress : Data->Iopb->Parameters.Read.MdlAddress;
    PVOID buffer;
    NTSTATUS status;
    if (length == 0) return STATUS_SUCCESS;
    if (mdl == NULL && !FLT_IS_SYSTEM_BUFFER(Data)) {
        status = FltLockUserBuffer(Data);
        if (!NT_SUCCESS(status)) return status;
        mdl = write ? Data->Iopb->Parameters.Write.MdlAddress : Data->Iopb->Parameters.Read.MdlAddress;
    }
    buffer = mdl != NULL ? MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute) :
        write ? Data->Iopb->Parameters.Write.WriteBuffer : Data->Iopb->Parameters.Read.ReadBuffer;
    if (buffer == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    ProbeAcquire(&Stream->Resource);
    __try {
        if (offset.QuadPart == (LONGLONG)(LONG)FILE_WRITE_TO_END_OF_FILE && write) offset = Stream->Header.FileSize;
        if (offset.QuadPart == (LONGLONG)(LONG)FILE_USE_FILE_POINTER_POSITION) offset = file->CurrentByteOffset;
        if (offset.QuadPart < 0 || offset.QuadPart > PROBE_MAX_BYTES ||
            length > PROBE_MAX_BYTES - (ULONGLONG)offset.QuadPart) {
            status = STATUS_INVALID_PARAMETER;
            __leave;
        }
        if (!write) {
            if (offset.QuadPart >= Stream->Header.FileSize.QuadPart) {
                status = STATUS_END_OF_FILE;
                __leave;
            }
            length = (ULONG)min((LONGLONG)length, Stream->Header.FileSize.QuadPart - offset.QuadPart);
        } else if (offset.QuadPart + length > Stream->Header.FileSize.QuadPart) {
            LARGE_INTEGER size;
            size.QuadPart = offset.QuadPart + length;
            status = ProbeResize(Stream, file, size);
            if (!NT_SUCCESS(status)) __leave;
        }
        ProbeInitializeCache(Stream, file);
        if (write) {
            CcCopyWrite(file, &offset, length, TRUE, buffer);
            Data->IoStatus.Information = length;
            status = STATUS_SUCCESS;
            if (FlagOn(file->Flags, FO_WRITE_THROUGH)) status = ProbeFlush(Stream);
        } else {
            CcCopyRead(file, &offset, length, TRUE, buffer, &Data->IoStatus);
            status = Data->IoStatus.Status;
        }
        if (NT_SUCCESS(status) && FlagOn(file->Flags, FO_SYNCHRONOUS_IO))
            file->CurrentByteOffset.QuadPart = offset.QuadPart + Data->IoStatus.Information;
    } __except(EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
    ProbeRelease(&Stream->Resource);
    return status;
}

static NTSTATUS ProbeQuery(PFLT_CALLBACK_DATA Data, PPROBE_STREAM Stream, PPROBE_HANDLE Handle)
{
    FILE_INFORMATION_CLASS cls = Data->Iopb->Parameters.QueryFileInformation.FileInformationClass;
    ULONG length = Data->Iopb->Parameters.QueryFileInformation.Length;
    PVOID output = Data->Iopb->Parameters.QueryFileInformation.InfoBuffer;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG returned = 0;
    ULONG prefix = 0, copied;
    PFILE_NAME_INFORMATION name;
    UNICODE_STRING relative = Stream->Name;
    ProbeAcquire(&Stream->Resource);
    relative.Buffer = (PWCH)((PUCHAR)relative.Buffer + Stream->VolumeLength);
    relative.Length -= Stream->VolumeLength;
    __try {
        if (cls == FileAllInformation) {
            PFILE_ALL_INFORMATION all;
            ULONG bytes = sizeof(FILE_ALL_INFORMATION) + SAFEUPLOAD_MAX_PATH_BYTES;
            prefix = FIELD_OFFSET(FILE_ALL_INFORMATION, NameInformation);
            if (length < prefix + sizeof(ULONG)) { status = STATUS_INFO_LENGTH_MISMATCH; __leave; }
            all = ExAllocatePool2(POOL_FLAG_PAGED, bytes, PROBE_TAG);
            if (all == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; __leave; }
            status = FltQueryInformationFile(Stream->BackingInstance, Stream->BackingObject,
                all, bytes, cls, &returned);
            if (NT_SUCCESS(status)) {
                all->StandardInformation.EndOfFile = Stream->Header.FileSize;
                all->StandardInformation.AllocationSize = Stream->Header.AllocationSize;
                all->AccessInformation.AccessFlags = Handle->GrantedAccess;
                all->PositionInformation.CurrentByteOffset = Data->Iopb->TargetFileObject->CurrentByteOffset;
                RtlCopyMemory(output, all, prefix);
            }
            ExFreePoolWithTag(all, PROBE_TAG);
            if (!NT_SUCCESS(status)) __leave;
        }
        if (cls == FileNameInformation || cls == FileNormalizedNameInformation || cls == FileAllInformation) {
            if (length < prefix + sizeof(ULONG)) { status = STATUS_INFO_LENGTH_MISMATCH; __leave; }
            name = (PFILE_NAME_INFORMATION)((PUCHAR)output + prefix);
            name->FileNameLength = relative.Length;
            copied = min(relative.Length, length - prefix - FIELD_OFFSET(FILE_NAME_INFORMATION, FileName));
            copied &= ~1UL;
            RtlCopyMemory(name->FileName, relative.Buffer, copied);
            Data->IoStatus.Information = prefix + sizeof(ULONG) + copied;
            status = copied == relative.Length ? STATUS_SUCCESS : STATUS_BUFFER_OVERFLOW;
        } else if (cls == FilePositionInformation) {
            if (length < sizeof(FILE_POSITION_INFORMATION)) { status = STATUS_INFO_LENGTH_MISMATCH; __leave; }
            ((PFILE_POSITION_INFORMATION)output)->CurrentByteOffset = Data->Iopb->TargetFileObject->CurrentByteOffset;
            Data->IoStatus.Information = sizeof(FILE_POSITION_INFORMATION);
        } else if (cls == FileAccessInformation) {
            if (length < sizeof(FILE_ACCESS_INFORMATION)) { status = STATUS_INFO_LENGTH_MISMATCH; __leave; }
            ((PFILE_ACCESS_INFORMATION)output)->AccessFlags = Handle->GrantedAccess;
            Data->IoStatus.Information = sizeof(FILE_ACCESS_INFORMATION);
        } else if (cls == FileAlternateNameInformation) {
            status = STATUS_OBJECT_NAME_NOT_FOUND;
        } else {
            status = FltQueryInformationFile(Stream->BackingInstance, Stream->BackingObject,
                output, length, cls, &returned);
            Data->IoStatus.Information = returned;
            if (NT_SUCCESS(status) && cls == FileStandardInformation) {
                ((PFILE_STANDARD_INFORMATION)output)->EndOfFile = Stream->Header.FileSize;
                ((PFILE_STANDARD_INFORMATION)output)->AllocationSize = Stream->Header.AllocationSize;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
    ProbeRelease(&Stream->Resource);
    return status;
}

static NTSTATUS ProbeRename(PFLT_CALLBACK_DATA Data, PPROBE_STREAM Stream)
{
    PFILE_RENAME_INFORMATION rename = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    PFLT_FILE_NAME_INFORMATION destination = NULL;
    UNICODE_STRING relative;
    NTSTATUS status;
    ULONG length = Data->Iopb->Parameters.SetFileInformation.Length;
    KIRQL irql;
    if (length < (ULONG)FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName) ||
        rename->FileNameLength == 0 || (rename->FileNameLength & 1) ||
        rename->FileNameLength > length - FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName))
        return STATUS_INVALID_PARAMETER;
    if (rename->ReplaceIfExists) return STATUS_NOT_SUPPORTED;
    ProbeAcquire(&ProbeNamespaceResource);
    status = FltGetDestinationFileNameInformation(Stream->OriginalInstance,
        Data->Iopb->TargetFileObject, rename->RootDirectory, rename->FileName,
        rename->FileNameLength, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY,
        &destination);
    if (!NT_SUCCESS(status)) goto Exit;
    status = FltParseFileNameInformation(destination);
    if (!NT_SUCCESS(status)) goto Exit;
    relative.Buffer = (PWCH)((PUCHAR)destination->Name.Buffer + destination->Volume.Length);
    relative.Length = destination->Name.Length - destination->Volume.Length;
    relative.MaximumLength = relative.Length;
    if (destination->Volume.Length != Stream->VolumeLength ||
        RtlCompareMemory(Stream->Name.Buffer, destination->Volume.Buffer, Stream->VolumeLength) != Stream->VolumeLength ||
        !RtlPrefixUnicodeString(&ProbePrefix, &relative, TRUE) ||
        !RtlEqualUnicodeString(&destination->ParentDir, &ProbePrefix, TRUE) ||
        destination->Name.Length > sizeof(Stream->NameBuffer)) {
        status = STATUS_NOT_SUPPORTED;
        goto Exit;
    }
    status = SafeUploadStageCheckRenameAccess(Stream->OriginalInstance, &destination->Name, FALSE);
    if (!NT_SUCCESS(status)) goto Exit;
    ProbeAcquire(&Stream->Resource);
    KeAcquireSpinLock(&ProbeListLock, &irql);
    Stream->Name.Length = destination->Name.Length;
    RtlCopyMemory(Stream->Name.Buffer, destination->Name.Buffer, destination->Name.Length);
    KeReleaseSpinLock(&ProbeListLock, irql);
    ProbeRelease(&Stream->Resource);
    /* A completed virtual rename never reaches FltMgr's normal post-rename
     * invalidation. Purge all names supplied by this bounded provider. */
    status = FltPurgeFileNameInformationCache(Stream->OriginalInstance, NULL);
Exit:
    if (destination != NULL) FltReleaseFileNameInformation(destination);
    ProbeRelease(&ProbeNamespaceResource);
    return status;
}

static FLT_PREOP_CALLBACK_STATUS ProbePreOperation(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS Objects, PVOID *CompletionContext)
{
    PPROBE_STREAM stream;
    PPROBE_HANDLE handle;
    PFILE_OBJECT file = Data->Iopb->TargetFileObject;
    NTSTATUS status = STATUS_NOT_SUPPORTED;
    *CompletionContext = NULL;
    if (Data->Iopb->MajorFunction == IRP_MJ_QUERY_OPEN ||
        Data->Iopb->MajorFunction == IRP_MJ_NETWORK_QUERY_OPEN) {
        PLIST_ENTRY link;
        KIRQL irql;
        BOOLEAN privateView = FALSE;
        KeAcquireSpinLock(&ProbeListLock, &irql);
        for (link = ProbeStreams.Flink; link != &ProbeStreams; link = link->Flink) {
            PPROBE_STREAM candidate = CONTAINING_RECORD(link, PROBE_STREAM, Link);
            if (candidate->Owner == FltGetRequestorProcess(Data)) { privateView = TRUE; break; }
        }
        KeReleaseSpinLock(&ProbeListLock, irql);
        if (privateView) {
            if (Data->Iopb->MajorFunction == IRP_MJ_QUERY_OPEN) return FLT_PREOP_DISALLOW_FSFILTER_IO;
            if (FLT_IS_FASTIO_OPERATION(Data)) return FLT_PREOP_DISALLOW_FASTIO;
        }
    }
    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
        PFLT_FILE_NAME_INFORMATION name = NULL;
        UNICODE_STRING relative;
        if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY))
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        status = FltGetFileNameInformation(Data,
            FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY, &name);
        if (!NT_SUCCESS(status)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
        status = FltParseFileNameInformation(name);
        if (!NT_SUCCESS(status) || name->Name.Length <= name->Volume.Length) {
            FltReleaseFileNameInformation(name);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        relative.Buffer = (PWCH)((PUCHAR)name->Name.Buffer + name->Volume.Length);
        relative.Length = name->Name.Length - name->Volume.Length;
        relative.MaximumLength = relative.Length;
        if (!RtlPrefixUnicodeString(&ProbePrefix, &relative, TRUE)) {
            FltReleaseFileNameInformation(name);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        /* An observer reads the real destination below the isolation layer.
         * Do not hide an accidental real file behind a synthesized not-found. */
        if ((Data->Iopb->Parameters.Create.Options >> 24) == FILE_OPEN &&
            !FlagOn(Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess,
                FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE | MAXIMUM_ALLOWED)) {
            PLIST_ENTRY link;
            BOOLEAN privateView = FALSE;
            ProbeAcquire(&ProbeNamespaceResource);
            for (link = ProbeStreams.Flink; link != &ProbeStreams; link = link->Flink) {
                PPROBE_STREAM candidate = CONTAINING_RECORD(link, PROBE_STREAM, Link);
                if (candidate->Owner == FltGetRequestorProcess(Data) &&
                    RtlEqualUnicodeString(&candidate->Name, &name->Name, TRUE)) {
                    privateView = TRUE;
                    break;
                }
            }
            ProbeRelease(&ProbeNamespaceResource);
            if (!privateView) {
                FltReleaseFileNameInformation(name);
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            }
        }
        Data->IoStatus.Information = 0;
        status = ProbeCreate(Data, Objects, name);
        FltReleaseFileNameInformation(name);
        Data->IoStatus.Status = status;
        return FLT_PREOP_COMPLETE;
    }
    stream = ProbeStreamForObject(file);
    if (stream == NULL) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (Data->Iopb->MajorFunction == IRP_MJ_QUERY_OPEN) return FLT_PREOP_DISALLOW_FSFILTER_IO;
    if (FLT_IS_FASTIO_OPERATION(Data)) return FLT_PREOP_DISALLOW_FASTIO;
    Data->IoStatus.Information = 0;
    handle = file->FsContext2;
    switch (Data->Iopb->MajorFunction) {
    case IRP_MJ_READ:
    case IRP_MJ_WRITE:
        if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) {
            /* Preserve paging flags, MDLs and asynchronous completion. The
             * upper cache/section stays on the destination; only this request
             * goes to the backing instance. References survive until unload. */
            Data->Iopb->TargetInstance = stream->BackingInstance;
            Data->Iopb->TargetFileObject = stream->BackingObject;
            FltSetCallbackDataDirty(Data);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        if (handle == NULL || handle->Cleaned) {
            status = STATUS_FILE_CLOSED;
            break;
        }
        status = ProbeReadWrite(Data, stream);
        break;
    case IRP_MJ_QUERY_INFORMATION:
        status = ProbeQuery(Data, stream, handle);
        break;
    case IRP_MJ_QUERY_VOLUME_INFORMATION:
        status = FltQueryVolumeInformation(stream->OriginalInstance, &Data->IoStatus,
            Data->Iopb->Parameters.QueryVolumeInformation.VolumeBuffer,
            Data->Iopb->Parameters.QueryVolumeInformation.Length,
            Data->Iopb->Parameters.QueryVolumeInformation.FsInformationClass);
        break;
    case IRP_MJ_SET_INFORMATION:
        if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileEndOfFileInformation &&
            Data->Iopb->Parameters.SetFileInformation.AdvanceOnly) {
            /* Cc may advance the on-disk VDL after cleanup. This is not a
             * resize and must never reinitialize the upper private cache map. */
            Data->Iopb->TargetInstance = stream->BackingInstance;
            Data->Iopb->TargetFileObject = stream->BackingObject;
            FltSetCallbackDataDirty(Data);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[SafeUploadArch] advance-only file=%p\n", file);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        if (handle == NULL || handle->Cleaned) {
            status = STATUS_FILE_CLOSED;
            break;
        }
        if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation)
            status = ProbeRename(Data, stream);
        else if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileEndOfFileInformation &&
            Data->Iopb->Parameters.SetFileInformation.Length >= sizeof(FILE_END_OF_FILE_INFORMATION)) {
            ProbeAcquire(&stream->Resource);
            __try {
                status = ProbeResize(stream, file,
                    ((PFILE_END_OF_FILE_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer)->EndOfFile);
            } __except(EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
            ProbeRelease(&stream->Resource);
        } else if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FilePositionInformation &&
            Data->Iopb->Parameters.SetFileInformation.Length >= sizeof(FILE_POSITION_INFORMATION)) {
            LARGE_INTEGER position = ((PFILE_POSITION_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer)->CurrentByteOffset;
            if (position.QuadPart >= 0) { file->CurrentByteOffset = position; status = STATUS_SUCCESS; }
            else status = STATUS_INVALID_PARAMETER;
        } else if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileAllocationInformation &&
            Data->Iopb->Parameters.SetFileInformation.Length >= sizeof(FILE_ALLOCATION_INFORMATION)) {
            PFILE_ALLOCATION_INFORMATION allocation = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
            FILE_STANDARD_INFORMATION standard = {0};
            ProbeAcquire(&stream->Resource);
            __try {
                if (allocation->AllocationSize.QuadPart < 0 || allocation->AllocationSize.QuadPart > PROBE_MAX_BYTES)
                    status = STATUS_FILE_TOO_LARGE;
                else {
                    status = STATUS_SUCCESS;
                    if (allocation->AllocationSize.QuadPart < stream->Header.FileSize.QuadPart)
                        status = ProbeResize(stream, file, allocation->AllocationSize);
                    if (NT_SUCCESS(status)) status = FltSetInformationFile(stream->BackingInstance,
                        stream->BackingObject, allocation, sizeof(*allocation), FileAllocationInformation);
                    if (NT_SUCCESS(status)) status = FltQueryInformationFile(stream->BackingInstance,
                        stream->BackingObject, &standard, sizeof(standard), FileStandardInformation, NULL);
                    if (NT_SUCCESS(status)) {
                        stream->Header.AllocationSize = standard.AllocationSize;
                        if (stream->Sections.SharedCacheMap != NULL) {
                            CC_FILE_SIZES sizes;
                            ProbeInitializeCache(stream, file);
                            sizes.AllocationSize = standard.AllocationSize;
                            sizes.FileSize = stream->Header.FileSize;
                            sizes.ValidDataLength = stream->Header.ValidDataLength;
                            CcSetFileSizes(file, &sizes);
                        }
                    }
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
            ProbeRelease(&stream->Resource);
        }
        break;
    case IRP_MJ_FLUSH_BUFFERS:
        status = ProbeFlush(stream);
        break;
    case IRP_MJ_CLEANUP:
        if (handle != NULL && !handle->Cleaned) {
            ProbeAcquire(&stream->Resource);
            (VOID)ProbeFlush(stream);
            IoRemoveShareAccess(file, &stream->ShareAccess);
            handle->Cleaned = TRUE;
            SetFlag(file->Flags, FO_CLEANUP_COMPLETE);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[SafeUploadArch] cleanup file=%p cache-before=%p\n", file, file->PrivateCacheMap);
            (VOID)CcUninitializeCacheMap(file, NULL, NULL);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[SafeUploadArch] cleanup file=%p cache-after=%p\n", file, file->PrivateCacheMap);
            ProbeRelease(&stream->Resource);
        }
        status = STATUS_SUCCESS;
        break;
    case IRP_MJ_CLOSE:
        if (handle != NULL) {
            ExFreePoolWithTag(handle, PROBE_TAG);
            file->FsContext2 = NULL;
            InterlockedDecrement(&ProbeFileObjects);
        }
        status = STATUS_SUCCESS;
        break;
    case IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION:
        ProbeAcquire(&stream->Resource);
        status = STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY;
        break;
    case IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION:
        ProbeRelease(&stream->Resource);
        status = STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY;
        break;
    case IRP_MJ_ACQUIRE_FOR_MOD_WRITE:
        KeEnterCriticalRegion();
        if (ExAcquireResourceSharedLite(&stream->PagingResource, FALSE)) {
            *Data->Iopb->Parameters.AcquireForModifiedPageWriter.ResourceToRelease = &stream->PagingResource;
            status = STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY;
        } else { KeLeaveCriticalRegion(); status = STATUS_CANT_WAIT; }
        break;
    case IRP_MJ_RELEASE_FOR_MOD_WRITE:
        ProbeRelease(&stream->PagingResource);
        status = STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY;
        break;
    case IRP_MJ_ACQUIRE_FOR_CC_FLUSH:
        ProbeAcquire(&stream->PagingResource);
        status = STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY;
        break;
    case IRP_MJ_RELEASE_FOR_CC_FLUSH:
        ProbeRelease(&stream->PagingResource);
        status = STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY;
        break;
    default:
        break; /* Never let a foreign filesystem decode an owned upper FCB. */
    }
    Data->IoStatus.Status = status;
    if (!NT_SUCCESS(status) || Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[SafeUploadArch] op=%u class=%u status=%08x\n", Data->Iopb->MajorFunction,
            Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION ?
                Data->Iopb->Parameters.SetFileInformation.FileInformationClass : 0, status);
    }
    return FLT_PREOP_COMPLETE;
}

#define PROBE_OPERATION(major) { major, 0, ProbePreOperation, NULL }
static CONST FLT_OPERATION_REGISTRATION ProbeOperations[] = {
    PROBE_OPERATION(IRP_MJ_CREATE), PROBE_OPERATION(IRP_MJ_CLOSE),
    PROBE_OPERATION(IRP_MJ_READ), PROBE_OPERATION(IRP_MJ_WRITE),
    PROBE_OPERATION(IRP_MJ_QUERY_INFORMATION), PROBE_OPERATION(IRP_MJ_SET_INFORMATION),
    PROBE_OPERATION(IRP_MJ_QUERY_EA), PROBE_OPERATION(IRP_MJ_SET_EA),
    PROBE_OPERATION(IRP_MJ_FLUSH_BUFFERS), PROBE_OPERATION(IRP_MJ_QUERY_VOLUME_INFORMATION),
    PROBE_OPERATION(IRP_MJ_SET_VOLUME_INFORMATION), PROBE_OPERATION(IRP_MJ_DIRECTORY_CONTROL),
    PROBE_OPERATION(IRP_MJ_FILE_SYSTEM_CONTROL), PROBE_OPERATION(IRP_MJ_DEVICE_CONTROL),
    PROBE_OPERATION(IRP_MJ_INTERNAL_DEVICE_CONTROL), PROBE_OPERATION(IRP_MJ_SHUTDOWN),
    PROBE_OPERATION(IRP_MJ_LOCK_CONTROL), PROBE_OPERATION(IRP_MJ_CLEANUP),
    PROBE_OPERATION(IRP_MJ_CREATE_MAILSLOT), PROBE_OPERATION(IRP_MJ_QUERY_SECURITY),
    PROBE_OPERATION(IRP_MJ_SET_SECURITY), PROBE_OPERATION(IRP_MJ_POWER),
    PROBE_OPERATION(IRP_MJ_SYSTEM_CONTROL), PROBE_OPERATION(IRP_MJ_DEVICE_CHANGE),
    PROBE_OPERATION(IRP_MJ_QUERY_QUOTA), PROBE_OPERATION(IRP_MJ_SET_QUOTA),
    PROBE_OPERATION(IRP_MJ_PNP), PROBE_OPERATION(IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION),
    PROBE_OPERATION(IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION),
    PROBE_OPERATION(IRP_MJ_ACQUIRE_FOR_MOD_WRITE), PROBE_OPERATION(IRP_MJ_RELEASE_FOR_MOD_WRITE),
    PROBE_OPERATION(IRP_MJ_ACQUIRE_FOR_CC_FLUSH), PROBE_OPERATION(IRP_MJ_RELEASE_FOR_CC_FLUSH),
    PROBE_OPERATION(IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE), PROBE_OPERATION(IRP_MJ_NETWORK_QUERY_OPEN),
    PROBE_OPERATION(IRP_MJ_MDL_READ), PROBE_OPERATION(IRP_MJ_MDL_READ_COMPLETE),
    PROBE_OPERATION(IRP_MJ_PREPARE_MDL_WRITE), PROBE_OPERATION(IRP_MJ_MDL_WRITE_COMPLETE),
    PROBE_OPERATION(IRP_MJ_VOLUME_MOUNT), PROBE_OPERATION(IRP_MJ_VOLUME_DISMOUNT),
    PROBE_OPERATION(IRP_MJ_QUERY_OPEN), {IRP_MJ_OPERATION_END}
};

static NTSTATUS ProbeInstanceSetup(PCFLT_RELATED_OBJECTS Objects, FLT_INSTANCE_SETUP_FLAGS Flags,
    DEVICE_TYPE DeviceType, FLT_FILESYSTEM_TYPE FsType)
{
    UNREFERENCED_PARAMETER(Objects); UNREFERENCED_PARAMETER(Flags);
    return DeviceType == FILE_DEVICE_DISK_FILE_SYSTEM && FsType == FLT_FSTYPE_NTFS ?
        STATUS_SUCCESS : STATUS_FLT_DO_NOT_ATTACH;
}

static NTSTATUS ProbeInstanceTeardown(PCFLT_RELATED_OBJECTS Objects, FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Objects); UNREFERENCED_PARAMETER(Flags);
    return ProbeStreamCount == 0 ? STATUS_SUCCESS : STATUS_FLT_DO_NOT_DETACH;
}

static NTSTATUS ProbeGenerateName(PFLT_INSTANCE Instance, PFILE_OBJECT FileObject,
    PFLT_CALLBACK_DATA Data, FLT_FILE_NAME_OPTIONS Options, PBOOLEAN CacheName,
    PFLT_NAME_CONTROL Output)
{
    PPROBE_STREAM stream = ProbeStreamForObject(FileObject);
    PFLT_FILE_NAME_INFORMATION lower = NULL;
    NTSTATUS status;
    /* The bounded probe deliberately avoids a second namespace cache. Names
     * can change on every upper handle when a virtual rename completes. */
    *CacheName = FALSE;
    if (stream != NULL) {
        if (FltGetFileNameFormat(Options) == FLT_FILE_NAME_SHORT)
            return STATUS_OBJECT_NAME_NOT_FOUND;
        ProbeAcquire(&stream->Resource);
        status = FltCheckAndGrowNameControl(Output, stream->Name.Length);
        if (NT_SUCCESS(status)) RtlCopyUnicodeString(&Output->Name, &stream->Name);
        ProbeRelease(&stream->Resource);
        return status;
    }
    Options &= ~FLT_FILE_NAME_REQUEST_FROM_CURRENT_PROVIDER;
    Options |= FLT_FILE_NAME_DO_NOT_CACHE;
    if (Data != NULL) status = FltGetFileNameInformation(Data, Options, &lower);
    else status = FltGetFileNameInformationUnsafe(FileObject, Instance, Options, &lower);
    if (NT_SUCCESS(status)) {
        status = FltCheckAndGrowNameControl(Output, lower->Name.Length);
        if (NT_SUCCESS(status)) RtlCopyUnicodeString(&Output->Name, &lower->Name);
        FltReleaseFileNameInformation(lower);
    }
    return status;
}

static NTSTATUS ProbeNormalizeComponent(PFLT_INSTANCE Instance, PCUNICODE_STRING Parent,
    USHORT VolumeNameLength, PCUNICODE_STRING Component, PFILE_NAMES_INFORMATION Output,
    ULONG Length, FLT_NORMALIZE_NAME_FLAGS Flags, PVOID *Context)
{
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io;
    HANDLE directory = NULL;
    PFILE_OBJECT object = NULL;
    UNICODE_STRING parent = *Parent, component = *Component;
    ULONG returned;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(VolumeNameLength);
    UNREFERENCED_PARAMETER(Context);
    InitializeObjectAttributes(&attributes, &parent, OBJ_KERNEL_HANDLE |
        (FlagOn(Flags, FLTFL_NORMALIZE_NAME_CASE_SENSITIVE) ? 0 : OBJ_CASE_INSENSITIVE), NULL, NULL);
    status = FltCreateFileEx(SafeUploadData.Filter, Instance, &directory, &object,
        FILE_LIST_DIRECTORY | SYNCHRONIZE, &attributes, &io, NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0, IO_IGNORE_SHARE_ACCESS_CHECK);
    if (NT_SUCCESS(status)) {
        status = FltQueryDirectoryFile(Instance, object, Output, Length,
            FileNamesInformation, TRUE, &component, TRUE, &returned);
        ObDereferenceObject(object);
        FltClose(directory);
    }
    return status;
}

static NTSTATUS ProbeUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    PLIST_ENTRY link;
    NTSTATUS status = STATUS_SUCCESS;
    UNREFERENCED_PARAMETER(Flags);
    ProbeAcquire(&ProbeNamespaceResource);
    ProbeStopping = TRUE;
    for (link = ProbeStreams.Flink; link != &ProbeStreams; link = link->Flink) {
        PPROBE_STREAM stream = CONTAINING_RECORD(link, PROBE_STREAM, Link);
        ProbeAcquire(&stream->Resource);
        if (stream->ShareAccess.OpenCount != 0) {
            ProbeRelease(&stream->Resource);
            status = STATUS_FLT_DO_NOT_DETACH;
            break;
        }
        status = ProbeFlush(stream);
        if (NT_SUCCESS(status) && !CcPurgeCacheSection(&stream->Sections, NULL, 0, TRUE)) {
            status = STATUS_FLT_DO_NOT_DETACH;
        }
        if (NT_SUCCESS(status) && (stream->Sections.SharedCacheMap != NULL ||
            stream->Sections.DataSectionObject != NULL || stream->Sections.ImageSectionObject != NULL))
            status = STATUS_FLT_DO_NOT_DETACH;
        ProbeRelease(&stream->Resource);
        if (!NT_SUCCESS(status)) break;
    }
    if (!NT_SUCCESS(status) || InterlockedCompareExchange(&ProbeFileObjects, 0, 0) != 0) {
        ProbeStopping = FALSE;
        ProbeRelease(&ProbeNamespaceResource);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[SafeUploadArch] unload deferred status=%08x objects=%ld\n", status,
            InterlockedCompareExchange(&ProbeFileObjects, 0, 0));
        return STATUS_FLT_DO_NOT_DETACH;
    }
    ProbeRelease(&ProbeNamespaceResource);
    /* Our explicit instance references must be dropped before unregister;
     * otherwise FltMgr waits for references that only our unload would free. */
    for (link = ProbeStreams.Flink; link != &ProbeStreams; link = link->Flink) {
        PPROBE_STREAM stream = CONTAINING_RECORD(link, PROBE_STREAM, Link);
        if (stream->BackingObject != NULL) ObDereferenceObject(stream->BackingObject);
        if (stream->BackingHandle != NULL) FltClose(stream->BackingHandle);
        stream->BackingObject = NULL;
        stream->BackingHandle = NULL;
        if (stream->BackingInstance != NULL) FltObjectDereference(stream->BackingInstance);
        if (stream->OriginalInstance != NULL) FltObjectDereference(stream->OriginalInstance);
        stream->BackingInstance = NULL;
        stream->OriginalInstance = NULL;
    }
    FltUnregisterFilter(SafeUploadData.Filter);
    while (!IsListEmpty(&ProbeStreams)) {
        PPROBE_STREAM stream = CONTAINING_RECORD(RemoveHeadList(&ProbeStreams), PROBE_STREAM, Link);
        FsRtlTeardownPerStreamContexts(&stream->Header);
        ProbeFreeStream(stream);
    }
    ExDeleteResourceLite(&ProbeNamespaceResource);
    return STATUS_SUCCESS;
}

static CONST FLT_REGISTRATION ProbeRegistration = {
    sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION, 0, NULL, ProbeOperations,
    ProbeUnload, ProbeInstanceSetup, ProbeInstanceTeardown, NULL, NULL,
    ProbeGenerateName, ProbeNormalizeComponent
};

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(RegistryPath);
    InitializeListHead(&ProbeStreams);
    KeInitializeSpinLock(&ProbeListLock);
    status = ExInitializeResourceLite(&ProbeNamespaceResource);
    if (!NT_SUCCESS(status)) return status;
    status = FltRegisterFilter(DriverObject, &ProbeRegistration, &SafeUploadData.Filter);
    if (NT_SUCCESS(status)) {
        status = FltStartFiltering(SafeUploadData.Filter);
        if (!NT_SUCCESS(status)) FltUnregisterFilter(SafeUploadData.Filter);
    }
    if (!NT_SUCCESS(status)) ExDeleteResourceLite(&ProbeNamespaceResource);
    return status;
}
