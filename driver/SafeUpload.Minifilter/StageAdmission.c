/* Passive worker helpers for the observe-only writer-state primitives. */
#include "Stage.h"
#include <ntstrsafe.h>

/* Canary-only allocations carry their own tag so Verifier low-resources simulation can fail exactly
 * the canary (tag reads "SUcN" in pool dumps), without touching any other driver allocation. */
#define SAFEUPLOAD_CANARY_POOL_TAG 'NcUS'

static NTSTATUS StageCanaryVerifySecurity(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT FileObject,
    _Out_ PULONG Reason);
#define STAGE_CANARY_SD_BYTES 1024
static NTSTATUS StageCanaryVerifyDescriptor(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT FileObject,
    _Out_writes_bytes_(STAGE_CANARY_SD_BYTES) PUCHAR buffer, _Out_ PULONG Reason);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SafeUploadStageOpenByIdentity)
#pragma alloc_text(PAGE, SafeUploadStageAdmissionVolumeStatus)
#pragma alloc_text(PAGE, SafeUploadStageVolumeFlags)
#pragma alloc_text(PAGE, SafeUploadStageAdmissionCanaryHold)
#pragma alloc_text(PAGE, StageCanaryVerifySecurity)
#pragma alloc_text(PAGE, StageCanaryVerifyDescriptor)
#endif

NTSTATUS SafeUploadStageOpenByIdentity(
    _In_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING VolumeName,
    _In_ PFILE_OBJECT SourceObject,
    _Out_ PHANDLE Handle,
    _Outptr_result_nullonfailure_ PFILE_OBJECT *Object,
    _Out_ PUINT32 ProbeStage)
{
    FILE_INTERNAL_INFORMATION internal;
    FILE_ID_INFORMATION expected, actual;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io = {0};
    UNICODE_STRING name;
    PWCHAR buffer = NULL;
    HANDLE handle = NULL;
    PFILE_OBJECT object = NULL;
    ULONG bytes, returned;
    NTSTATUS status;

    PAGED_CODE();
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    *Handle = NULL;
    *Object = NULL;
    *ProbeStage = SAFEUPLOAD_ADMISSION_PROBE_STAGE_IDENTITY_QUERY;
    RtlZeroMemory(&internal, sizeof(internal));
    RtlZeroMemory(&expected, sizeof(expected));
    returned = 0;
    status = FltQueryInformationFile(Instance, SourceObject, &internal, sizeof(internal),
        FileInternalInformation, &returned);
    if (status != STATUS_SUCCESS) goto Exit;
    if (returned != sizeof(internal)) { status = STATUS_INFO_LENGTH_MISMATCH; goto Exit; }
    returned = 0;
    status = FltQueryInformationFile(Instance, SourceObject, &expected, sizeof(expected),
        FileIdInformation, &returned);
    if (status != STATUS_SUCCESS) goto Exit;
    if (returned != sizeof(expected)) { status = STATUS_INFO_LENGTH_MISMATCH; goto Exit; }

    /* Keep SourceObject and its handle alive in the caller until this open is closed. This prevents
     * file-ID reuse while the pathname may be renamed/replaced by another process. */
    bytes = VolumeName->Length + sizeof(WCHAR) + sizeof(internal.IndexNumber);
    if (bytes > MAXUSHORT) { status = STATUS_NAME_TOO_LONG; goto Exit; }
    buffer = ExAllocatePool2(POOL_FLAG_PAGED, bytes, SAFEUPLOAD_POOL_TAG);
    if (buffer == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    RtlCopyMemory(buffer, VolumeName->Buffer, VolumeName->Length);
    buffer[VolumeName->Length / sizeof(WCHAR)] = L'\\';
    RtlCopyMemory((PUCHAR)buffer + VolumeName->Length + sizeof(WCHAR),
        &internal.IndexNumber, sizeof(internal.IndexNumber));
    name.Buffer = buffer;
    name.Length = name.MaximumLength = (USHORT)bytes;
    InitializeObjectAttributes(&attributes, &name, OBJ_KERNEL_HANDLE, NULL, NULL);
    *ProbeStage = SAFEUPLOAD_ADMISSION_PROBE_STAGE_IDENTITY_OPEN;
    status = FltCreateFileEx2(SafeUploadData.Filter, Instance, &handle, &object,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attributes, &io, NULL, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
        FILE_OPEN_BY_FILE_ID | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
            FILE_COMPLETE_IF_OPLOCKED,
        NULL, 0, 0, NULL);
    if (status != STATUS_SUCCESS) goto Exit;
    if (object == NULL || handle == NULL) { status = STATUS_INVALID_HANDLE; goto Exit; }
    *ProbeStage = SAFEUPLOAD_ADMISSION_PROBE_STAGE_IDENTITY_VERIFY;
    RtlZeroMemory(&actual, sizeof(actual));
    returned = 0;
    status = FltQueryInformationFile(Instance, object, &actual, sizeof(actual),
        FileIdInformation, &returned);
    if (status != STATUS_SUCCESS) goto Exit;
    if (returned != sizeof(actual)) { status = STATUS_INFO_LENGTH_MISMATCH; goto Exit; }
    if (actual.VolumeSerialNumber != expected.VolumeSerialNumber ||
        !RtlEqualMemory(&actual.FileId, &expected.FileId, sizeof(actual.FileId))) {
        status = STATUS_FILE_INVALID;
        goto Exit;
    }
    /* File IDs identify the file; the pinned section-pointer identity identifies its stream.
     * A future caller passing an ADS must not silently sample the unnamed stream. */
    if (SourceObject->SectionObjectPointer == NULL || object->SectionObjectPointer == NULL ||
        SourceObject->SectionObjectPointer != object->SectionObjectPointer) {
        status = STATUS_FILE_INVALID;
        goto Exit;
    }
    *Handle = handle; handle = NULL;
    *Object = object; object = NULL;
Exit:
    /* Positive completion codes that did not produce a verified open are not successful probes. */
    if (status != STATUS_SUCCESS && NT_SUCCESS(status)) status = STATUS_UNSUCCESSFUL;
    if (object != NULL) ObDereferenceObject(object);
    if (handle != NULL) FltClose(handle);
    if (buffer != NULL) ExFreePoolWithTag(buffer, SAFEUPLOAD_POOL_TAG);
    return status;
}

static volatile LONG AdmissionFilteringReady;
static KEVENT CanaryStop;
static HANDLE CanaryThreadHandle;

#if SAFEUPLOAD_STAGING_PROTOTYPE
#define SAFEUPLOAD_CANARY_HOLD_IDLE      ((LONG)0)
#define SAFEUPLOAD_CANARY_HOLD_ARMED     ((LONG)1)
#define SAFEUPLOAD_CANARY_HOLD_PREPARING ((LONG)2)
#define SAFEUPLOAD_CANARY_HOLD_ACTIVE    ((LONG)3)
#define SAFEUPLOAD_CANARY_HOLD_COMPLETE  ((LONG)4)

static FAST_MUTEX CanaryHoldMutex;
static KEVENT CanaryHoldPathReady;
static KEVENT CanaryHoldCancel;
static LONG CanaryHoldState;
static BOOLEAN CanaryHoldReplyConsumed;
static PFLT_INSTANCE CanaryHoldInstance;
static ULONG CanaryHoldMilliseconds;
static NTSTATUS CanaryHoldStatus;
static ULONG CanaryHoldPathChars;
static WCHAR CanaryHoldPath[SAFEUPLOAD_MAX_PATH_CHARS];
#endif

NTSTATUS SafeUploadStageVolumeFlags(_In_ PFLT_VOLUME Volume, _Out_ PUINT32 Flags)
{
    PFILTER_VOLUME_STANDARD_INFORMATION information;
    ULONG bytes = sizeof(*information) + SAFEUPLOAD_MAX_PATH_CHARS * sizeof(WCHAR), returned = 0;
    NTSTATUS status;
    PAGED_CODE();
    C_ASSERT(FLTFL_VSI_DETACHED_VOLUME == SAFEUPLOAD_VOLUME_DETACHED_FLAG);
    *Flags = 0;
    information = ExAllocatePool2(POOL_FLAG_PAGED, bytes, SAFEUPLOAD_POOL_TAG);
    if (information == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    status = FltGetVolumeInformation(Volume, FilterVolumeStandardInformation, information, bytes, &returned);
    if (status == STATUS_SUCCESS) {
        if (returned < (ULONG)FIELD_OFFSET(FILTER_VOLUME_STANDARD_INFORMATION, FilterVolumeName) || returned > bytes ||
            (information->FilterVolumeNameLength % sizeof(WCHAR)) != 0 ||
            information->FilterVolumeNameLength > returned - FIELD_OFFSET(FILTER_VOLUME_STANDARD_INFORMATION, FilterVolumeName)) {
            status = STATUS_INFO_LENGTH_MISMATCH;
        } else if ((information->Flags & ~FLTFL_VSI_DETACHED_VOLUME) != 0) {
            status = STATUS_NOT_SUPPORTED;
        } else {
            *Flags = information->Flags;
        }
    }
    ExFreePoolWithTag(information, SAFEUPLOAD_POOL_TAG);
    if (status != STATUS_SUCCESS && NT_SUCCESS(status)) status = STATUS_UNSUCCESSFUL;
    return status;
}

NTSTATUS SafeUploadStageAdmissionVolumeStatus(_Out_ PSAFEUPLOAD_ADMISSION_VOLUME_STATUS Status)
{
    PFLT_INSTANCE instances[SAFEUPLOAD_ADMISSION_VOLUME_MAX_ENTRIES];
    ULONG count = 0, index;
    NTSTATUS status;
    PAGED_CODE();
    RtlZeroMemory(Status, sizeof(*Status));
    Status->StructSize = sizeof(*Status);
    Status->WriterGlobalUnknown = SafeUploadStageWritersGlobalUnknown();
    Status->BootPolicyState = SafeUploadData.BootPolicyState;
    if (!ExAcquireRundownProtection(&SafeUploadData.ChannelRundown)) return STATUS_FLT_DELETING_OBJECT;
    status = FltEnumerateInstances(NULL, SafeUploadData.Filter, instances,
        RTL_NUMBER_OF(instances), &count);
    if (NT_SUCCESS(status)) {
        Status->EntryCount = count;
        for (index = 0; index < count; ++index) {
            PSAFEUPLOAD_INSTANCE_CONTEXT context = NULL;
            PFLT_VOLUME volume = NULL;
            PSAFEUPLOAD_ADMISSION_VOLUME_ENTRY entry = &Status->Entries[index];
            entry->Instance = (UINT64)(ULONG_PTR)instances[index];
            entry->ContextStatus = (UINT32)FltGetInstanceContext(instances[index], (PFLT_CONTEXT *)&context);
            entry->CanaryStatus = entry->CanaryCleanupStatus = (UINT32)STATUS_PENDING;
            entry->FileSystemStatus = entry->VolumeGuidStatus = entry->ContextStatus;
            entry->InstanceWritersUntracked = 1;
            entry->VolumeInfoStatus = (UINT32)FltGetVolumeFromInstance(instances[index], &volume);
            if (NT_SUCCESS((NTSTATUS)entry->VolumeInfoStatus)) {
                entry->VolumeInfoStatus = (UINT32)SafeUploadStageVolumeFlags(volume, &entry->VolumeFlags);
                FltObjectDereference(volume);
            }
            if (NT_SUCCESS((NTSTATUS)entry->ContextStatus)) {
                SafeUploadInstanceCheckCanaryDeadline(context);
                entry->VolumeKind = (UINT32)context->VolumeKind;
                entry->FileSystemType = (UINT32)context->FileSystemType;
                entry->FileSystemStatus = (UINT32)context->FileSystemStatus;
                entry->SetupFlags = ((UINT32)context->SetupFlags & SAFEUPLOAD_SETUP_FLAGS_MASK) |
                    ((UINT32)InterlockedCompareExchange(&context->TrustState, 0, 0) <<
                        SAFEUPLOAD_SETUP_TRUST_STATE_SHIFT);
                entry->VolumeGuidStatus = (UINT32)context->VolumeGuidStatus;
                entry->VolumeGuidChars = context->VolumeGuidChars;
                RtlCopyMemory(entry->VolumeGuid, context->VolumeGuid, sizeof(entry->VolumeGuid));
                entry->InstanceWritersUntracked = (UINT32)InterlockedCompareExchange(&context->WritersUntracked, 0, 0);
                entry->InstanceRegistryUnknownReasons = (UINT32)InterlockedCompareExchange(&context->RegistryUnknownReasons, 0, 0);
                {
                    LONG64 firstUnknown = InterlockedCompareExchange64(&context->RegistryFirstUnknown, 0, 0);
                    entry->FirstUnknownReason = (UINT32)(ULONGLONG)firstUnknown;
                    entry->FirstUnknownSite = (UINT32)((ULONGLONG)firstUnknown >> 32);
                }
                /* Final state is published last. Pending/Running reports no partial results. */
                entry->CanaryState = (UINT32)InterlockedCompareExchange(&context->CanaryState, 0, 0);
                if (entry->CanaryState >= SAFEUPLOAD_CANARY_PASSED) {
                    entry->CanaryStatus = (UINT32)context->CanaryStatus;
                    entry->CanaryChecks = context->CanaryChecks;
                    entry->CanaryCleanupStatus = (UINT32)context->CanaryCleanupStatus;
                }
                FltReleaseContext(context);
            }
            FltObjectDereference(instances[index]);
        }
    }
    /* Too many instances returns an error rather than partial success. */
    Status->WriterGlobalUnknown |= SafeUploadStageWritersGlobalUnknown();
    ExReleaseRundownProtection(&SafeUploadData.ChannelRundown);
    return status;
}

VOID SafeUploadStageAdmissionReady(VOID)
{
    InterlockedExchange(&AdmissionFilteringReady, 1);
}

static NTSTATUS StageCanarySecurity(_Out_ SECURITY_DESCRIPTOR *Descriptor, _Out_ PACL Acl,
    _In_ ULONG AclBytes)
{
    NTSTATUS status;
    status = RtlCreateSecurityDescriptor(Descriptor, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status)) return status;
    status = RtlCreateAcl(Acl, AclBytes, ACL_REVISION);
    if (!NT_SUCCESS(status)) return status;
    status = RtlAddAccessAllowedAce(Acl, ACL_REVISION, FILE_ALL_ACCESS, SeExports->SeLocalSystemSid);
    if (!NT_SUCCESS(status)) return status;
    status = RtlSetDaclSecurityDescriptor(Descriptor, TRUE, Acl, FALSE);
    if (!NT_SUCCESS(status)) return status;
    status = RtlSetOwnerSecurityDescriptor(Descriptor, SeExports->SeLocalSystemSid, FALSE);
    if (!NT_SUCCESS(status)) return status;
    status = RtlSetGroupSecurityDescriptor(Descriptor, SeExports->SeLocalSystemSid, FALSE);
    if (!NT_SUCCESS(status)) return status;
    /* This is our private absolute SECURITY_DESCRIPTOR, initialized above. Suppress inherited
     * directory ACEs so the new canary is writable only by the trusted SYSTEM principal. */
    Descriptor->Control |= SE_DACL_PROTECTED;
    return STATUS_SUCCESS;
}

/* Reason (reported as canary step 50 + Reason on failure): 1 query, 2 descriptor validation,
 * 3 revision/control, 4 owner, 5 group, 6 DACL presence/count, 7 ACE header, 8 ACE SID/mask. */
static NTSTATUS StageCanaryVerifySecurity(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT FileObject,
    _Out_ PULONG Reason)
{
    PUCHAR buffer;
    NTSTATUS status;
    PAGED_CODE();
    *Reason = 1;
    buffer = ExAllocatePool2(POOL_FLAG_PAGED, STAGE_CANARY_SD_BYTES, SAFEUPLOAD_CANARY_POOL_TAG);
    if (buffer == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    status = StageCanaryVerifyDescriptor(Instance, FileObject, buffer, Reason);
    ExFreePoolWithTag(buffer, SAFEUPLOAD_CANARY_POOL_TAG);
    return status;
}

static NTSTATUS StageCanaryVerifyDescriptor(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT FileObject,
    _Out_writes_bytes_(STAGE_CANARY_SD_BYTES) PUCHAR buffer, _Out_ PULONG Reason)
{
    PSECURITY_DESCRIPTOR descriptor = (PSECURITY_DESCRIPTOR)buffer;
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    ULONG revision = 0, needed = 0, sidBytes;
    PSID owner = NULL, group = NULL;
    PACL dacl = NULL;
    PVOID ace = NULL;
    BOOLEAN ownerDefaulted = FALSE, groupDefaulted = FALSE;
    BOOLEAN daclPresent = FALSE, daclDefaulted = FALSE;
    NTSTATUS status;

    PAGED_CODE();
    *Reason = 1;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    RtlZeroMemory(buffer, STAGE_CANARY_SD_BYTES);
    status = FltQuerySecurityObject(Instance, FileObject,
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        descriptor, STAGE_CANARY_SD_BYTES, &needed);
    /* LengthNeeded is only meaningful when the buffer is too small; on success validate every
     * component offset against the whole buffer instead. */
    if (status != STATUS_SUCCESS) return STATUS_INVALID_SECURITY_DESCR;
    *Reason = 2;
    if (!RtlValidRelativeSecurityDescriptor(descriptor, STAGE_CANARY_SD_BYTES,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)) {
        return STATUS_INVALID_SECURITY_DESCR;
    }

    *Reason = 3;
    /* RtlGetControlSecurityDescriptor is not declared for kernel mode; the header of the
     * validated self-relative descriptor carries the same revision and control fields. */
    revision = ((PISECURITY_DESCRIPTOR_RELATIVE)descriptor)->Revision;
    control = ((PISECURITY_DESCRIPTOR_RELATIVE)descriptor)->Control;
    if (revision != SECURITY_DESCRIPTOR_REVISION || !FlagOn(control, SE_SELF_RELATIVE) ||
        !FlagOn(control, SE_DACL_PRESENT) || !FlagOn(control, SE_DACL_PROTECTED)) {
        return STATUS_INVALID_SECURITY_DESCR;
    }
    *Reason = 4;
    status = RtlGetOwnerSecurityDescriptor(descriptor, &owner, &ownerDefaulted);
    if (!NT_SUCCESS(status) || owner == NULL || !RtlValidSid(owner) ||
        !RtlEqualSid(owner, SeExports->SeLocalSystemSid)) {
        return STATUS_INVALID_SECURITY_DESCR;
    }
    *Reason = 5;
    status = RtlGetGroupSecurityDescriptor(descriptor, &group, &groupDefaulted);
    if (!NT_SUCCESS(status) || group == NULL || !RtlValidSid(group) ||
        !RtlEqualSid(group, SeExports->SeLocalSystemSid)) {
        return STATUS_INVALID_SECURITY_DESCR;
    }
    *Reason = 6;
    status = RtlGetDaclSecurityDescriptor(descriptor, &daclPresent, &dacl, &daclDefaulted);
    /* RtlValidRelativeSecurityDescriptor above already validated this ACL against the buffer. */
    if (!NT_SUCCESS(status) || !daclPresent || dacl == NULL || dacl->AceCount != 1) {
        return STATUS_INVALID_SECURITY_DESCR;
    }
    *Reason = 7;
    status = RtlGetAce(dacl, 0, &ace);
    if (!NT_SUCCESS(status) || ace == NULL) return STATUS_INVALID_SECURITY_DESCR;
    if (((PACE_HEADER)ace)->AceType != ACCESS_ALLOWED_ACE_TYPE ||
        ((PACE_HEADER)ace)->AceFlags != 0 ||
        ((PACE_HEADER)ace)->AceSize < FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart)) {
        return STATUS_INVALID_SECURITY_DESCR;
    }
    {
        *Reason = 8;
        PACCESS_ALLOWED_ACE allowed = (PACCESS_ALLOWED_ACE)ace;
        PSID trustee = (PSID)&allowed->SidStart;

        if (!RtlValidSid(trustee)) return STATUS_INVALID_SECURITY_DESCR;
        sidBytes = RtlLengthSid(trustee);
        if ((ULONG)allowed->Header.AceSize != FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + sidBytes ||
            allowed->Mask != FILE_ALL_ACCESS ||
            !RtlEqualSid(trustee, SeExports->SeLocalSystemSid)) {
            /* The input ACE is already FILE_ALL_ACCESS, with no GENERIC_* bits to map. NTFS
             * should therefore store this file-specific mask unchanged; no alternate mask is
             * accepted without evidence that this filesystem rewrites the supplied ACE. */
            return STATUS_INVALID_SECURITY_DESCR;
        }
    }
    UNREFERENCED_PARAMETER(ownerDefaulted);
    UNREFERENCED_PARAMETER(groupDefaulted);
    UNREFERENCED_PARAMETER(daclDefaulted);
    UNREFERENCED_PARAMETER(needed);
    *Reason = 0;
    return STATUS_SUCCESS;
}

#if SAFEUPLOAD_STAGING_PROTOTYPE
static VOID StageCanaryRevokeTrust(_Inout_ PSAFEUPLOAD_INSTANCE_CONTEXT Context)
{
    LONG trust;
    if (!FlagOn(Context->SetupFlags, SAFEUPLOAD_SETUP_FLAG_NEWLY_MOUNTED_VOLUME)) return;
    trust = InterlockedCompareExchange(&Context->TrustState, 0, 0);
    while (trust == SAFEUPLOAD_VOLUME_TRUST_CANARY_PENDING ||
        trust == SAFEUPLOAD_VOLUME_TRUST_CANARY_PASSED) {
        LONG prior = InterlockedCompareExchange(&Context->TrustState,
            SAFEUPLOAD_VOLUME_TRUST_CANARY_LOST, trust);
        if (prior == trust) return;
        trust = prior;
    }
}

static VOID StageCanaryRecordTrustPass(_Inout_ PSAFEUPLOAD_INSTANCE_CONTEXT Context)
{
    if (FlagOn(Context->SetupFlags, SAFEUPLOAD_SETUP_FLAG_NEWLY_MOUNTED_VOLUME)) {
        (VOID)InterlockedCompareExchange(&Context->TrustState,
            SAFEUPLOAD_VOLUME_TRUST_CANARY_PASSED, SAFEUPLOAD_VOLUME_TRUST_CANARY_PENDING);
    }
}

static BOOLEAN StageCanaryHoldClaim(_In_ PFLT_INSTANCE Instance, _Out_ PULONG HoldMilliseconds)
{
    BOOLEAN claimed = FALSE;
    *HoldMilliseconds = 0;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    ExAcquireFastMutex(&CanaryHoldMutex);
    if (CanaryHoldState == SAFEUPLOAD_CANARY_HOLD_ARMED && CanaryHoldInstance == Instance) {
        CanaryHoldState = SAFEUPLOAD_CANARY_HOLD_PREPARING;
        *HoldMilliseconds = CanaryHoldMilliseconds;
        claimed = TRUE;
    }
    ExReleaseFastMutex(&CanaryHoldMutex);
    return claimed;
}

static VOID StageCanaryHoldReportFailure(_In_ PFLT_INSTANCE Instance, _In_ NTSTATUS Status)
{
    PFLT_INSTANCE dereference = NULL;
    ExAcquireFastMutex(&CanaryHoldMutex);
    if (CanaryHoldInstance == Instance &&
        (CanaryHoldState == SAFEUPLOAD_CANARY_HOLD_PREPARING ||
         CanaryHoldState == SAFEUPLOAD_CANARY_HOLD_ARMED)) {
        CanaryHoldStatus = Status;
        CanaryHoldPathChars = 0;
        CanaryHoldInstance = NULL;
        CanaryHoldState = CanaryHoldReplyConsumed ? SAFEUPLOAD_CANARY_HOLD_IDLE :
            SAFEUPLOAD_CANARY_HOLD_COMPLETE;
        if (CanaryHoldState == SAFEUPLOAD_CANARY_HOLD_IDLE) CanaryHoldReplyConsumed = FALSE;
        dereference = Instance;
        KeSetEvent(&CanaryHoldPathReady, IO_NO_INCREMENT, FALSE);
    }
    ExReleaseFastMutex(&CanaryHoldMutex);
    if (dereference != NULL) FltObjectDereference(dereference);
}

static VOID StageCanaryHoldFinish(_In_ PFLT_INSTANCE Instance)
{
    PFLT_INSTANCE dereference = NULL;
    ExAcquireFastMutex(&CanaryHoldMutex);
    if (CanaryHoldInstance == Instance &&
        (CanaryHoldState == SAFEUPLOAD_CANARY_HOLD_ACTIVE ||
         CanaryHoldState == SAFEUPLOAD_CANARY_HOLD_PREPARING)) {
        CanaryHoldInstance = NULL;
        CanaryHoldState = CanaryHoldReplyConsumed ? SAFEUPLOAD_CANARY_HOLD_IDLE :
            SAFEUPLOAD_CANARY_HOLD_COMPLETE;
        if (CanaryHoldState == SAFEUPLOAD_CANARY_HOLD_IDLE) CanaryHoldReplyConsumed = FALSE;
        CanaryHoldMilliseconds = 0;
        dereference = Instance;
    }
    ExReleaseFastMutex(&CanaryHoldMutex);
    if (dereference != NULL) FltObjectDereference(dereference);
}

static NTSTATUS StageCanarySetDeleteDisposition(_In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject, _In_ BOOLEAN DeleteFile)
{
    FILE_DISPOSITION_INFORMATION disposition;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    disposition.DeleteFile = DeleteFile;
    return FltSetInformationFile(Instance, FileObject, &disposition, sizeof(disposition),
        FileDispositionInformation);
}

static NTSTATUS StageCanaryHoldAfterSecurity(_In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject, _In_ PUNICODE_STRING Name, _In_ ULONG HoldMilliseconds)
{
    BOOLEAN fits = (Name->Length % sizeof(WCHAR)) == 0 && Name->Length < sizeof(CanaryHoldPath);
    PFLT_INSTANCE dereference = NULL;
    LARGE_INTEGER timeout;
    PVOID waitObjects[2] = { &CanaryHoldCancel, &CanaryStop };
    BOOLEAN published = FALSE;
    NTSTATUS status;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    ExAcquireFastMutex(&CanaryHoldMutex);
    if (CanaryHoldInstance == Instance && CanaryHoldState == SAFEUPLOAD_CANARY_HOLD_PREPARING) {
        if (fits && Name->Length != 0) {
            /* Copied under the mutex straight into the published buffer (no 1 KB stack copy). */
            RtlCopyMemory(CanaryHoldPath, Name->Buffer, Name->Length);
            CanaryHoldPath[Name->Length / sizeof(WCHAR)] = UNICODE_NULL;
            CanaryHoldPathChars = Name->Length / sizeof(WCHAR);
            CanaryHoldStatus = STATUS_SUCCESS;
            CanaryHoldState = SAFEUPLOAD_CANARY_HOLD_ACTIVE;
            KeSetEvent(&CanaryHoldPathReady, IO_NO_INCREMENT, FALSE);
            published = TRUE;
        } else {
            CanaryHoldStatus = STATUS_NAME_TOO_LONG;
            CanaryHoldPathChars = 0;
            CanaryHoldInstance = NULL;
            CanaryHoldState = CanaryHoldReplyConsumed ? SAFEUPLOAD_CANARY_HOLD_IDLE :
                SAFEUPLOAD_CANARY_HOLD_COMPLETE;
            if (CanaryHoldState == SAFEUPLOAD_CANARY_HOLD_IDLE) CanaryHoldReplyConsumed = FALSE;
            dereference = Instance;
            KeSetEvent(&CanaryHoldPathReady, IO_NO_INCREMENT, FALSE);
        }
    }
    ExReleaseFastMutex(&CanaryHoldMutex);

    if (published) {
        timeout.QuadPart = -((LONGLONG)HoldMilliseconds * 10000LL);
        (VOID)KeWaitForMultipleObjects(RTL_NUMBER_OF(waitObjects), waitObjects,
            WaitAny, Executive, KernelMode, FALSE, &timeout, NULL);
    }

    /* The test-only run omitted FILE_DELETE_ON_CLOSE so SYSTEM and non-SYSTEM callers can
     * exercise the live DACL by name. Restore delete-pending before any mapping step. */
    status = StageCanarySetDeleteDisposition(Instance, FileObject, TRUE);
    if (dereference != NULL) FltObjectDereference(dereference);
    StageCanaryHoldFinish(Instance);
    return status;
}

NTSTATUS SafeUploadStageAdmissionCanaryHold(_In_ PCUNICODE_STRING VolumeName,
    _In_ UINT32 HoldMilliseconds, _Out_ PSAFEUPLOAD_ADMISSION_CANARY_HOLD_REPLY Reply)
{
    PFLT_INSTANCE instances[SAFEUPLOAD_ADMISSION_VOLUME_MAX_ENTRIES];
    PSAFEUPLOAD_INSTANCE_CONTEXT chosenContext = NULL;
    PFLT_INSTANCE chosenInstance = NULL;
    ULONG count = 0, index;
    LARGE_INTEGER timeout;
    BOOLEAN enumerated = FALSE, targetReferenced = FALSE;
    NTSTATUS status;

    PAGED_CODE();
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (VolumeName == NULL || VolumeName->Buffer == NULL || VolumeName->Length == 0 ||
        (VolumeName->Length % sizeof(WCHAR)) != 0 ||
        VolumeName->Length > SAFEUPLOAD_CANARY_VOLUME_CHARS * sizeof(WCHAR) ||
        HoldMilliseconds == 0 || HoldMilliseconds > SAFEUPLOAD_CANARY_MAX_HOLD_MS) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeReadStateEvent(&CanaryStop) != 0) return STATUS_FLT_DELETING_OBJECT;

    status = FltEnumerateInstances(NULL, SafeUploadData.Filter, instances,
        RTL_NUMBER_OF(instances), &count);
    if (!NT_SUCCESS(status)) return status;
    enumerated = TRUE;
    for (index = 0; index < count; ++index) {
        PSAFEUPLOAD_INSTANCE_CONTEXT context = NULL;
        if (NT_SUCCESS(FltGetInstanceContext(instances[index], (PFLT_CONTEXT *)&context))) {
            UNICODE_STRING contextVolume;
            contextVolume.Buffer = context->VolumeGuid;
            contextVolume.Length = (USHORT)(context->VolumeGuidChars * sizeof(WCHAR));
            contextVolume.MaximumLength = sizeof(context->VolumeGuid);
            if (context->VolumeGuidStatus == STATUS_SUCCESS &&
                RtlEqualUnicodeString(&contextVolume, VolumeName, TRUE)) {
                if (context->VolumeKind != SafeUploadVolumeFixed ||
                    context->FileSystemType != FLT_FSTYPE_NTFS ||
                    InterlockedCompareExchange(&context->CanaryState, 0, 0) != SAFEUPLOAD_CANARY_PASSED ||
                    context->CanaryStatus != STATUS_SUCCESS ||
                    context->CanaryChecks != SAFEUPLOAD_CANARY_CHECKS_ALL ||
                    context->CanaryCleanupStatus != STATUS_SUCCESS) {
                    FltReleaseContext(context);
                    status = STATUS_INVALID_DEVICE_STATE;
                    goto Exit;
                }
                if (chosenContext != NULL) {
                    FltReleaseContext(context);
                    status = STATUS_OBJECT_NAME_COLLISION;
                    goto Exit;
                }
                chosenContext = context;
                chosenInstance = instances[index];
            } else {
                FltReleaseContext(context);
            }
        }
    }
    if (chosenInstance == NULL || chosenContext == NULL) {
        status = STATUS_OBJECT_NAME_NOT_FOUND;
        goto Exit;
    }

    status = FltObjectReference(chosenInstance);
    if (!NT_SUCCESS(status)) goto Exit;
    targetReferenced = TRUE;

    ExAcquireFastMutex(&CanaryHoldMutex);
    if (CanaryHoldState != SAFEUPLOAD_CANARY_HOLD_IDLE ||
        InterlockedCompareExchange(&chosenContext->CanaryState, 0, 0) != SAFEUPLOAD_CANARY_PASSED ||
        KeReadStateEvent(&CanaryStop) != 0) {
        status = CanaryHoldState != SAFEUPLOAD_CANARY_HOLD_IDLE ? STATUS_DEVICE_BUSY :
            STATUS_INVALID_DEVICE_STATE;
        ExReleaseFastMutex(&CanaryHoldMutex);
        goto Exit;
    }
    KeClearEvent(&CanaryHoldPathReady);
    KeClearEvent(&CanaryHoldCancel);
    CanaryHoldStatus = STATUS_PENDING;
    CanaryHoldPathChars = 0;
    CanaryHoldMilliseconds = HoldMilliseconds;
    CanaryHoldReplyConsumed = FALSE;
    CanaryHoldInstance = chosenInstance;
    targetReferenced = FALSE; /* The hold state now owns this reference. */
    CanaryHoldState = SAFEUPLOAD_CANARY_HOLD_ARMED;
    chosenContext->CanaryStatus = STATUS_PENDING;
    chosenContext->CanaryChecks = 0;
    chosenContext->CanaryCleanupStatus = STATUS_PENDING;
    /* The diagnostic hold re-arms the primitive; trust lost during this
     * reset is sticky even if the later canary run succeeds. */
    StageCanaryRevokeTrust(chosenContext);
    InterlockedExchange(&chosenContext->CanaryState, SAFEUPLOAD_CANARY_PENDING);
    ExReleaseFastMutex(&CanaryHoldMutex);

    /* The separately referenced target instance is owned by the hold state. Drop the
     * enumeration and context references before sleeping so unrelated volumes can detach. */
    FltReleaseContext(chosenContext);
    chosenContext = NULL;
    for (index = 0; index < count; ++index) FltObjectDereference(instances[index]);
    enumerated = FALSE;

    timeout.QuadPart = -((LONGLONG)SAFEUPLOAD_CANARY_MAX_HOLD_MS * 10000LL);
    status = KeWaitForSingleObject(&CanaryHoldPathReady, Executive, KernelMode, FALSE, &timeout);
    if (status == STATUS_SUCCESS) {
        ExAcquireFastMutex(&CanaryHoldMutex);
        status = CanaryHoldStatus;
        if (NT_SUCCESS(status) && CanaryHoldPathChars < RTL_NUMBER_OF(Reply->CanaryPath)) {
            Reply->StructSize = sizeof(*Reply);
            Reply->Status = (UINT32)status;
            Reply->PathChars = CanaryHoldPathChars;
            Reply->Reserved = 0;
            RtlCopyMemory(Reply->CanaryPath, CanaryHoldPath,
                (CanaryHoldPathChars + 1) * sizeof(WCHAR));
        } else if (NT_SUCCESS(status)) {
            status = STATUS_INVALID_BUFFER_SIZE;
        }
        if (CanaryHoldState == SAFEUPLOAD_CANARY_HOLD_COMPLETE) {
            CanaryHoldState = SAFEUPLOAD_CANARY_HOLD_IDLE;
            CanaryHoldReplyConsumed = FALSE;
        } else if (CanaryHoldState == SAFEUPLOAD_CANARY_HOLD_ACTIVE) {
            CanaryHoldReplyConsumed = TRUE;
        }
        ExReleaseFastMutex(&CanaryHoldMutex);
    } else {
        status = STATUS_IO_TIMEOUT;
        ExAcquireFastMutex(&CanaryHoldMutex);
        CanaryHoldReplyConsumed = TRUE;
        if (CanaryHoldState == SAFEUPLOAD_CANARY_HOLD_COMPLETE) {
            CanaryHoldState = SAFEUPLOAD_CANARY_HOLD_IDLE;
            CanaryHoldReplyConsumed = FALSE;
        }
        ExReleaseFastMutex(&CanaryHoldMutex);
        SafeUploadStageAdmissionCanaryHoldCancel();
    }

Exit:
    if (targetReferenced) FltObjectDereference(chosenInstance);
    if (chosenContext != NULL) FltReleaseContext(chosenContext);
    if (enumerated) {
        for (index = 0; index < count; ++index) FltObjectDereference(instances[index]);
    }
    return status;
}

VOID SafeUploadStageAdmissionCanaryHoldCancel(VOID)
{
    PFLT_INSTANCE dereference = NULL;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    ExAcquireFastMutex(&CanaryHoldMutex);
    if (CanaryHoldState == SAFEUPLOAD_CANARY_HOLD_ARMED) {
        dereference = CanaryHoldInstance;
        CanaryHoldInstance = NULL;
        CanaryHoldStatus = STATUS_CANCELLED;
        CanaryHoldPathChars = 0;
        CanaryHoldState = CanaryHoldReplyConsumed ? SAFEUPLOAD_CANARY_HOLD_IDLE :
            SAFEUPLOAD_CANARY_HOLD_COMPLETE;
        if (CanaryHoldState == SAFEUPLOAD_CANARY_HOLD_IDLE) CanaryHoldReplyConsumed = FALSE;
        KeSetEvent(&CanaryHoldPathReady, IO_NO_INCREMENT, FALSE);
    }
    if (CanaryHoldState == SAFEUPLOAD_CANARY_HOLD_PREPARING ||
        CanaryHoldState == SAFEUPLOAD_CANARY_HOLD_ACTIVE) {
        KeSetEvent(&CanaryHoldCancel, IO_NO_INCREMENT, FALSE);
    }
    ExReleaseFastMutex(&CanaryHoldMutex);
    if (dereference != NULL) FltObjectDereference(dereference);
}
#endif

static NTSTATUS StageCanaryCheckRemoved(_In_ PFLT_INSTANCE Instance, _In_ PUNICODE_STRING Name)
{
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io;
    HANDLE handle;
    PFILE_OBJECT object;
    LARGE_INTEGER delay;
    ULONG attempt;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    delay.QuadPart = -100 * 10000LL;
    InitializeObjectAttributes(&attributes, Name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    for (attempt = 0; attempt < 20; ++attempt) {
        RtlZeroMemory(&io, sizeof(io));
        handle = NULL; object = NULL;
        status = FltCreateFileEx2(SafeUploadData.Filter, Instance, &handle, &object,
            FILE_READ_ATTRIBUTES, &attributes, &io, NULL, 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_COMPLETE_IF_OPLOCKED,
            NULL, 0, 0, NULL);
        if (object != NULL) ObDereferenceObject(object);
        if (handle != NULL) FltClose(handle);
        if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND)
            return STATUS_SUCCESS;
        if (status != STATUS_DELETE_PENDING) return NT_SUCCESS(status) ? STATUS_OBJECT_NAME_COLLISION : status;
        (VOID)KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }
    return status;
}

static VOID StageCanaryRun(_In_ PFLT_INSTANCE Instance, _Inout_ PSAFEUPLOAD_INSTANCE_CONTEXT Context)
{
    PFLT_VOLUME volume = NULL;
    UNICODE_STRING volumeName, name;
    PWCHAR buffer = NULL;
    WCHAR suffix[80];
    GUID id;
    SECURITY_DESCRIPTOR descriptor;
    union { ACL Header; UCHAR Bytes[128]; } acl;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io = {0};
    FILE_END_OF_FILE_INFORMATION eof;
    FILE_ID_INFORMATION identity;
    HANDLE fileHandle = NULL, sectionHandle = NULL;
    PFILE_OBJECT fileObject = NULL;
    LARGE_INTEGER delay;
    UINT32 checks = 0, step = 1;
    ULONG securityReason = 0;
    ULONG returned = 0;
    ULONG attempt;
    NTSTATUS status, cleanupStatus = STATUS_SUCCESS;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    ULONG holdMilliseconds = 0;
    BOOLEAN holdClaimed = FALSE;
    BOOLEAN fileDeleteMarked = FALSE;
#endif

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
#if SAFEUPLOAD_STAGING_PROTOTYPE
    holdClaimed = StageCanaryHoldClaim(Instance, &holdMilliseconds);
#endif
    status = FltGetVolumeFromInstance(Instance, &volume);
    if (!NT_SUCCESS(status)) goto Exit;
    buffer = ExAllocatePool2(POOL_FLAG_PAGED, SAFEUPLOAD_MAX_PATH_CHARS * sizeof(WCHAR), SAFEUPLOAD_CANARY_POOL_TAG);
    if (buffer == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    volumeName.Buffer = buffer;
    volumeName.Length = 0;
    volumeName.MaximumLength = (USHORT)(SAFEUPLOAD_MAX_PATH_CHARS * sizeof(WCHAR));
    status = FltGetVolumeName(volume, &volumeName, NULL);
    if (!NT_SUCCESS(status)) goto Exit;
    step = 2;
    status = ExUuidCreate(&id);
    if (!NT_SUCCESS(status)) goto Exit;
    status = RtlStringCchPrintfW(suffix, RTL_NUMBER_OF(suffix),
        L"\\SafeUpload-canary-%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X.tmp",
        id.Data1, id.Data2, id.Data3, id.Data4[0], id.Data4[1], id.Data4[2], id.Data4[3],
        id.Data4[4], id.Data4[5], id.Data4[6], id.Data4[7]);
    if (!NT_SUCCESS(status)) goto Exit;
    name = volumeName;
    status = RtlAppendUnicodeToString(&name, suffix);
    if (!NT_SUCCESS(status)) goto Exit;
    step = 3;
    status = StageCanarySecurity(&descriptor, &acl.Header, sizeof(acl));
    if (!NT_SUCCESS(status)) goto Exit;
    InitializeObjectAttributes(&attributes, &name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, &descriptor);
    step = 4;
#if SAFEUPLOAD_STAGING_PROTOTYPE
    /* Only an explicitly armed test run omits delete-on-close so user-mode can reopen the
     * DACL-verified name. The hold path restores delete-pending before any mapping step. */
    status = FltCreateFileEx2(SafeUploadData.Filter, Instance, &fileHandle, &fileObject,
        FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE | SYNCHRONIZE,
        &attributes, &io, NULL, FILE_ATTRIBUTE_TEMPORARY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_CREATE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_COMPLETE_IF_OPLOCKED |
            (holdClaimed ? 0 : FILE_DELETE_ON_CLOSE),
        NULL, 0, 0, NULL);
#else
    status = FltCreateFileEx2(SafeUploadData.Filter, Instance, &fileHandle, &fileObject,
        FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE | SYNCHRONIZE,
        &attributes, &io, NULL, FILE_ATTRIBUTE_TEMPORARY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_CREATE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_COMPLETE_IF_OPLOCKED |
            FILE_DELETE_ON_CLOSE,
        NULL, 0, 0, NULL);
#endif
    if (status != STATUS_SUCCESS) goto Exit;
    if (fileObject == NULL || fileHandle == NULL) { status = STATUS_INVALID_HANDLE; goto Exit; }
#if SAFEUPLOAD_STAGING_PROTOTYPE
    fileDeleteMarked = !holdClaimed;
#endif
    /* This readback is deliberately the first post-create operation: no EOF, identity, or
     * section work can make a volume trusted before NTFS's applied owner/group/DACL is checked. */
    step = 5;
    status = StageCanaryVerifySecurity(Instance, fileObject, &securityReason);
    if (!NT_SUCCESS(status)) { step = 50 + securityReason; goto Exit; }
    checks |= SAFEUPLOAD_CANARY_DACL_VERIFIED;
    if (io.Information != FILE_CREATED) { status = STATUS_DATA_ERROR; goto Exit; }
#if SAFEUPLOAD_STAGING_PROTOTYPE
    if (holdClaimed) {
        step = 6;
        status = StageCanaryHoldAfterSecurity(Instance, fileObject, &name, holdMilliseconds);
        if (!NT_SUCCESS(status)) goto Exit;
        fileDeleteMarked = TRUE;
    }
#endif
    eof.EndOfFile.QuadPart = PAGE_SIZE;
    step = 7;
    status = FltSetInformationFile(Instance, fileObject, &eof, sizeof(eof), FileEndOfFileInformation);
    if (!NT_SUCCESS(status)) goto Exit;
    /* The canary owns this newly created lower object for its entire lifetime. Its delete-pending
     * name cannot be reopened; actual S(F) diagnostics use the verified attribute-only ID helper.
     * Here the referenced source object supplies the same NTFS per-stream section-pointer state. */
    step = 8;
    RtlZeroMemory(&identity, sizeof(identity));
    status = FltQueryInformationFile(Instance, fileObject, &identity, sizeof(identity),
        FileIdInformation, &returned);
    if (!NT_SUCCESS(status)) goto Exit;
    if (returned != sizeof(identity)) { status = STATUS_INFO_LENGTH_MISMATCH; goto Exit; }
    if (fileObject->SectionObjectPointer == NULL) { status = STATUS_INVALID_FILE_FOR_SECTION; goto Exit; }
    InitializeObjectAttributes(&attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    step = 9;
    status = ZwCreateSection(&sectionHandle, SECTION_QUERY | SECTION_MAP_READ | SECTION_MAP_WRITE,
        &attributes, NULL, PAGE_READWRITE, SEC_COMMIT, fileHandle);
    if (!NT_SUCCESS(status)) goto Exit;
    /* Retain the section handle without creating a view, the admission-critical case. */
    step = 10;
    if (!MmDoesFileHaveUserWritableReferences(fileObject->SectionObjectPointer)) {
        status = STATUS_NOT_SUPPORTED; goto Exit;
    }
    checks |= SAFEUPLOAD_CANARY_RETAINED_YES;
    ZwClose(sectionHandle); sectionHandle = NULL;
    delay.QuadPart = -100 * 10000LL;
    step = 11;
    for (attempt = 0; attempt < 20; ++attempt) {
        if (!MmDoesFileHaveUserWritableReferences(fileObject->SectionObjectPointer)) {
            checks |= SAFEUPLOAD_CANARY_RELEASED_NO;
            break;
        }
        (VOID)KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }
    status = (checks & SAFEUPLOAD_CANARY_RELEASED_NO) != 0 ? STATUS_SUCCESS : STATUS_IO_TIMEOUT;
Exit:
    if (sectionHandle != NULL) ZwClose(sectionHandle);
    if (fileObject != NULL) {
#if SAFEUPLOAD_STAGING_PROTOTYPE
        if (!fileDeleteMarked) {
            NTSTATUS deleteStatus = StageCanarySetDeleteDisposition(Instance, fileObject, TRUE);
            if (NT_SUCCESS(deleteStatus)) fileDeleteMarked = TRUE;
            else if (fileHandle != NULL) {
                FILE_DISPOSITION_INFORMATION disposition;
                IO_STATUS_BLOCK deleteIo = {0};
                NTSTATUS fallbackStatus;
                disposition.DeleteFile = TRUE;
                fallbackStatus = ZwSetInformationFile(fileHandle, &deleteIo, &disposition,
                    sizeof(disposition), FileDispositionInformation);
                deleteStatus = fallbackStatus;
                if (NT_SUCCESS(fallbackStatus)) fileDeleteMarked = TRUE;
                if (!NT_SUCCESS(deleteStatus)) cleanupStatus = deleteStatus;
            } else {
                cleanupStatus = deleteStatus;
            }
        }
#endif
        if (fileHandle != NULL) FltClose(fileHandle);
        ObDereferenceObject(fileObject);
#if SAFEUPLOAD_STAGING_PROTOTYPE
        if (holdClaimed) StageCanaryHoldReportFailure(Instance, status);
#endif
        {
            NTSTATUS removedStatus = StageCanaryCheckRemoved(Instance, &name);
            if (NT_SUCCESS(removedStatus)) {
                checks |= SAFEUPLOAD_CANARY_REMOVED;
                cleanupStatus = STATUS_SUCCESS;
            } else if (NT_SUCCESS(cleanupStatus)) {
                cleanupStatus = removedStatus;
            }
        }
    } else {
#if SAFEUPLOAD_STAGING_PROTOTYPE
        if (fileHandle != NULL && holdClaimed && !fileDeleteMarked) {
            FILE_DISPOSITION_INFORMATION disposition;
            IO_STATUS_BLOCK deleteIo = {0};
            disposition.DeleteFile = TRUE;
            cleanupStatus = ZwSetInformationFile(fileHandle, &deleteIo, &disposition,
                sizeof(disposition), FileDispositionInformation);
        }
#endif
        if (fileHandle != NULL) FltClose(fileHandle);
#if SAFEUPLOAD_STAGING_PROTOTYPE
        if (holdClaimed) StageCanaryHoldReportFailure(Instance, status);
#endif
    }
    if (buffer != NULL) ExFreePoolWithTag(buffer, SAFEUPLOAD_CANARY_POOL_TAG);
    if (volume != NULL) FltObjectDereference(volume);
    Context->CanaryStatus = status;
    Context->CanaryCleanupStatus = cleanupStatus;
    /* Failure phase in bits 8..15: volume/name/security/create/DACL/test-hold/EOF/ID/section/
     * retained/released. The low bits are individual checks; passed is exactly 15. */
    Context->CanaryChecks = checks | (status == STATUS_SUCCESS ? 0 : step << 8);
    /* Trust can advance only from a newly-mounted pending state. Any failure
     * permanently loses it for this instance; a later diagnostic rerun cannot
     * restore trust before reboot. */
    if (status == STATUS_SUCCESS && cleanupStatus == STATUS_SUCCESS &&
        checks == SAFEUPLOAD_CANARY_CHECKS_ALL) {
        /* A worker can return after the deadline without an Inspector read
         * arriving during the canary. Record that timeout before trust can
         * advance, so a slow pass cannot turn a timed-out instance trusted. */
        SafeUploadInstanceCheckCanaryDeadline(Context);
        StageCanaryRecordTrustPass(Context);
        /* Published last; consumers treat Pending/Running as Untrusted. */
        InterlockedExchange(&Context->CanaryState, SAFEUPLOAD_CANARY_PASSED);
    } else {
        StageCanaryRevokeTrust(Context);
        InterlockedExchange(&Context->CanaryState, SAFEUPLOAD_CANARY_FAILED);
    }
}

VOID SafeUploadStageCanaryTick(VOID)
{
    PFLT_INSTANCE instances[64];
    PSAFEUPLOAD_INSTANCE_CONTEXT context;
    FLT_FILESYSTEM_TYPE fs;
    ULONG count = 0, index;
    NTSTATUS status;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (InterlockedCompareExchange(&AdmissionFilteringReady, 0, 0) == 0) return;
    /* Called only by the separate, joined canary worker. InstanceSetup never waits or issues
     * canary I/O. Unload joins this worker before FltUnregisterFilter; all references drop here. */
    status = FltEnumerateInstances(NULL, SafeUploadData.Filter, instances,
        RTL_NUMBER_OF(instances), &count);
    if (!NT_SUCCESS(status)) return; /* Unvisited instances stay Pending, never trusted. */
    for (index = 0; index < count; ++index) {
        PFLT_VOLUME volume = NULL;
        UINT32 volumeFlags = 0;
        context = NULL;
        if (KeReadStateEvent(&CanaryStop) == 0 &&
            NT_SUCCESS(FltGetInstanceContext(instances[index], (PFLT_CONTEXT *)&context))) {
            if (InterlockedCompareExchange(&context->CanaryState,
                    SAFEUPLOAD_CANARY_RUNNING, SAFEUPLOAD_CANARY_PENDING) == SAFEUPLOAD_CANARY_PENDING) {
                InterlockedExchange64(&context->CanaryStartInterruptTime,
                    (LONG64)KeQueryInterruptTime());
                status = FltGetFileSystemType(instances[index], &fs);
                if (context->VolumeKind == SafeUploadVolumeFixed && NT_SUCCESS(status) && fs == FLT_FSTYPE_NTFS) {
                    status = FltGetVolumeFromInstance(instances[index], &volume);
                    if (NT_SUCCESS(status)) status = SafeUploadStageVolumeFlags(volume, &volumeFlags);
                    if (volume != NULL) FltObjectDereference(volume);
                    if (status == STATUS_SUCCESS && !FlagOn(volumeFlags, SAFEUPLOAD_VOLUME_DETACHED_FLAG)) {
                        StageCanaryRun(instances[index], context);
                    } else {
                        context->CanaryStatus = status == STATUS_SUCCESS ? STATUS_VOLUME_DISMOUNTED : status;
                        context->CanaryCleanupStatus = STATUS_SUCCESS;
                        StageCanaryRevokeTrust(context);
                        InterlockedExchange(&context->CanaryState, status == STATUS_SUCCESS ?
                            SAFEUPLOAD_CANARY_DETACHED : SAFEUPLOAD_CANARY_FAILED);
                    }
                } else {
                    context->CanaryStatus = NT_SUCCESS(status) ? STATUS_NOT_SUPPORTED : status;
                    context->CanaryCleanupStatus = STATUS_SUCCESS;
                    StageCanaryRevokeTrust(context);
                    InterlockedExchange(&context->CanaryState, SAFEUPLOAD_CANARY_UNSUPPORTED);
                }
            }
            FltReleaseContext(context);
        }
        FltObjectDereference(instances[index]);
    }
}

static KSTART_ROUTINE StageCanaryWorker;

static VOID StageCanaryWorker(_In_ PVOID Context)
{
    LARGE_INTEGER interval;
    UNREFERENCED_PARAMETER(Context);
    interval.QuadPart = -250 * 10000LL;
    while (KeWaitForSingleObject(&CanaryStop, Executive, KernelMode, FALSE, &interval) == STATUS_TIMEOUT)
        SafeUploadStageCanaryTick();
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS SafeUploadStageAdmissionStartWorker(VOID)
{
    OBJECT_ATTRIBUTES attributes;
    KeInitializeEvent(&CanaryStop, NotificationEvent, FALSE);
#if SAFEUPLOAD_STAGING_PROTOTYPE
    ExInitializeFastMutex(&CanaryHoldMutex);
    KeInitializeEvent(&CanaryHoldPathReady, NotificationEvent, FALSE);
    KeInitializeEvent(&CanaryHoldCancel, NotificationEvent, FALSE);
    CanaryHoldState = SAFEUPLOAD_CANARY_HOLD_IDLE;
    CanaryHoldReplyConsumed = FALSE;
    CanaryHoldInstance = NULL;
    CanaryHoldMilliseconds = 0;
    CanaryHoldStatus = STATUS_SUCCESS;
    CanaryHoldPathChars = 0;
    RtlZeroMemory(CanaryHoldPath, sizeof(CanaryHoldPath));
#endif
    InitializeObjectAttributes(&attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    return PsCreateSystemThread(&CanaryThreadHandle, SYNCHRONIZE, &attributes,
        NULL, NULL, StageCanaryWorker, &CanaryStop);
}

VOID SafeUploadStageAdmissionStopWorker(VOID)
{
    if (CanaryThreadHandle != NULL) {
        KeSetEvent(&CanaryStop, IO_NO_INCREMENT, FALSE);
#if SAFEUPLOAD_STAGING_PROTOTYPE
        SafeUploadStageAdmissionCanaryHoldCancel();
#endif
        (VOID)ZwWaitForSingleObject(CanaryThreadHandle, FALSE, NULL);
        ZwClose(CanaryThreadHandle);
        CanaryThreadHandle = NULL;
    }
#if SAFEUPLOAD_STAGING_PROTOTYPE
    SafeUploadStageAdmissionCanaryHoldCancel();
#endif
}
