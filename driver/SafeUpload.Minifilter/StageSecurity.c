#include "Filter.h"
#include "StageSecurity.h"

static NTSTATUS SafeUploadStageQuerySecurity(_In_ PFLT_INSTANCE Instance,
    _In_ PUNICODE_STRING Name, _In_ BOOLEAN Directory,
    _Outptr_result_nullonfailure_ PSECURITY_DESCRIPTOR *Descriptor);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SafeUploadStageQuerySecurity)
#pragma alloc_text(PAGE, SafeUploadStageCheckAccess)
#pragma alloc_text(PAGE, SafeUploadStageCaptureSecurity)
#pragma alloc_text(PAGE, SafeUploadStageFreeSecurity)
#pragma alloc_text(PAGE, SafeUploadStageCheckRenameAccess)
#pragma alloc_text(PAGE, SafeUploadStageCheckSubjectAccess)
#endif

// Read the destination's descriptor below our instance. This never creates,
// truncates, or writes to the protected destination.
static NTSTATUS
SafeUploadStageQuerySecurity (
    _In_ PFLT_INSTANCE Instance,
    _In_ PUNICODE_STRING Name,
    _In_ BOOLEAN Directory,
    _Outptr_result_nullonfailure_ PSECURITY_DESCRIPTOR *Descriptor
    )
{
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK ioStatus;
    HANDLE handle = NULL;
    PFILE_OBJECT fileObject = NULL;
    ULONG needed = 0;
    NTSTATUS status;

    PAGED_CODE();
    *Descriptor = NULL;
    InitializeObjectAttributes( &attributes, Name,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL );
    status = FltCreateFileEx2( SafeUploadData.Filter, Instance,
        &handle, &fileObject, READ_CONTROL, &attributes, &ioStatus,
        NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN, Directory ? FILE_DIRECTORY_FILE : FILE_NON_DIRECTORY_FILE,
        NULL, 0, IO_IGNORE_SHARE_ACCESS_CHECK | IO_STOP_ON_SYMLINK, NULL );
    if (!NT_SUCCESS( status )) {
        if (status == STATUS_STOPPED_ON_SYMLINK && ioStatus.Information != 0) {
            ExFreePool( (PVOID) ioStatus.Information );
        }
        return status;
    }

    status = FltQuerySecurityObject( Instance, fileObject,
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
            DACL_SECURITY_INFORMATION,
        NULL, 0, &needed );
    if (status == STATUS_BUFFER_TOO_SMALL && needed > 0 && needed <= 65536) {
        *Descriptor = ExAllocatePool2( POOL_FLAG_PAGED, needed,
                                       SAFEUPLOAD_POOL_TAG );
        if (*Descriptor == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
        } else {
            status = FltQuerySecurityObject( Instance, fileObject,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                    DACL_SECURITY_INFORMATION,
                *Descriptor, needed, NULL );
        }
    }
    ObDereferenceObject( fileObject );
    FltClose( handle );
    if (NT_SUCCESS( status ) && *Descriptor == NULL) {
        status = STATUS_INVALID_SECURITY_DESCR;
    }
    if (!NT_SUCCESS( status ) && *Descriptor != NULL) {
        ExFreePoolWithTag( *Descriptor, SAFEUPLOAD_POOL_TAG );
        *Descriptor = NULL;
    }
    return status;
}

NTSTATUS
SafeUploadStageCheckAccess (
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PACCESS_MASK GrantedAccess
    )
{
    PIO_SECURITY_CONTEXT security = Data->Iopb->Parameters.Create.SecurityContext;
    PACCESS_STATE access;
    PPRIVILEGE_SET privileges = NULL;
    BOOLEAN allowed;
    NTSTATUS status;

    PAGED_CODE();
    *GrantedAccess = 0;
    if (security == NULL || security->AccessState == NULL ||
        SecurityDescriptor == NULL ||
        FlagOn( DesiredAccess, WRITE_DAC | WRITE_OWNER | ACCESS_SYSTEM_SECURITY )) {
        // Security changes require namespace virtualization; never give a
        // staged handle authority to weaken the backing file's private ACL.
        return STATUS_ACCESS_DENIED;
    }
    access = security->AccessState;
    SeLockSubjectContext( &access->SubjectSecurityContext );
    allowed = SeAccessCheck( SecurityDescriptor,
        &access->SubjectSecurityContext, TRUE, DesiredAccess, 0,
        &privileges, IoGetFileObjectGenericMapping(), UserMode,
        GrantedAccess, &status );
    SeUnlockSubjectContext( &access->SubjectSecurityContext );
    if (privileges != NULL) {
        SeFreePrivileges( privileges );
    }
    if (!allowed) {
        return NT_SUCCESS( status ) ? STATUS_ACCESS_DENIED : status;
    }
    *GrantedAccess &= ~(WRITE_DAC | WRITE_OWNER | ACCESS_SYSTEM_SECURITY);
    return STATUS_SUCCESS;
}

NTSTATUS
SafeUploadStageCaptureSecurity (
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PFLT_INSTANCE Instance,
    _In_ PUNICODE_STRING Destination,
    _Outptr_ PSECURITY_DESCRIPTOR *SecurityDescriptor,
    _Out_ PBOOLEAN AssignedDescriptor,
    _Out_ PBOOLEAN DestinationExists,
    _Out_ PACCESS_MASK GrantedAccess
    )
{
    PIO_SECURITY_CONTEXT security = Data->Iopb->Parameters.Create.SecurityContext;
    UNICODE_STRING parent = *Destination;
    PSECURITY_DESCRIPTOR parentDescriptor = NULL;
    ACCESS_MASK parentGranted;
    ULONG disposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xff;
    USHORT i;
    NTSTATUS status;

    PAGED_CODE();
    *SecurityDescriptor = NULL;
    *AssignedDescriptor = FALSE;
    *DestinationExists = FALSE;
    *GrantedAccess = 0;
    if (security == NULL || security->AccessState == NULL ||
        !FlagOn( security->AccessState->Flags, TOKEN_HAS_TRAVERSE_PRIVILEGE )) {
        return STATUS_ACCESS_DENIED;
    }

    status = SafeUploadStageQuerySecurity( Instance, Destination, FALSE,
                                          SecurityDescriptor );
    if (NT_SUCCESS( status )) {
        *DestinationExists = TRUE;
        if (disposition == FILE_CREATE) {
            status = STATUS_OBJECT_NAME_COLLISION;
        } else {
            status = SafeUploadStageCheckAccess( Data, *SecurityDescriptor,
                security->DesiredAccess, GrantedAccess );
        }
    } else if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
        if (disposition == FILE_OPEN || disposition == FILE_OVERWRITE) {
            return status;
        }
        for (i = parent.Length / sizeof( WCHAR ); i > 0; --i) {
            if (parent.Buffer[i - 1] == L'\\') {
                parent.Length = (i - 1) * sizeof( WCHAR );
                parent.MaximumLength = parent.Length;
                break;
            }
        }
        if (i == 0) {
            return STATUS_OBJECT_PATH_INVALID;
        }
        status = SafeUploadStageQuerySecurity( Instance, &parent, TRUE,
                                              &parentDescriptor );
        if (NT_SUCCESS( status )) {
            status = SafeUploadStageCheckAccess( Data, parentDescriptor,
                                                 FILE_ADD_FILE, &parentGranted );
        }
        if (NT_SUCCESS( status )) {
            status = SeAssignSecurityEx( parentDescriptor,
                security->AccessState->SecurityDescriptor, SecurityDescriptor,
                NULL, FALSE, SEF_DACL_AUTO_INHERIT,
                &security->AccessState->SubjectSecurityContext,
                IoGetFileObjectGenericMapping(), PagedPool );
            if (NT_SUCCESS( status )) {
                *AssignedDescriptor = TRUE;
                status = SafeUploadStageCheckAccess( Data, *SecurityDescriptor,
                    security->DesiredAccess, GrantedAccess );
            }
        }
        if (parentDescriptor != NULL) {
            ExFreePoolWithTag( parentDescriptor, SAFEUPLOAD_POOL_TAG );
        }
    }
    if (!NT_SUCCESS( status )) {
        SafeUploadStageFreeSecurity( *SecurityDescriptor, *AssignedDescriptor );
        *SecurityDescriptor = NULL;
    }
    return status;
}

VOID
SafeUploadStageFreeSecurity (
    _In_opt_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ BOOLEAN AssignedDescriptor
    )
{
    PAGED_CODE();
    if (SecurityDescriptor != NULL) {
        if (AssignedDescriptor) {
            (VOID) SeDeassignSecurity( &SecurityDescriptor );
        } else {
            ExFreePoolWithTag( SecurityDescriptor, SAFEUPLOAD_POOL_TAG );
        }
    }
}

NTSTATUS
SafeUploadStageCheckRenameAccess (
    _In_ PFLT_INSTANCE Instance,
    _In_ PUNICODE_STRING Destination,
    _In_ BOOLEAN Replace
    )
{
    SECURITY_SUBJECT_CONTEXT subject;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    PPRIVILEGE_SET privileges = NULL;
    ACCESS_MASK granted;
    UNICODE_STRING parent = *Destination;
    NTSTATUS status;
    NTSTATUS accessStatus;
    USHORT i;

    PAGED_CODE();
    if (!SeSinglePrivilegeCheck( SeExports->SeChangeNotifyPrivilege, UserMode )) {
        return STATUS_ACCESS_DENIED;
    }
    SeCaptureSubjectContext( &subject );
    status = SafeUploadStageQuerySecurity( Instance, Destination, FALSE, &descriptor );
    if (NT_SUCCESS( status )) {
        if (!Replace) {
            status = STATUS_OBJECT_NAME_COLLISION;
            goto Exit;
        }
        if (!SeAccessCheck( descriptor, &subject, FALSE, DELETE, 0,
                &privileges, IoGetFileObjectGenericMapping(), UserMode,
                &granted, &accessStatus )) {
            status = STATUS_ACCESS_DENIED;
            goto Exit;
        }
        if (privileges != NULL) {
            SeFreePrivileges( privileges );
            privileges = NULL;
        }
        ExFreePoolWithTag( descriptor, SAFEUPLOAD_POOL_TAG );
        descriptor = NULL;
    } else if (status != STATUS_OBJECT_NAME_NOT_FOUND) {
        goto Exit;
    }
    for (i = parent.Length / sizeof( WCHAR ); i > 0; --i) {
        if (parent.Buffer[i - 1] == L'\\') {
            parent.Length = (i - 1) * sizeof( WCHAR );
            parent.MaximumLength = parent.Length;
            break;
        }
    }
    if (i == 0) {
        status = STATUS_OBJECT_PATH_INVALID;
        goto Exit;
    }
    status = SafeUploadStageQuerySecurity( Instance, &parent, TRUE, &descriptor );
    if (NT_SUCCESS( status ) &&
        !SeAccessCheck( descriptor, &subject, FALSE, FILE_ADD_FILE, 0,
            &privileges, IoGetFileObjectGenericMapping(), UserMode,
            &granted, &accessStatus )) {
        status = STATUS_ACCESS_DENIED;
    }
Exit:
    if (privileges != NULL) SeFreePrivileges( privileges );
    if (descriptor != NULL) ExFreePoolWithTag( descriptor, SAFEUPLOAD_POOL_TAG );
    SeReleaseSubjectContext( &subject );
    return status;
}

/* SET_INFORMATION has no CREATE security context. Capture its effective caller
 * instead of borrowing the service/kernel token used for the backing. */
NTSTATUS SafeUploadStageCheckSubjectAccess(PSECURITY_DESCRIPTOR Descriptor, ACCESS_MASK Desired)
{
    SECURITY_SUBJECT_CONTEXT subject;
    PPRIVILEGE_SET privileges = NULL;
    ACCESS_MASK granted;
    NTSTATUS status;
    BOOLEAN allowed;
    PAGED_CODE();
    SeCaptureSubjectContext(&subject);
    allowed = SeAccessCheck(Descriptor, &subject, FALSE, Desired, 0, &privileges,
        IoGetFileObjectGenericMapping(), UserMode, &granted, &status);
    if (privileges != NULL) SeFreePrivileges(privileges);
    SeReleaseSubjectContext(&subject);
    return allowed ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
}
