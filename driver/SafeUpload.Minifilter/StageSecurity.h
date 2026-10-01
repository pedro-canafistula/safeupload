#ifndef _SAFEUPLOAD_STAGE_SECURITY_H_
#define _SAFEUPLOAD_STAGE_SECURITY_H_

#include <fltKernel.h>

NTSTATUS
SafeUploadStageCheckAccess (
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PACCESS_MASK GrantedAccess
    );

NTSTATUS
SafeUploadStageCaptureSecurity (
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PFLT_INSTANCE Instance,
    _In_ PUNICODE_STRING Destination,
    _Outptr_ PSECURITY_DESCRIPTOR *SecurityDescriptor,
    _Out_ PBOOLEAN AssignedDescriptor,
    _Out_ PBOOLEAN DestinationExists,
    _Out_ PACCESS_MASK GrantedAccess
    );

VOID
SafeUploadStageFreeSecurity (
    _In_opt_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ BOOLEAN AssignedDescriptor
    );

NTSTATUS
SafeUploadStageCheckRenameAccess (
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PFLT_INSTANCE Instance,
    _In_ PUNICODE_STRING Destination,
    _In_ BOOLEAN Replace
    );

NTSTATUS SafeUploadStageCheckSubjectAccess(PFLT_CALLBACK_DATA Data,
    PSECURITY_DESCRIPTOR Descriptor, ACCESS_MASK Desired);

#endif
