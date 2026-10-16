#ifndef _SAFEUPLOAD_STAGE_SECURITY_H_
#define _SAFEUPLOAD_STAGE_SECURITY_H_

#include <fltKernel.h>

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStageQueryIdentity(PFLT_INSTANCE Instance, PUNICODE_STRING Name,
    BOOLEAN Directory, PFILE_ID_INFORMATION Identity);

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
SafeUploadStageCheckAccess (
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PACCESS_MASK GrantedAccess
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
SafeUploadStageCaptureSecurity (
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PFLT_INSTANCE Instance,
    _In_ PUNICODE_STRING Destination,
    _In_ BOOLEAN PrivateAbsent,
    _Outptr_ PSECURITY_DESCRIPTOR *SecurityDescriptor,
    _Out_ PBOOLEAN AssignedDescriptor,
    _Out_ PBOOLEAN DestinationExists,
    _Out_ PACCESS_MASK GrantedAccess
    );

_IRQL_requires_(PASSIVE_LEVEL)
VOID
SafeUploadStageFreeSecurity (
    _In_opt_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _In_ BOOLEAN AssignedDescriptor
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
SafeUploadStageCheckRenameAccess (
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PFLT_INSTANCE Instance,
    _In_ PUNICODE_STRING Destination,
    _In_ BOOLEAN Replace
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadStageCheckSubjectAccess(PFLT_CALLBACK_DATA Data,
    PSECURITY_DESCRIPTOR Descriptor, ACCESS_MASK Desired);

#endif
