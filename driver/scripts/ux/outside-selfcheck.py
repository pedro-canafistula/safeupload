#!/usr/bin/env python3
"""Execute production outside-scope gates with deterministic NTFS/DDI shims.

Scratch stays under .scratch. These controls do not qualify Windows, IRQL,
sharing, restricted tokens, callback draining or native races.
"""
from pathlib import Path
import importlib.util
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[3]
K = ROOT / 'driver/SafeUpload.Minifilter'
spec = importlib.util.spec_from_file_location('contracts', ROOT / 'driver/scripts/t5/teardown-participation-selfcheck.py')
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)


def definition(file, name):
    source = (K / file).read_text()
    body = t.body(file, name)
    start = t.strip_code(source).index(body)
    signature = source.rfind('\nstatic ', 0, start)
    if signature < 0:
        raise AssertionError(name)
    return source[signature:start + len(body)]


SHIM = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <wchar.h>
typedef int32_t NTSTATUS, LONG;
typedef uint32_t ULONG, UINT32, FLT_FILESYSTEM_TYPE;
typedef uint16_t USHORT;
typedef unsigned char BOOLEAN, *PBOOLEAN, *PUCHAR;
typedef wchar_t WCHAR, *PWCHAR, *PWCH;
typedef void VOID, *PVOID, *HANDLE, **PHANDLE, *PFLT_INSTANCE;
typedef int64_t LONGLONG;
typedef uint64_t ULONGLONG;
typedef struct { USHORT Length, MaximumLength; PWCHAR Buffer; } UNICODE_STRING, *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;
typedef struct { UNICODE_STRING Name, Volume, Stream; } FLT_FILE_NAME_INFORMATION, *PFLT_FILE_NAME_INFORMATION;
typedef struct { ULONG DesiredAccess; } SECURITY, *PIO_SECURITY_CONTEXT;
typedef struct { int MajorFunction; ULONG IrpFlags, OperationFlags; struct {
    struct { ULONG Options, FileAttributes, EaLength; PVOID EaBuffer; PIO_SECURITY_CONTEXT SecurityContext; } Create;
    struct { int FileInformationClass; } SetFileInformation;
    struct { int SyncType; ULONG PageProtection, AllocationAttributes; } AcquireForSectionSynchronization;
} Parameters; } IOPB;
typedef struct { IOPB *Iopb; struct { NTSTATUS Status; ULONG Information; } IoStatus; } DATA, *PFLT_CALLBACK_DATA;
typedef struct { UNICODE_STRING FileName; } FILE_OBJECT, *PFILE_OBJECT;
typedef struct { PFLT_INSTANCE Instance; PFILE_OBJECT FileObject; PVOID Transaction; } OBJECTS, *PCFLT_RELATED_OBJECTS;
typedef int SAFEUPLOAD_VOLUME_KIND, FLT_PREOP_CALLBACK_STATUS;
typedef struct { PUNICODE_STRING Name; ULONG Attributes; } OBJECT_ATTRIBUTES;
typedef struct { NTSTATUS Status; uintptr_t Information; } IO_STATUS_BLOCK;
typedef struct { ULONG NumberOfLinks; BOOLEAN Directory; } FILE_STANDARD_INFORMATION;
typedef struct { ULONG FileAttributes, ReparseTag; } FILE_ATTRIBUTE_TAG_INFORMATION;
typedef struct { uint64_t VolumeSerialNumber; unsigned char FileId[16]; } FILE_ID_INFORMATION;
typedef struct { BOOLEAN Valid, Absent; uint64_t ScopeSequence; FILE_ID_INFORMATION Identity; } SAFEUPLOAD_CREATE_ALIAS_PROOF, *PSAFEUPLOAD_CREATE_ALIAS_PROOF;
typedef struct { ULONG NextEntryOffset; LONGLONG ParentFileId; ULONG FileNameLength; WCHAR FileName[1]; } FILE_LINK_ENTRY_INFORMATION, *PFILE_LINK_ENTRY_INFORMATION;
typedef struct { ULONG BytesNeeded, EntriesReturned; FILE_LINK_ENTRY_INFORMATION Entry; } FILE_LINKS_INFORMATION, *PFILE_LINKS_INFORMATION;
#define TRUE 1
#define FALSE 0
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#define STATUS_SUCCESS 0
#define STATUS_ACCESS_DENIED ((NTSTATUS)-1)
#define STATUS_NAME_TOO_LONG ((NTSTATUS)-2)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)-3)
#define STATUS_DATA_ERROR ((NTSTATUS)-4)
#define STATUS_NOT_SAME_DEVICE ((NTSTATUS)-5)
#define STATUS_OBJECT_PATH_INVALID ((NTSTATUS)-6)
#define STATUS_TOO_MANY_LINKS ((NTSTATUS)-7)
#define STATUS_OBJECT_NAME_INVALID ((NTSTATUS)-8)
#define STATUS_STOPPED_ON_SYMLINK ((NTSTATUS)-9)
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)-10)
#define STATUS_OBJECT_PATH_NOT_FOUND ((NTSTATUS)-11)
#define STATUS_FILE_IS_A_DIRECTORY ((NTSTATUS)-12)
#define STATUS_NOT_SUPPORTED ((NTSTATUS)-13)
#define FLT_PREOP_SUCCESS_NO_CALLBACK 0
#define FLT_PREOP_COMPLETE 1
#define FLT_PREOP_DISALLOW_FASTIO 2
#define PASSIVE_LEVEL 0
#define APC_LEVEL 1
#define FLT_FSTYPE_NTFS 1
#define SafeUploadVolumeFixed 1
#define SAFEUPLOAD_MAX_PATH_CHARS 1024
#define SAFEUPLOAD_STAGING_PROTOTYPE 1
#define STAGE_DIRECTORY_COLLISION_LIMIT 16
#define FileStandardInformation 1
#define FileHardLinkInformation 2
#define FileIdInformation 3
#define FileAttributeTagInformation 4
#define FileBasicInformation 5
#define FileEndOfFileInformation 6
#define FileAllocationInformation 7
#define FileDispositionInformation 8
#define FileRenameInformation 9
#define FileLinkInformation 10
#define IRP_MJ_SET_INFORMATION 1
#define IRP_MJ_WRITE 2
#define IRP_MJ_SET_EA 3
#define FILE_OPEN 1u
#define FILE_CREATE 2u
#define FILE_OPEN_IF 3u
#define FILE_SUPERSEDE 0u
#define FILE_OVERWRITE 4u
#define FILE_OVERWRITE_IF 5u
#define FILE_DIRECTORY_FILE 1u
#define FILE_NON_DIRECTORY_FILE 2u
#define FILE_SYNCHRONOUS_IO_NONALERT 4u
#define FILE_COMPLETE_IF_OPLOCKED 8u
#define FILE_OPEN_REPARSE_POINT 16u
#define FILE_OPEN_BY_FILE_ID 32u
#define FILE_DELETE_ON_CLOSE 64u
#define FILE_SHARE_READ 1u
#define FILE_SHARE_WRITE 2u
#define FILE_SHARE_DELETE 4u
#define FILE_READ_ATTRIBUTES 1u
#define SYNCHRONIZE 2u
#define FILE_WRITE_DATA 4u
#define FILE_APPEND_DATA 8u
#define FILE_WRITE_EA 16u
#define FILE_WRITE_ATTRIBUTES 32u
#define FILE_DELETE_CHILD 64u
#define DELETE 128u
#define GENERIC_WRITE 256u
#define GENERIC_ALL 512u
#define MAXIMUM_ALLOWED 1024u
#define FILE_ATTRIBUTE_DIRECTORY 16u
#define FILE_ATTRIBUTE_REPARSE_POINT 1024u
#define FILE_ATTRIBUTE_ENCRYPTED 16384u
#define FILE_ATTRIBUTE_OFFLINE 4096u
#define OBJ_KERNEL_HANDLE 1u
#define OBJ_CASE_INSENSITIVE 2u
#define IO_IGNORE_SHARE_ACCESS_CHECK 1u
#define IO_STOP_ON_SYMLINK 2u
#define POOL_FLAG_PAGED 1u
#define IRP_PAGING_IO 1u
#define SL_CASE_SENSITIVE 1u
#define FLT_FILE_NAME_NORMALIZED 1u
#define FLT_FILE_NAME_QUERY_DEFAULT 2u
#define FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY 4u
#define FIELD_OFFSET(t, f) offsetof(t, f)
#define RTL_NUMBER_OF(a) (sizeof(a)/sizeof((a)[0]))
#define RTL_CONSTANT_STRING(s) {sizeof(s)-sizeof(WCHAR), sizeof(s), (PWCHAR)(s)}
#define FlagOn(v, m) ((v) & (m))
#define RtlCopyMemory memcpy
#define RtlZeroMemory(p,n) memset(p,0,n)
#define _In_
#define _Inout_
#define _Inout_opt_
#define _Out_
#define _Outptr_result_nullonfailure_
#define _IRQL_requires_(x)
#define __declspec(x) __attribute__((noinline))
#define _ReturnAddress() __builtin_return_address(0)
#define PAGED_CODE() assert(irql <= APC_LEVEL)
#define FLT_IS_FASTIO_OPERATION(d) (fastio)
#define InitializeObjectAttributes(a,n,f,r,s) do { (a)->Name=(n); (a)->Attributes=(f); } while(0)
#define DEFINE_REASON(n,v) enum { SAFEUPLOAD_DENY_REASON_##n=v }
DEFINE_REASON(NONE,0); DEFINE_REASON(NAME_UNRESOLVED,1); DEFINE_REASON(ACTIVATING_NAME,2);
DEFINE_REASON(POLICY_SCOPE,3); DEFINE_REASON(PROTECTED_NAMESPACE,4); DEFINE_REASON(PROTECTED_ALIAS,5);
DEFINE_REASON(ALIAS_CHECK_FAILED,6); DEFINE_REASON(TOP_LEVEL_IRP,7); DEFINE_REASON(REGISTRY_SCOPE,14);
#define SAFEUPLOAD_SOP_OUTSIDE_KNOWN 0
#define SyncTypeCreateSection 1
#define PAGE_READWRITE 4u
#define PAGE_EXECUTE_READWRITE 64u
#define SEC_IMAGE 0x1000000u
static struct { PVOID Filter; ULONG InspectorProcessId; } SafeUploadData;
static volatile LONG StageDirectoryCollisionHolds;
static FILE_OBJECT original, parent_object;
static FLT_FILE_NAME_INFORMATION resolved, parent_name;
static int irql, fastio, top, scoped, activating, alias_calls, opens, closes, queries, hints, reason;
static int name_status, standard_status, links_status, open_status, parent_status, parse_status, tag_status;
static int anchor=1, nonntfs, nameless, protected_alias, links_count=2, bad_links, volume_scoped=1;
static int sop, outside_why=4, wait_resolves, waits, scope_after_wait, mutate_sequence;
static uint64_t sequence;
static ULONG attributes=FILE_ATTRIBUTE_DIRECTORY, short_tag;
static PFILE_OBJECT last_queried;
static PVOID last_hint;
static PVOID IoGetTopLevelIrp(void) { return top ? &top : NULL; }
static int KeGetCurrentIrql(void) { return irql; }
static BOOLEAN SafeUploadIsAuthenticatedClient(void) { return FALSE; }
static ULONG FltGetRequestorProcessId(PFLT_CALLBACK_DATA d) { (void)d; return 1; }
static SAFEUPLOAD_VOLUME_KIND StageVolumeKind(PFLT_INSTANCE i) { (void)i; return SafeUploadVolumeFixed; }
static NTSTATUS FltGetFileSystemType(PFLT_INSTANCE i, FLT_FILESYSTEM_TYPE *f) { (void)i; *f=nonntfs?2:FLT_FSTYPE_NTFS; return 0; }
static BOOLEAN SafeUploadPolicyMayMatchInstanceVolume(PFLT_INSTANCE i) { (void)i; return volume_scoped; }
static BOOLEAN SafeUploadPolicyMatchesCurrentOrPendingDestination(SAFEUPLOAD_VOLUME_KIND k, PCUNICODE_STRING n, BOOLEAN a) { (void)k;(void)n;(void)a;return scoped; }
static BOOLEAN SafeUploadStageProtectedName(PFLT_FILE_NAME_INFORMATION n, SAFEUPLOAD_VOLUME_KIND k) { (void)n;(void)k; return scoped; }
static BOOLEAN SafeUploadStageTouchesProtectedNamespace(PFLT_FILE_NAME_INFORMATION n, SAFEUPLOAD_VOLUME_KIND k) { (void)n;(void)k;return scoped; }
static BOOLEAN SafeUploadPolicyDirectoryIsScopeAnchor(PCUNICODE_STRING n) { (void)n;return anchor; }
static BOOLEAN SafeUploadStageProtectedPath(PUNICODE_STRING n, USHORT v, SAFEUPLOAD_VOLUME_KIND k) { (void)n;(void)v;(void)k;return protected_alias; }
static NTSTATUS FltGetFileNameInformation(PFLT_CALLBACK_DATA d, ULONG flags, PFLT_FILE_NAME_INFORMATION *n) { (void)d;(void)flags;*n=nameless?NULL:&resolved;return name_status; }
static NTSTATUS FltGetFileNameInformationUnsafe(PFILE_OBJECT o, PFLT_INSTANCE i, ULONG f, PFLT_FILE_NAME_INFORMATION *n) { (void)o;(void)i;(void)f;*n=&parent_name;return parent_status; }
static NTSTATUS FltParseFileNameInformation(PFLT_FILE_NAME_INFORMATION n) { (void)n;return parse_status; }
static void FltReleaseFileNameInformation(PFLT_FILE_NAME_INFORMATION n) { (void)n; }
static void ObDereferenceObject(PFILE_OBJECT o) { (void)o; }
static void FltClose(HANDLE h) { assert(h);++closes; }
static LONG InterlockedIncrement(volatile LONG *n) { return ++*n; }
static LONG InterlockedDecrement(volatile LONG *n) { return --*n; }
static void SafeUploadDenyDetail(PFLT_CALLBACK_DATA d, UINT32 r, NTSTATUS s, PCUNICODE_STRING n) { (void)d;(void)s;(void)n;reason=(int)r; }
static void SafeUploadDenySiteHint(PFLT_CALLBACK_DATA d, PVOID site) { (void)d; ++hints;last_hint=site; }
static BOOLEAN SafeUploadNameLookupProvesAbsent(NTSTATUS s) { return s==STATUS_OBJECT_PATH_NOT_FOUND || s==STATUS_OBJECT_NAME_NOT_FOUND; }
static ULONG SafeUploadStageWritersSopOutsideWhy(PFLT_INSTANCE i, PFILE_OBJECT o) { (void)i;(void)o;return outside_why; }
static ULONG SafeUploadStageWritersAdmitNestedMutation(PFLT_INSTANCE i, PFILE_OBJECT o, PVOID *c) { (void)i;(void)o;*c=NULL;return outside_why; }
static BOOLEAN SafeUploadStageWritersNameActivating(PFLT_INSTANCE i, PCUNICODE_STRING n) { (void)i;(void)n;return activating; }
static BOOLEAN SafeUploadStageWritersSopKnownOutside(PFLT_INSTANCE i, PFILE_OBJECT o) { (void)i;(void)o;return outside_why==0; }
static BOOLEAN SafeUploadStageWritersSopMatchesPolicy(PFLT_INSTANCE i, PFILE_OBJECT o, BOOLEAN a) { (void)i;(void)o;(void)a; if(mutate_sequence)++sequence;return sop; }
static void SafeUploadStageWritersAwaitClassification(PFLT_INSTANCE i, PFILE_OBJECT o) { (void)i;(void)o;++waits;if(wait_resolves)sop=0;if(scope_after_wait)scoped=1; }
static uint64_t SafeUploadPolicyScopeSequenceSnapshot(void) { return sequence; }
#define SafeUploadTrace(s) ((void)0)
static void *ExAllocatePool2(ULONG flags, size_t n, ULONG tag) { (void)flags;(void)tag;return calloc(1,n); }
static void ExFreePoolWithTag(void *p, ULONG tag) { (void)tag;free(p); }
static void ExFreePool(void *p) { free(p); }
static BOOLEAN RtlEqualUnicodeString(PCUNICODE_STRING a, PCUNICODE_STRING b, BOOLEAN insensitive) {
    (void)insensitive;return a->Length==b->Length && !memcmp(a->Buffer,b->Buffer,a->Length);
}
static NTSTATUS FltCreateFileEx2(PVOID f, PFLT_INSTANCE i, PHANDLE h, PFILE_OBJECT *o,
    ULONG access, OBJECT_ATTRIBUTES *a, IO_STATUS_BLOCK *io, PVOID size, ULONG attr,
    ULONG share, ULONG disposition, ULONG options, PVOID ea, ULONG ealen, ULONG flags, PVOID ctx) {
    (void)f;(void)i;(void)access;(void)a;(void)io;(void)size;(void)attr;(void)ea;(void)ealen;(void)ctx;
    ++opens; assert(disposition==FILE_OPEN);
    if (!(options & FILE_OPEN_BY_FILE_ID) && (options & FILE_DIRECTORY_FILE)) {
        assert(!(share & FILE_SHARE_DELETE)); assert(flags==0); assert(options & FILE_OPEN_REPARSE_POINT);
        assert(!(access & (FILE_WRITE_DATA|DELETE))); assert(StageDirectoryCollisionHolds>0);
    }
    *h=open_status?NULL:&parent_object;if(o)*o=open_status?NULL:&parent_object;return open_status;
}
static NTSTATUS FltQueryInformationFile(PFLT_INSTANCE i, PFILE_OBJECT o, PVOID info, ULONG bytes, int cls, ULONG *returned) {
    (void)i;(void)bytes;++queries;last_queried=o;
    if(cls==FileStandardInformation) { FILE_STANDARD_INFORMATION *s=info;s->NumberOfLinks=(ULONG)links_count;s->Directory=FALSE;return standard_status; }
    if(cls==FileAttributeTagInformation) { FILE_ATTRIBUTE_TAG_INFORMATION *t=info;t->FileAttributes=attributes;t->ReparseTag=0;*returned=short_tag?0:sizeof(*t);return tag_status; }
    if(cls==FileHardLinkInformation) {
        PFILE_LINKS_INFORMATION l=info;size_t stride=32, base=FIELD_OFFSET(FILE_LINKS_INFORMATION,Entry);
        ++alias_calls;l->EntriesReturned=bad_links?0:(ULONG)links_count;l->BytesNeeded=(ULONG)(base+stride*(size_t)links_count);
        for(int x=0;x<links_count && x<64;++x) { PFILE_LINK_ENTRY_INFORMATION e=(void*)((char*)l+base+stride*(size_t)x);
            e->FileNameLength=1;e->ParentFileId=42;e->FileName[0]=L'x';e->NextEntryOffset=x+1==links_count?0:(ULONG)stride; }
        if(returned)*returned=l->BytesNeeded;
        return links_status;
    }
    if(cls==FileIdInformation) { memset(info,0,sizeof(FILE_ID_INFORMATION));if(returned)*returned=sizeof(FILE_ID_INFORMATION);return 0; }
    assert(0);return STATUS_DATA_ERROR;
}
'''

CASES = r'''
static void reset(void) {
    irql=fastio=top=scoped=activating=alias_calls=opens=closes=queries=hints=reason=0;
    name_status=standard_status=links_status=open_status=parent_status=parse_status=tag_status=0;
    nonntfs=nameless=protected_alias=bad_links=short_tag=0;links_count=2;volume_scoped=1;
    sop=wait_resolves=waits=scope_after_wait=mutate_sequence=0;outside_why=4;sequence=0;
    attributes=FILE_ATTRIBUTE_DIRECTORY;StageDirectoryCollisionHolds=0;anchor=1;
    resolved.Name=(UNICODE_STRING)RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume3\\outside");
    resolved.Volume=(UNICODE_STRING)RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume3");
    resolved.Stream.Length=0;
    parent_name.Name=(UNICODE_STRING)RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume3\\Windows");
    parent_name.Volume=resolved.Volume;
}
int main(void) {
    IOPB io={0}; DATA data={.Iopb=&io}; OBJECTS objects={.Instance=&original,.FileObject=&original};
    SECURITY security={0}; HANDLE hold=NULL; PVOID mutation=NULL; BOOLEAN protected=TRUE;
    reset(); assert(sizeof(WCHAR)==2);
    /* Existing exact object, both link parents: no source-ID/path reopen. */
    assert(SafeUploadStageCheckObjectAliases(&data,objects.Instance,&original,&resolved.Volume,1,&protected)==0);
    assert(!protected && opens==2 && closes==2 && alias_calls==1);
    reset(); links_count=1;
    assert(SafeUploadStageCheckObjectAliases(&data,objects.Instance,&original,&resolved.Volume,1,&protected)==0);
    assert(last_queried==&original && opens==0);
    reset(); protected_alias=1;
    assert(SafeUploadStageCheckObjectAliases(&data,objects.Instance,&original,&resolved.Volume,1,&protected)==0 && protected);
    reset(); open_status=STATUS_ACCESS_DENIED;
    assert(SafeUploadStageCheckObjectAliases(&data,objects.Instance,&original,&resolved.Volume,1,&protected)==STATUS_ACCESS_DENIED && hints==1);
    PVOID open_hint=last_hint;
    reset(); parent_status=STATUS_ACCESS_DENIED;
    assert(SafeUploadStageCheckObjectAliases(&data,objects.Instance,&original,&resolved.Volume,1,&protected)==STATUS_ACCESS_DENIED && hints==1 && closes==1);
    assert(open_hint!=last_hint);
    reset(); links_status=STATUS_ACCESS_DENIED;
    assert(SafeUploadStageCheckObjectAliases(&data,objects.Instance,&original,&resolved.Volume,1,&protected)==STATUS_ACCESS_DENIED && hints==1);
    reset(); links_count=65;
    assert(SafeUploadStageCheckObjectAliases(&data,objects.Instance,&original,&resolved.Volume,1,&protected)==STATUS_TOO_MANY_LINKS && opens==0);
    reset(); bad_links=1;
    assert(SafeUploadStageCheckObjectAliases(&data,objects.Instance,&original,&resolved.Volume,1,&protected)==STATUS_DATA_ERROR);
    reset(); top=1;
    assert(SafeUploadStageCheckObjectAliases(&data,objects.Instance,&original,&resolved.Volume,1,&protected)==STATUS_ACCESS_DENIED && queries==0);
    /* Metadata outside passes even with denied alias queries; content stays closed. */
    reset(); io.MajorFunction=IRP_MJ_SET_INFORMATION;io.Parameters.SetFileInformation.FileInformationClass=FileBasicInformation;open_status=STATUS_ACCESS_DENIED;
    assert(StagePhysicalMutationEx(&data,&objects,FALSE,FALSE,&mutation)==0 && opens==0 && queries==0);
    scoped=1;assert(StagePhysicalMutationEx(&data,&objects,FALSE,FALSE,&mutation)==FLT_PREOP_COMPLETE);
    int classes[]={FileEndOfFileInformation,FileAllocationInformation,FileDispositionInformation};
    for(size_t x=0;x<RTL_NUMBER_OF(classes);++x) { reset();open_status=STATUS_ACCESS_DENIED;io.Parameters.SetFileInformation.FileInformationClass=classes[x];
        assert(StagePhysicalMutationEx(&data,&objects,FALSE,FALSE,&mutation)==FLT_PREOP_COMPLETE && reason==SAFEUPLOAD_DENY_REASON_ALIAS_CHECK_FAILED); }
    reset();io.MajorFunction=IRP_MJ_WRITE;links_status=STATUS_ACCESS_DENIED;
    assert(StagePhysicalMutationEx(&data,&objects,FALSE,FALSE,&mutation)==FLT_PREOP_COMPLETE);
    reset();io.MajorFunction=IRP_MJ_SET_EA;links_status=STATUS_ACCESS_DENIED;
    assert(StagePhysicalMutationEx(&data,&objects,FALSE,FALSE,&mutation)==FLT_PREOP_COMPLETE);
    reset();io.MajorFunction=IRP_MJ_SET_INFORMATION;io.Parameters.SetFileInformation.FileInformationClass=FileBasicInformation;name_status=STATUS_ACCESS_DENIED;
    assert(StagePhysicalMutationEx(&data,&objects,FALSE,FALSE,&mutation)==FLT_PREOP_COMPLETE);
    /* Existing scope/ancestor directory, retained pin through native result. */
    reset();scoped=1;io.Parameters.Create.Options=(FILE_CREATE<<24)|FILE_DIRECTORY_FILE;io.Parameters.Create.SecurityContext=&security;
    assert(StageAdmitDirectoryMutation(&data,&objects,TRUE,&hold)==0 && hold && StageDirectoryCollisionHolds==1 && closes==0);
    StageDirectoryCollisionComplete(hold);assert(closes==1 && StageDirectoryCollisionHolds==0);
    reset();scoped=1;open_status=STATUS_OBJECT_NAME_NOT_FOUND;
    assert(StageAdmitDirectoryMutation(&data,&objects,TRUE,&hold)==FLT_PREOP_COMPLETE && !hold && StageDirectoryCollisionHolds==0);
    reset();scoped=1;attributes|=FILE_ATTRIBUTE_REPARSE_POINT;
    assert(StageAdmitDirectoryMutation(&data,&objects,TRUE,&hold)==FLT_PREOP_COMPLETE && !hold && closes==1 && StageDirectoryCollisionHolds==0);
    reset();scoped=1;short_tag=1;
    assert(StageAdmitDirectoryMutation(&data,&objects,TRUE,&hold)==FLT_PREOP_COMPLETE && !hold && closes==1 && StageDirectoryCollisionHolds==0);
    reset();scoped=1;nonntfs=1;
    assert(StageAdmitDirectoryMutation(&data,&objects,TRUE,&hold)==FLT_PREOP_COMPLETE && !hold && opens==0 && StageDirectoryCollisionHolds==0);
    reset();scoped=1;objects.Transaction=&original;
    assert(StageAdmitDirectoryMutation(&data,&objects,TRUE,&hold)==FLT_PREOP_COMPLETE && !hold && opens==0);objects.Transaction=NULL;
    reset();scoped=1;StageDirectoryCollisionHolds=STAGE_DIRECTORY_COLLISION_LIMIT;
    for(int x=0;x<100;++x) assert(StageAdmitDirectoryMutation(&data,&objects,TRUE,&hold)==FLT_PREOP_COMPLETE && !hold && opens==0 && StageDirectoryCollisionHolds==STAGE_DIRECTORY_COLLISION_LIMIT);
    reset();scoped=1;io.OperationFlags=SL_CASE_SENSITIVE;
    assert(StageAdmitDirectoryMutation(&data,&objects,TRUE,&hold)==FLT_PREOP_COMPLETE && !hold && opens==0);io.OperationFlags=0;
    reset();scoped=1;io.Parameters.Create.Options|=FILE_OPEN_BY_FILE_ID;
    assert(StageAdmitDirectoryMutation(&data,&objects,TRUE,&hold)==FLT_PREOP_COMPLETE && !hold && opens==0);
    io.Parameters.Create.Options=(FILE_CREATE<<24)|FILE_DIRECTORY_FILE;
    reset();scoped=1;io.Parameters.Create.Options|=FILE_DELETE_ON_CLOSE;
    assert(StageAdmitDirectoryMutation(&data,&objects,TRUE,&hold)==FLT_PREOP_COMPLETE && !hold && opens==0);
    reset();scoped=1;io.Parameters.Create.Options=(FILE_OPEN_IF<<24)|FILE_DIRECTORY_FILE;
    assert(StageAdmitDirectoryMutation(&data,&objects,TRUE,&hold)==0 && !hold && opens==0);
    io.Parameters.Create.Options=(FILE_CREATE<<24)|FILE_DIRECTORY_FILE;
    reset();scoped=1;
    assert(StageAdmitDirectoryMutation(&data,&objects,FALSE,&hold)==FLT_PREOP_COMPLETE && !hold && opens==0);
    /* A new empty child directory uses the dirs native path, without a pin. */
    reset();scoped=1;anchor=0;open_status=STATUS_OBJECT_NAME_NOT_FOUND;
    assert(StageAdmitDirectoryMutation(&data,&objects,TRUE,&hold)==0 && !hold && opens==0);
    /* Unsupported directory payloads/selectors cannot borrow the collision pin. */
    reset();scoped=1;io.Parameters.Create.EaLength=1;
    assert(StageAdmitDirectoryMutation(&data,&objects,TRUE,&hold)==FLT_PREOP_COMPLETE && !hold && opens==0);io.Parameters.Create.EaLength=0;
    io.Parameters.Create.EaBuffer=&original;
    assert(StageAdmitDirectoryMutation(&data,&objects,TRUE,&hold)==FLT_PREOP_COMPLETE && !hold && opens==0);io.Parameters.Create.EaBuffer=NULL;
    io.Parameters.Create.FileAttributes=FILE_ATTRIBUTE_ENCRYPTED;
    assert(StageAdmitDirectoryMutation(&data,&objects,TRUE,&hold)==FLT_PREOP_COMPLETE && !hold && opens==0);io.Parameters.Create.FileAttributes=0;
    resolved.Stream.Length=2;
    assert(StageAdmitDirectoryMutation(&data,&objects,TRUE,&hold)==FLT_PREOP_COMPLETE && !hold && opens==0);resolved.Stream.Length=0;
    /* Outside names and registry positives are different diagnostic decisions. */
    reset();io.Parameters.AcquireForSectionSynchronization.SyncType=SyncTypeCreateSection;io.Parameters.AcquireForSectionSynchronization.PageProtection=PAGE_READWRITE;scoped=1;
    assert(StageUnownedWritableSection(&data,&objects)==FLT_PREOP_COMPLETE && reason==SAFEUPLOAD_DENY_REASON_POLICY_SCOPE);
    reset();sop=1;
    assert(StageUnownedWritableSection(&data,&objects)==FLT_PREOP_COMPLETE && reason==SAFEUPLOAD_DENY_REASON_REGISTRY_SCOPE && waits==1);
    reset();sop=1;wait_resolves=1;
    assert(StageUnownedWritableSection(&data,&objects)==0 && waits==1);
    reset();sop=1;scope_after_wait=1;
    assert(StageUnownedWritableSection(&data,&objects)==FLT_PREOP_COMPLETE && reason==SAFEUPLOAD_DENY_REASON_POLICY_SCOPE);
    reset();sop=1;wait_resolves=mutate_sequence=1;
    assert(StageUnownedWritableSection(&data,&objects)==FLT_PREOP_COMPLETE && reason==SAFEUPLOAD_DENY_REASON_REGISTRY_SCOPE);
    reset();activating=1;
    assert(StageUnownedWritableSection(&data,&objects)==FLT_PREOP_COMPLETE && reason==SAFEUPLOAD_DENY_REASON_ACTIVATING_NAME);
    puts("outside production shims PASS: alias identity/failures/bounds, metadata/content, directory pins/cap, section attribution");
}
'''


class OutsideTests(unittest.TestCase):
    def test_production_bodies(self):
        alias = (K / 'StageAlias.c').read_text().replace('#include "Stage.h"', '')
        alias = re.sub(r"#define ALIAS_TAG '[^']+'", '#define ALIAS_TAG 1', alias)
        names = ('StageDirectoryPlainPath', 'StageDirectoryPlainName',
                 'StageDirectoryCreateCanMutate', 'StageNameLookupProvesAbsent',
                 'StageDirectoryCollisionComplete', 'StageAdmitDirectoryMutation',
                 'StagePhysicalMutationEx', 'StageUnownedWritableSection')
        program = SHIM + alias + '\n'.join(definition('StageStream.c', name) for name in names) + CASES
        out = ROOT / '.scratch/checks/outside'
        out.mkdir(parents=True, exist_ok=True)
        (out / 'shim.c').write_text(program)
        subprocess.run(['gcc', '-std=c11', '-fshort-wchar', '-Wall', '-Wextra', '-Werror',
                        str(out / 'shim.c'), '-o', str(out / 'shim')], check=True)
        subprocess.run([str(out / 'shim')], check=True)

    def test_completion_and_callsite_contracts(self):
        source = (K / 'StageStream.c').read_text()
        post = t.body('StageStream.c', 'SafeUploadStagePostOperation')
        start = post.index('if (FlagOn(token->OperationKind, STAGE_EPOCH_DIRECTORY_COLLISION))')
        end = post.index('return FLT_POSTOP_FINISHED_PROCESSING;', start)
        close = post[start:end]
        self.assertLess(close.index('StageDirectoryCollisionComplete'), close.index('SafeUploadPolicyAdmissionRelease'))
        self.assertNotIn('IoStatus.Status =', close)
        self.assertNotIn('FLTFL_POST_OPERATION_DRAINING', close)  # same close on success/failure/drain
        dispatch = t.body('StageStream.c', 'StageDispatchCore')
        self.assertLess(dispatch.index('AdmissionSlot->DirectoryCollision = TRUE'), dispatch.index('SafeUploadPreCreate'))
        epoch = t.body('StageStream.c', 'StageDispatchEpoch')
        self.assertIn('slot.DirectoryCollision ? STAGE_EPOCH_DIRECTORY_COLLISION : 0', epoch)
        self.assertIn('token->DirectoryMutation = slot.DirectoryMutation;', epoch)
        self.assertLess(epoch.index('slot.DirectorySequence ='), epoch.index('StageDispatchCore('))
        self.assertIn('if (slot.DirectoryMutation) StageDirectoryEndMutation(FALSE);', epoch)
        self.assertIn('if (token->DirectoryMutation)', post)
        self.assertIn('StageDirectoryEndMutation(FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING))', post)
        admit = t.body('StageStream.c', 'StageAdmit')
        # Both explicitly typed and metadata-proved directory CREATEs must
        # return the retained collision pin to the same epoch-owned dispatch.
        self.assertEqual(admit.count('if (*DirectoryCollisionHold != NULL) return FLT_PREOP_SUCCESS_WITH_CALLBACK;'), 2)
        self.assertIn('AdmissionSlot != NULL && AdmissionSlot->Token != NULL', source)
        obj = t.body('StageAlias.c', 'SafeUploadStageCheckObjectAliases')
        self.assertNotIn('StageAliasOpenId', obj)
        self.assertIn('StageAliasQuery(Data, Instance, Object, Volume, Kind, Protected)', obj)
        for name in ('StageExternalRename', 'StageUnownedMutatingFsctl'):
            self.assertIn('SafeUploadStageCheckObjectAliases(Data,', t.body('StageStream.c', name))
        for file, names in {'StageAlias.c': ('StageAliasOpenId', 'StageAliasEntryProtected', 'StageAliasQuery'),
                            'StageStream.c': ('StageAdmitDirectoryMutation', 'StageDirectoryCollisionComplete')}.items():
            text = (K / file).read_text()
            for name in names:
                declaration = text.index('static ', text.index(name) - 65)
                pragma = text.index('#pragma alloc_text(PAGE, ' + name + ')')
                self.assertLess(declaration, pragma, name)
                self.assertIn('PAGED_CODE()', t.body(file, name))
        self.assertIn('14 => "registryScope"', (ROOT / 'agente/SafeUpload.Agent.Service/Diagnostics/DriverDiagnosticsSource.cs').read_text())


if __name__ == '__main__':
    unittest.main()
