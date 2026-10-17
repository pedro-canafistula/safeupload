/* Inject OS boundaries, compile the actual native authorization and exact
 * descriptor-query bodies. Host controls; no Windows qualification claim. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
typedef void VOID,*PVOID,*HANDLE;
typedef int32_t NTSTATUS;
typedef uint32_t ULONG,ACCESS_MASK;
typedef uint16_t USHORT;
typedef wchar_t WCHAR;
typedef unsigned char BOOLEAN;
typedef struct { USHORT Length,MaximumLength; WCHAR *Buffer; } UNICODE_STRING,*PUNICODE_STRING;
typedef struct { uint64_t VolumeSerialNumber; unsigned char FileId[16]; } FILE_ID_INFORMATION;
typedef struct { ACCESS_MASK Masks[3]; ULONG Valid; } SECURITY_DESCRIPTOR_RELATIVE,*PSECURITY_DESCRIPTOR;
typedef struct { FILE_ID_INFORMATION Identity; PSECURITY_DESCRIPTOR Security; BOOLEAN DeleteAccess; } FILE_OBJECT,*PFILE_OBJECT;
typedef struct { HANDLE RootDirectory; ULONG FileNameLength; WCHAR FileName[200]; } FILE_RENAME_INFORMATION,*PFILE_RENAME_INFORMATION;
typedef struct { NTSTATUS Status; uintptr_t Information; } IO_STATUS_BLOCK;
typedef struct { PFILE_OBJECT TargetFileObject; struct { struct { PVOID InfoBuffer; PFILE_OBJECT ParentOfTarget; } SetFileInformation; } Parameters; } IOPB;
typedef struct { IOPB *Iopb; PVOID Thread; } CALLBACK_DATA,*PFLT_CALLBACK_DATA;
typedef PVOID PFLT_INSTANCE,PEPROCESS;
typedef struct { int CapturedSubject; } SECURITY_SUBJECT_CONTEXT;
typedef PVOID PPRIVILEGE_SET;
typedef struct { PUNICODE_STRING Name; } OBJECT_ATTRIBUTES;
#define _In_
#define _In_opt_
#define _Outptr_result_nullonfailure_
#define _IRQL_requires_(x)
#define TRUE 1
#define FALSE 0
#define PASSIVE_LEVEL 0
#define UserMode 1
#define PAGED_CODE() assert(Irql==0)
#define NT_SUCCESS(s) ((s)>=0)
#define STATUS_SUCCESS 0
#define STATUS_ACCESS_DENIED -1
#define STATUS_SHARING_VIOLATION -2
#define STATUS_OBJECT_PATH_INVALID -3
#define STATUS_INVALID_SECURITY_DESCR -4
#define STATUS_BUFFER_TOO_SMALL -5
#define STATUS_INSUFFICIENT_RESOURCES -6
#define STATUS_STOPPED_ON_SYMLINK -7
#define STATUS_NOT_SUPPORTED -8
#define DELETE 2
#define FILE_ADD_FILE 1
#define FILE_DELETE_CHILD 4
#define READ_CONTROL 8
#define OBJ_KERNEL_HANDLE 1
#define OBJ_CASE_INSENSITIVE 2
#define FILE_SHARE_READ 1
#define FILE_SHARE_WRITE 2
#define FILE_SHARE_DELETE 4
#define FILE_OPEN 1
#define FILE_OPENED 1
#define FILE_DIRECTORY_FILE 1
#define FILE_NON_DIRECTORY_FILE 2
#define IO_IGNORE_SHARE_ACCESS_CHECK 1
#define IO_STOP_ON_SYMLINK 2
#define OWNER_SECURITY_INFORMATION 1
#define GROUP_SECURITY_INFORMATION 2
#define DACL_SECURITY_INFORMATION 4
#define POOL_FLAG_PAGED 1
#define SAFEUPLOAD_POOL_TAG 1
#define FileIdInformation 59
#define RtlEqualMemory(a,b,c) (memcmp(a,b,c)==0)
static int Irql,SubjectClass,Locks,Captures,AccessChecks,QueryFault,IdentityFault,IdentityShort,Opens,Descriptors;
static FILE_OBJECT Parent,Target;
static struct { PVOID Filter; } SafeUploadData;
static UNICODE_STRING u(const WCHAR *s){USHORT n=0;while(s[n])++n;return (UNICODE_STRING){(USHORT)(n*2),(USHORT)(n*2),(WCHAR *)s};}
static BOOLEAN RtlEqualUnicodeString(PUNICODE_STRING a,PUNICODE_STRING b,BOOLEAN ignore)
{ (void)ignore;return a->Length==b->Length&&!memcmp(a->Buffer,b->Buffer,a->Length); }
static void InitializeObjectAttributes(OBJECT_ATTRIBUTES *a,PUNICODE_STRING n,int f,PVOID r,PVOID s)
{ (void)f;(void)r;(void)s;a->Name=n; }
static int KeGetCurrentIrql(void){return Irql;}
static PEPROCESS FltGetRequestorProcess(PFLT_CALLBACK_DATA d){(void)d;return (PVOID)2;}
static NTSTATUS FltCreateFileEx2(PVOID filter,PFLT_INSTANCE instance,HANDLE *h,PFILE_OBJECT *f,ACCESS_MASK access,
 OBJECT_ATTRIBUTES *a,IO_STATUS_BLOCK *io,PVOID allocation,int attr,int share,int disposition,int options,PVOID ea,int len,int flags,PVOID ctx)
{ (void)filter;(void)instance;(void)a;(void)allocation;(void)attr;(void)ea;(void)len;(void)ctx;
 assert(!Locks&&access==READ_CONTROL&&share==7&&disposition==FILE_OPEN&&flags==3);
 Opens++;*f=options==FILE_DIRECTORY_FILE?&Parent:&Target;*h=*f;io->Status=0;io->Information=FILE_OPENED;return 0; }
static NTSTATUS FltQueryInformationFile(PFLT_INSTANCE i,PFILE_OBJECT f,PVOID buffer,ULONG len,int cls,ULONG *returned)
{ (void)i;assert(!Locks&&len==sizeof(FILE_ID_INFORMATION)&&cls==FileIdInformation);
 if(IdentityFault){return STATUS_ACCESS_DENIED;}memcpy(buffer,&f->Identity,len);*returned=IdentityShort?0:len;return 0; }
static NTSTATUS FltQuerySecurityObject(PFLT_INSTANCE i,PFILE_OBJECT f,int which,PSECURITY_DESCRIPTOR s,ULONG len,ULONG *needed)
{ (void)i;(void)which;assert(!Locks);if(QueryFault)return STATUS_ACCESS_DENIED;*needed=sizeof(*s);
 if(!s){return STATUS_BUFFER_TOO_SMALL;}assert(len==sizeof(*s));memcpy(s,f->Security,len);*needed=0;return 0; }
static BOOLEAN RtlValidRelativeSecurityDescriptor(PSECURITY_DESCRIPTOR s,ULONG len,int flags)
{ (void)len;(void)flags;return s->Valid==1; }
static PVOID ExAllocatePool2(int flags,ULONG bytes,int tag){(void)flags;(void)tag;Descriptors++;return malloc(bytes);}
static void ExFreePoolWithTag(PVOID p,int tag){(void)tag;assert(p&&Descriptors>0);Descriptors--;free(p);}
static void ExFreePool(PVOID p){free(p);}
static void ObDereferenceObject(PFILE_OBJECT f){assert(f==&Parent||f==&Target);}
static void FltClose(HANDLE h){assert(h==&Parent||h==&Target);Opens--;}
static void SeCaptureSubjectContextEx(PVOID thread,PEPROCESS process,SECURITY_SUBJECT_CONTEXT *s)
{ assert(thread==(PVOID)1&&process==(PVOID)2&&!Locks);s->CapturedSubject=SubjectClass;Captures++; }
static void SeLockSubjectContext(SECURITY_SUBJECT_CONTEXT *s){(void)s;assert(!Locks);Locks++;}
static void SeUnlockSubjectContext(SECURITY_SUBJECT_CONTEXT *s){(void)s;assert(Locks==1);Locks--;}
static void SeReleaseSubjectContext(SECURITY_SUBJECT_CONTEXT *s){(void)s;assert(!Locks);}
static PVOID IoGetFileObjectGenericMapping(void){return NULL;}
static BOOLEAN SeAccessCheck(PSECURITY_DESCRIPTOR sd,SECURITY_SUBJECT_CONTEXT *s,BOOLEAN locked,ACCESS_MASK access,
 ACCESS_MASK previous,PPRIVILEGE_SET *privileges,PVOID mapping,int mode,ACCESS_MASK *granted,NTSTATUS *status)
{ (void)previous;(void)privileges;(void)mapping;assert(locked&&Locks==1&&mode==UserMode);AccessChecks++;
 *granted=sd->Masks[s->CapturedSubject]&access;*status=*granted==access?0:STATUS_ACCESS_DENIED;return *status==0; }
static void SeFreePrivileges(PPRIVILEGE_SET p){assert(!p);}
/* PRODUCTION */
static FILE_ID_INFORMATION id(int volume,int leaf)
{ FILE_ID_INFORMATION r={0};r.VolumeSerialNumber=(uint64_t)volume;r.FileId[15]=(unsigned char)leaf;return r; }
int main(void)
{
 SECURITY_DESCRIPTOR_RELATIVE ps={{7,7,0},1},ts={{7,0,0},1};
 Parent=(FILE_OBJECT){id(1,2),&ps,0};Target=(FILE_OBJECT){id(1,3),&ts,0};FILE_OBJECT source={id(1,1),&ts,1};
 FILE_ID_INFORMATION src=source.Identity,parent=Parent.Identity,target=Target.Identity;
 FILE_RENAME_INFORMATION rename={0};rename.FileName[0]=L'x';rename.FileNameLength=2;
 IOPB io={.TargetFileObject=&source};io.Parameters.SetFileInformation.InfoBuffer=&rename;
 CALLBACK_DATA data={&io,(PVOID)1};UNICODE_STRING sn=u(L"\\Device\\V\\Protected\\old.txt"),dn=u(L"\\Device\\V\\Protected\\new.txt");
 /* Original parent lookup carries traversal/create authority, without a
  * bypass-traverse privilege requirement or a new target share-access open. */
 io.Parameters.SetFileInformation.ParentOfTarget=&Parent;
 for(SubjectClass=0;SubjectClass<3;SubjectClass++)for(int t=0;t<2;t++)for(int p=0;p<2;p++){
  ts.Masks[SubjectClass]=t?DELETE:0;ps.Masks[SubjectClass]=p?FILE_DELETE_CHILD:0;
  assert(SafeUploadStageCheckNativeReplace(&data,(PVOID)1,&sn,&dn,&src,&parent,&target,TRUE)==((t||p)?0:STATUS_ACCESS_DENIED));
  assert(!Locks&&!Opens&&!Descriptors);
 }
 SubjectClass=0;ps.Masks[0]=0;ts.Masks[0]=DELETE;
 /* Exact full identity, not just file-ID low half or matching path. */
 Parent.Identity.VolumeSerialNumber=9;
 assert(SafeUploadStageCheckNativeReplace(&data,(PVOID)1,&sn,&dn,&src,&parent,&target,TRUE)==STATUS_SHARING_VIOLATION);
 Parent.Identity=parent;Target.Identity.FileId[0]=9;
 assert(SafeUploadStageCheckNativeReplace(&data,(PVOID)1,&sn,&dn,&src,&parent,&target,TRUE)==STATUS_SHARING_VIOLATION);
 Target.Identity=target;
 for(int fault=0;fault<3;fault++){
  QueryFault=fault==0;IdentityFault=fault==1;IdentityShort=fault==2;
  assert(SafeUploadStageCheckNativeReplace(&data,(PVOID)1,&sn,&dn,&src,&parent,&target,TRUE)<0);
  assert(!Locks&&!Opens&&!Descriptors);
 }
 QueryFault=IdentityFault=IdentityShort=0;
 /* Same-object rename retains source DELETE already granted even if the DACL
  * has since revoked it; it is not a fresh open of the target. */
 ts.Masks[0]=0;
 assert(SafeUploadStageCheckNativeReplace(&data,(PVOID)1,&sn,&dn,&src,&parent,&src,TRUE)==0);
 /* Relative leaf uses the source parent; create-child still checked. */
 io.Parameters.SetFileInformation.ParentOfTarget=NULL;ps.Masks[0]=FILE_ADD_FILE|FILE_DELETE_CHILD;
 assert(SafeUploadStageCheckNativeReplace(&data,(PVOID)1,&sn,&dn,&src,&parent,&target,TRUE)==0);
 ps.Masks[0]=FILE_DELETE_CHILD;
 assert(SafeUploadStageCheckNativeReplace(&data,(PVOID)1,&sn,&dn,&src,&parent,&target,TRUE)==STATUS_ACCESS_DENIED);
 ps.Masks[0]=FILE_ADD_FILE;
 assert(SafeUploadStageCheckNativeReplace(&data,(PVOID)1,&sn,&dn,&src,&parent,&target,FALSE)==0);
 for(int shape=0;shape<3;shape++){
  rename.RootDirectory=shape==0?(PVOID)1:NULL;rename.FileName[0]=shape==1?L'\\':L':';
  assert(SafeUploadStageCheckNativeReplace(&data,(PVOID)1,&sn,&dn,&src,&parent,&target,FALSE)<0);
 }
 rename.RootDirectory=NULL;rename.FileName[0]=L'x';UNICODE_STRING elsewhere=u(L"\\Device\\V\\Elsewhere\\new.txt");
 assert(SafeUploadStageCheckNativeReplace(&data,(PVOID)1,&sn,&elsewhere,&src,&parent,&target,FALSE)==STATUS_SHARING_VIOLATION);
 assert(!Locks&&!Opens&&!Descriptors&&Captures>0&&AccessChecks>0);
 puts("native replacement: original subjects, parent alternatives, exact SD identity, faults, relative lookup, existing grants PASS");
}
