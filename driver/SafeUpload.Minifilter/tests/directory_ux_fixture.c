/* Injectable OS boundaries only; the runner inserts actual production bodies. */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
typedef void VOID, *PVOID, *HANDLE, **PHANDLE, *PFLT_INSTANCE, *PFLT_VOLUME;
typedef int32_t NTSTATUS, LONG, *PLONG;
typedef int64_t LONG64;
typedef uint32_t ULONG, UINT32, ACCESS_MASK, *PULONG;
typedef uint16_t USHORT;
typedef wchar_t WCHAR;
typedef const WCHAR *PCWCH;
typedef uint8_t BOOLEAN, *PBOOLEAN;
typedef struct { USHORT Length, MaximumLength; WCHAR *Buffer; } UNICODE_STRING, *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;
typedef struct _LIST_ENTRY { struct _LIST_ENTRY *Flink, *Blink; } LIST_ENTRY, *PLIST_ENTRY;
typedef struct { UNICODE_STRING Name, Stream, Volume; } FLT_FILE_NAME_INFORMATION, *PFLT_FILE_NAME_INFORMATION;
typedef struct { UNICODE_STRING FileName; } FILE_OBJECT, *PFILE_OBJECT;
typedef struct { ACCESS_MASK DesiredAccess; } IO_SECURITY_CONTEXT, *PIO_SECURITY_CONTEXT;
typedef struct { NTSTATUS Status; ULONG Information; } IO_STATUS_BLOCK;
typedef int FILE_INFORMATION_CLASS, FLT_FILESYSTEM_TYPE, SAFEUPLOAD_VOLUME_KIND, FLT_PREOP_CALLBACK_STATUS;
typedef struct { BOOLEAN Directory; } FILE_STANDARD_INFORMATION;
typedef struct { ULONG FileAttributes, ReparseTag; } FILE_ATTRIBUTE_TAG_INFORMATION;
typedef struct { BOOLEAN DeleteFile; } FILE_DISPOSITION_INFORMATION, *PFILE_DISPOSITION_INFORMATION;
typedef struct { ULONG Flags; HANDLE RootDirectory; ULONG FileNameLength; WCHAR FileName[512]; } FILE_RENAME_INFORMATION, *PFILE_RENAME_INFORMATION;
typedef struct { struct { ULONG Options, FileAttributes, EaLength; PVOID EaBuffer; PIO_SECURITY_CONTEXT SecurityContext; } Create;
    struct { FILE_INFORMATION_CLASS FileInformationClass; PVOID InfoBuffer; ULONG Length; } SetFileInformation; } PARAMETERS;
typedef struct { PARAMETERS Parameters; ULONG OperationFlags; } IOPB;
typedef struct { IOPB *Iopb; IO_STATUS_BLOCK IoStatus; } CALLBACK_DATA, *PFLT_CALLBACK_DATA;
typedef struct { PFLT_INSTANCE Instance; PFILE_OBJECT FileObject; PFLT_VOLUME Volume; PVOID Transaction; } RELATED_OBJECTS;
typedef const RELATED_OBJECTS *PCFLT_RELATED_OBJECTS;
typedef struct { ULONG PrefixCount; UNICODE_STRING Prefixes[4]; } SAFEUPLOAD_POLICY;
typedef struct { BOOLEAN Overflow; ULONG PrefixCount; USHORT PrefixChars[4]; WCHAR Prefixes[4][512]; } BOOT_SCOPES;
typedef struct { PVOID Token; LONG64 DirectorySequence; BOOLEAN DirectoryMutation; } STAGE_ADMISSION_TOKEN_SLOT, *PSTAGE_ADMISSION_TOKEN_SLOT;
typedef struct { UNICODE_STRING Name; } STAGE_VIEW;
typedef struct { struct { WCHAR Path[512]; ULONG PathLength; } Request; } EXCHANGE;
typedef struct { LIST_ENTRY Link, ReservationLink; UNICODE_STRING Name; STAGE_VIEW *View; EXCHANGE *RenameExchange; } STAGE_STREAM, *PSTAGE_STREAM;
typedef struct { int unused; } OBJECT_ATTRIBUTES;
#define _In_
#define _Inout_
#define _In_opt_
#define _Out_
#define _Out_opt_
#define _IRQL_requires_(x)
#define _IRQL_requires_max_(x)
#define TRUE 1
#define FALSE 0
#define PASSIVE_LEVEL 0
#define DISPATCH_LEVEL 2
#define STATUS_SUCCESS 0
#define STATUS_ACCESS_DENIED -1
#define STATUS_SHARING_VIOLATION -2
#define STATUS_DEVICE_NOT_READY -3
#define STATUS_NOT_SAME_DEVICE -4
#define STATUS_NOT_SUPPORTED -5
#define STATUS_OBJECT_PATH_NOT_FOUND -6
#define STATUS_INVALID_PARAMETER -7
#define NT_SUCCESS(s) ((s) >= 0)
#define FILE_SUPERSEDE 0
#define FILE_OPEN 1
#define FILE_CREATE 2
#define FILE_OPEN_IF 3
#define FILE_OVERWRITE 4
#define FILE_OVERWRITE_IF 5
#define FILE_DIRECTORY_FILE 1
#define FILE_NON_DIRECTORY_FILE 0x40
#define FILE_DELETE_ON_CLOSE 0x1000
#define FILE_OPEN_BY_FILE_ID 0x2000
#define FILE_OPEN_REPARSE_POINT 0x200000
#define FILE_SYNCHRONOUS_IO_NONALERT 0x20
#define FILE_COMPLETE_IF_OPLOCKED 0x100
#define FILE_WRITE_DATA 2
#define FILE_APPEND_DATA 4
#define FILE_WRITE_EA 0x10
#define FILE_WRITE_ATTRIBUTES 0x100
#define FILE_DELETE_CHILD 0x40
#define FILE_READ_ATTRIBUTES 0x80
#define DELETE 0x10000
#define GENERIC_WRITE 0x40000000
#define GENERIC_ALL 0x10000000
#define MAXIMUM_ALLOWED 0x2000000
#define SYNCHRONIZE 0x100000
#define FILE_ATTRIBUTE_DIRECTORY 0x10
#define SL_CASE_SENSITIVE 1
#define STAGE_DIRECTORY_COLLISION_LIMIT 16
#define FileAttributeTagInformation 9
#define FILE_ATTRIBUTE_REPARSE_POINT 0x400
#define FILE_ATTRIBUTE_ENCRYPTED 0x4000
#define FILE_ATTRIBUTE_OFFLINE 0x1000
#define FILE_SHARE_READ 1
#define FILE_SHARE_WRITE 2
#define FILE_SHARE_DELETE 4
#define FILE_DISPOSITION_DELETE 1
#define FILE_DISPOSITION_ON_CLOSE 8
#define FLT_FILE_NAME_NORMALIZED 1
#define FLT_FILE_NAME_QUERY_DEFAULT 2
#define OBJ_KERNEL_HANDLE 1
#define OBJ_CASE_INSENSITIVE 2
#define SAFEUPLOAD_STAGING_PROTOTYPE 1
#define SAFEUPLOAD_DENY_REASON_PROTECTED_NAMESPACE 1
#define SAFEUPLOAD_DENY_REASON_NAME_UNRESOLVED 2
#define FLT_PREOP_SUCCESS_NO_CALLBACK 0
#define FLT_PREOP_COMPLETE 1
#define SafeUploadVolumeFixed 1
#define SafeUploadVolumeRemovable 2
#define FLT_FSTYPE_NTFS 1
#define FileDispositionInformation 1
#define FileDispositionInformationEx 2
#define FileBasicInformation 3
#define FileRenameInformation 4
#define FileRenameInformationEx 5
#define FileLinkInformation 6
#define FileLinkInformationEx 7
#define FileStandardInformation 8
#define MAXUSHORT UINT16_MAX
#define min(a,b) ((a)<(b)?(a):(b))
#define FlagOn(a,b) ((a)&(b))
#define RTL_NUMBER_OF(a) (sizeof(a)/sizeof((a)[0]))
#define FIELD_OFFSET(t,f) offsetof(t,f)
#define CONTAINING_RECORD(p,t,f) ((t *)((char *)(p)-offsetof(t,f)))
#define InitializeObjectAttributes(a,n,f,r,s) ((void)(a),(void)(n),(void)(f),(void)(r),(void)(s))
#define PAGED_CODE() assert(Irql == PASSIVE_LEVEL)
static int Irql, NamespaceDepth, StageNamespaceResource, SafeUploadPolicyLock;
static volatile LONG StageDirectoryMutationActive;
static volatile LONG StageDirectoryCollisionHolds;
static volatile LONG StageMvpNamespaceFence; /* merged with ux/kernel: the private rename also honours its namespace fence */
static volatile LONG64 StageDirectorySequence;
static BOOLEAN StageStopping, SafeUploadBootScopesActive;
static LIST_ENTRY StageStreams, StageAllocationReservations;
static const SAFEUPLOAD_POLICY *SafeUploadPolicy, *SafeUploadPendingPolicy;
static BOOT_SCOPES SafeUploadBootScopes;
static struct { PVOID Filter; ULONG InspectorProcessId; } SafeUploadData;
static int NativeDirectory, Kind, Fs, MayMatch, Auth, PrepareCalls, Dirty, ProbeRefs, ProbeCalls;
static NTSTATUS NameStatus, ParseStatus, DestinationStatus, ProbeStatus;
static FLT_FILE_NAME_INFORMATION Source, Destination;
static FILE_OBJECT ProbeObject;
static UNICODE_STRING u(const WCHAR *s) { size_t n=0; while(s[n]) ++n; return (UNICODE_STRING){(USHORT)(n*2),(USHORT)(n*2),(WCHAR *)s}; }
static WCHAR fold(WCHAR c) { return c>=L'a' && c<=L'z' ? (WCHAR)(c-L'a'+L'A') : c; }
static BOOLEAN RtlPrefixUnicodeString(PCUNICODE_STRING prefix, PCUNICODE_STRING path, BOOLEAN ignore)
{ assert(Irql==0); if(prefix->Length>path->Length) return FALSE; for(USHORT i=0;i<prefix->Length/2;++i) if((ignore?fold(prefix->Buffer[i]):prefix->Buffer[i])!=(ignore?fold(path->Buffer[i]):path->Buffer[i])) return FALSE; return TRUE; }
static void StageAcquire(int *p) { assert(p==&StageNamespaceResource && NamespaceDepth==0 && Irql==0); ++NamespaceDepth; }
static void StageRelease(int *p) { assert(p==&StageNamespaceResource && NamespaceDepth==1); --NamespaceDepth; }
static LONG InterlockedCompareExchange(volatile LONG *p,LONG value,LONG compare) { LONG old=*p; if(old==compare)*p=value; return old; }
static LONG64 InterlockedCompareExchange64(volatile LONG64 *p,LONG64 value,LONG64 compare) { LONG64 old=*p; if(old==compare)*p=value; return old; }
static LONG InterlockedIncrement(volatile LONG *p) { return ++*p; }
static LONG InterlockedDecrement(volatile LONG *p) { return --*p; }
static LONG InterlockedExchange(volatile LONG *p,LONG value) { LONG old=*p; *p=value; return old; }
static LONG64 InterlockedIncrement64(volatile LONG64 *p) { return ++*p; }
static void FltAcquirePushLockShared(int *p) { assert(p==&SafeUploadPolicyLock && Irql==0); }
static void FltReleasePushLock(int *p) { assert(p==&SafeUploadPolicyLock); }
/* PRODUCTION_POLICY */
static BOOLEAN SafeUploadPolicyMatchesCurrentOrPendingDestination(SAFEUPLOAD_VOLUME_KIND kind, PCUNICODE_STRING path, BOOLEAN ancestors)
{ (void)kind; const SAFEUPLOAD_POLICY *policies[]={SafeUploadPolicy,SafeUploadPendingPolicy}; for(unsigned p=0;p<2;++p) if(policies[p]) for(ULONG i=0;i<policies[p]->PrefixCount;++i) if(SafeUploadPathUnderPrefix(&policies[p]->Prefixes[i],path)||(ancestors&&SafeUploadPathUnderPrefix(path,&policies[p]->Prefixes[i])))return TRUE; return FALSE; }
static BOOLEAN SafeUploadStageTouchesProtectedNamespace(PFLT_FILE_NAME_INFORMATION n, SAFEUPLOAD_VOLUME_KIND k) { return SafeUploadPolicyMatchesCurrentOrPendingDestination(k,&n->Name,TRUE); }
static SAFEUPLOAD_VOLUME_KIND StageVolumeKind(PFLT_INSTANCE p) { (void)p; return Kind; }
static BOOLEAN SafeUploadPolicyMayMatchInstanceVolume(PFLT_INSTANCE p) { (void)p; return (BOOLEAN)MayMatch; }
static NTSTATUS FltGetFileNameInformation(PFLT_CALLBACK_DATA d,int flags,PFLT_FILE_NAME_INFORMATION *n) { (void)d;(void)flags;assert(!NamespaceDepth&&Irql==0);*n=NameStatus==0?&Source:NULL;return NameStatus; }
static NTSTATUS FltParseFileNameInformation(PFLT_FILE_NAME_INFORMATION n) { assert(n&&Irql==0);return ParseStatus; }
static VOID FltReleaseFileNameInformation(PFLT_FILE_NAME_INFORMATION n) { assert(n); }
static NTSTATUS FltGetDestinationFileNameInformation(PFLT_INSTANCE i,PFILE_OBJECT o,HANDLE r,WCHAR *name,ULONG length,int flags,PFLT_FILE_NAME_INFORMATION *n)
{ (void)i;(void)o;(void)r;(void)name;(void)length;(void)flags;assert(!NamespaceDepth);*n=DestinationStatus==0?&Destination:NULL;return DestinationStatus; }
static NTSTATUS FltGetFileSystemType(PFLT_INSTANCE i,FLT_FILESYSTEM_TYPE *fs) { (void)i;assert(!NamespaceDepth);*fs=Fs;return 0; }
static BOOLEAN SafeUploadNameLookupProvesAbsent(NTSTATUS s) { return s==STATUS_OBJECT_PATH_NOT_FOUND; }
static VOID SafeUploadDenyDetail(PFLT_CALLBACK_DATA d,UINT32 r,NTSTATUS s,PUNICODE_STRING n) { (void)d;(void)r;(void)s;(void)n; }
static NTSTATUS FltIsDirectory(PFILE_OBJECT o,PFLT_INSTANCE i,PBOOLEAN d) { (void)o;(void)i;assert(!NamespaceDepth);*d=(BOOLEAN)NativeDirectory;return 0; }
static int KeGetCurrentIrql(void) { return Irql; }
static PVOID IoGetTopLevelIrp(void) { return NULL; }
static BOOLEAN SafeUploadIsAuthenticatedClient(void) { return (BOOLEAN)Auth; }
static ULONG FltGetRequestorProcessId(PFLT_CALLBACK_DATA d) { (void)d;return 100; }
static NTSTATUS SafeUploadStageCheckObjectAliases(PFLT_CALLBACK_DATA data,PFLT_INSTANCE i,PFILE_OBJECT o,PUNICODE_STRING v,SAFEUPLOAD_VOLUME_KIND k,PBOOLEAN p)
{ (void)data;(void)i;(void)o;(void)v;(void)k;*p=FALSE;return 0; }
static BOOLEAN SafeUploadPublicationRename(PFLT_VOLUME v,PUNICODE_STRING s,PUNICODE_STRING d,PBOOLEAN refused)
{ (void)v;(void)s;(void)d;*refused=FALSE;return FALSE; }
static NTSTATUS SafeUploadStageWritersPrepareRename(PFLT_CALLBACK_DATA d,PCFLT_RELATED_OBJECTS o,PUNICODE_STRING s,PUNICODE_STRING t,BOOLEAN link,PVOID *ctx)
{ (void)d;(void)o;(void)s;(void)t;(void)link;assert(!NamespaceDepth);++PrepareCalls;*ctx=(PVOID)(uintptr_t)16;return 0; }
static VOID SafeUploadStageWritersMutationDraining(PFLT_INSTANCE i,PVOID sop) { (void)i;(void)sop; }
/* Only the raw identity field used by the legacy fallback is added by macro. */
#define SectionObjectPointer FileName.Buffer
static NTSTATUS FltCreateFileEx(PVOID f,PFLT_INSTANCE i,HANDLE *h,PFILE_OBJECT *o,ACCESS_MASK access,OBJECT_ATTRIBUTES *a,IO_STATUS_BLOCK *io,PVOID size,ULONG attr,ULONG share,ULONG disp,ULONG options,PVOID ea,ULONG bytes,ULONG flags)
{ (void)f;(void)i;(void)a;(void)io;(void)size;(void)attr;assert(!NamespaceDepth&&Irql==0);assert(access==(FILE_READ_ATTRIBUTES|SYNCHRONIZE));assert(share==7&&disp==FILE_OPEN&&flags==0&&!ea&&!bytes);assert((options&(FILE_DIRECTORY_FILE|FILE_OPEN_REPARSE_POINT))==(FILE_DIRECTORY_FILE|FILE_OPEN_REPARSE_POINT));++ProbeCalls;if(ProbeStatus)return ProbeStatus;*h=&ProbeObject;*o=&ProbeObject;ProbeRefs=2;return 0; }
static NTSTATUS FltCreateFileEx2(PVOID f,PFLT_INSTANCE i,PHANDLE h,PFILE_OBJECT *o,ACCESS_MASK access,OBJECT_ATTRIBUTES *a,IO_STATUS_BLOCK *io,PVOID size,ULONG attr,ULONG share,ULONG disp,ULONG options,PVOID ea,ULONG bytes,ULONG flags,PVOID ctx)
{ (void)f;(void)i;(void)a;(void)io;(void)size;(void)attr;(void)ctx;assert(!NamespaceDepth&&Irql==0);assert(access==FILE_READ_ATTRIBUTES&&share==(FILE_SHARE_READ|FILE_SHARE_WRITE)&&disp==FILE_OPEN&&flags==0&&!ea&&!bytes);assert((options&(FILE_DIRECTORY_FILE|FILE_OPEN_REPARSE_POINT))==(FILE_DIRECTORY_FILE|FILE_OPEN_REPARSE_POINT));assert(StageDirectoryCollisionHolds>0);++ProbeCalls;if(ProbeStatus)return ProbeStatus;*h=&ProbeObject;*o=&ProbeObject;ProbeRefs=2;return 0; }
static NTSTATUS FltQueryInformationFile(PFLT_INSTANCE i,PFILE_OBJECT o,PVOID info,ULONG bytes,FILE_INFORMATION_CLASS c,PULONG returned)
{ (void)i;assert(!NamespaceDepth&&Irql==0&&o==&ProbeObject);if(c==FileStandardInformation){assert(bytes==sizeof(FILE_STANDARD_INFORMATION));((FILE_STANDARD_INFORMATION *)info)->Directory=(BOOLEAN)NativeDirectory;}else{assert(c==FileAttributeTagInformation&&bytes==sizeof(FILE_ATTRIBUTE_TAG_INFORMATION));((FILE_ATTRIBUTE_TAG_INFORMATION *)info)->FileAttributes=FILE_ATTRIBUTE_DIRECTORY;}if(returned)*returned=bytes;return 0; }
static VOID ObDereferenceObject(PFILE_OBJECT o) { assert(o==&ProbeObject&&ProbeRefs>0);--ProbeRefs; }
static VOID FltClose(HANDLE h) { assert(h==&ProbeObject&&ProbeRefs>0);--ProbeRefs; }
static VOID FltSetCallbackDataDirty(PFLT_CALLBACK_DATA d) { (void)d;++Dirty; }
/* PRODUCTION_DIRECTORY */
static void head(PLIST_ENTRY l) { l->Flink=l->Blink=l; }
static void add(PLIST_ENTRY h,PLIST_ENTRY e) { e->Flink=h;e->Blink=h->Blink;h->Blink->Flink=e;h->Blink=e; }
static SAFEUPLOAD_POLICY Policy, Pending;
static void reset(void)
{
 Irql=NamespaceDepth=StageDirectoryMutationActive=StageStopping=SafeUploadBootScopesActive=0;
 StageDirectorySequence=0; StageDirectoryCollisionHolds=0; Kind=SafeUploadVolumeFixed;Fs=FLT_FSTYPE_NTFS;MayMatch=NativeDirectory=1;Auth=PrepareCalls=Dirty=ProbeRefs=ProbeCalls=0;
 NameStatus=ParseStatus=DestinationStatus=ProbeStatus=0;head(&StageStreams);head(&StageAllocationReservations);
 memset(&SafeUploadBootScopes,0,sizeof(SafeUploadBootScopes));memset(&Policy,0,sizeof(Policy));memset(&Pending,0,sizeof(Pending));
 Policy.PrefixCount=1;Policy.Prefixes[0]=u(L"\\Device\\V\\Protected");SafeUploadPolicy=&Policy;SafeUploadPendingPolicy=NULL;
 Source=(FLT_FILE_NAME_INFORMATION){.Name=u(L"\\Device\\V\\Protected\\folder"),.Volume=u(L"\\Device\\V")};
 Destination=(FLT_FILE_NAME_INFORMATION){.Name=u(L"\\Device\\V\\Protected\\new"),.Volume=u(L"\\Device\\V")};
}
static STAGE_ADMISSION_TOKEN_SLOT slot(void) { return (STAGE_ADMISSION_TOKEN_SLOT){.Token=(PVOID)(uintptr_t)8,.DirectorySequence=StageDirectorySequence}; }
static void tests(void)
{
 IOPB iopb={0}; CALLBACK_DATA data={.Iopb=&iopb}; FILE_OBJECT file={.FileName=u(L"\\Protected\\folder")}; RELATED_OBJECTS objects={.Instance=(PVOID)1,.FileObject=&file};
 HANDLE hold=NULL;
 IO_SECURITY_CONTEXT security={.DesiredAccess=GENERIC_ALL};iopb.Parameters.Create.SecurityContext=&security;
 reset();
 UNICODE_STRING root=u(L"\\Device\\V\\Protected"),child=u(L"\\Device\\V\\Protected\\a\\b.txt"),sibling=u(L"\\Device\\V\\Protected2\\a");
 assert(SafeUploadPathUnderPrefix(&root,&child));assert(!SafeUploadPathUnderPrefix(&root,&sibling));assert(StageDirectoryContains(&root,&child));assert(!StageDirectoryContains(&root,&sibling));
 assert(SafeUploadPolicyDirectoryIsScopeAnchor(&root));assert(!SafeUploadPolicyDirectoryIsScopeAnchor(&Source.Name));
 Pending.PrefixCount=1;Pending.Prefixes[0]=Source.Name;SafeUploadPendingPolicy=&Pending;assert(SafeUploadPolicyDirectoryIsScopeAnchor(&Source.Name));SafeUploadPendingPolicy=NULL;
 assert(StageDirectoryPlainName(&Source,&file));UNICODE_STRING selectors[]={u(L"x:stream"),u(L"dir::$DATA"),u(L"dir:$I30:$INDEX_ALLOCATION"),u(L"a:$INDEX_ALLOCATION"),u(L"dir:Zone.Identifier")};
 for(unsigned i=0;i<RTL_NUMBER_OF(selectors);++i)assert(!StageDirectoryPlainPath(&selectors[i]));
 UNICODE_STRING drive=u(L"C:\\Protected\\folder"),ntdrive=u(L"\\??\\C:\\Protected\\folder");assert(StageDirectoryPlainPath(&drive)&&StageDirectoryPlainPath(&ntdrive));
 for(ULONG disposition=0;disposition<=5;++disposition){ iopb.Parameters.Create.Options=FILE_DIRECTORY_FILE|(disposition<<24);assert(StageAdmitDirectoryMutation(&data,&objects,TRUE,&hold)==((disposition==1||disposition==2||disposition==3)?0:1)); }
 iopb.Parameters.Create.Options=FILE_DIRECTORY_FILE|(FILE_CREATE<<24);iopb.Parameters.Create.EaLength=1;assert(StageAdmitDirectoryMutation(&data,&objects,TRUE,&hold)==1);iopb.Parameters.Create.EaLength=0;
 iopb.Parameters.Create.EaBuffer=&file;assert(StageAdmitDirectoryMutation(&data,&objects,TRUE,&hold)==1);iopb.Parameters.Create.EaBuffer=NULL;
 iopb.Parameters.Create.Options|=FILE_DELETE_ON_CLOSE;assert(StageAdmitDirectoryMutation(&data,&objects,TRUE,&hold)==1);iopb.Parameters.Create.Options&=~FILE_DELETE_ON_CLOSE;
 NameStatus=STATUS_OBJECT_PATH_NOT_FOUND;assert(StageAdmitDirectoryMutation(&data,&objects,TRUE,&hold)==0);NameStatus=STATUS_ACCESS_DENIED;assert(StageAdmitDirectoryMutation(&data,&objects,TRUE,&hold)==1);NameStatus=0;
 /* Existing scope roots and ancestors must remain collision-only. New child folders stay native above. */
 Source.Name=root;iopb.Parameters.Create.Options=FILE_DIRECTORY_FILE|(FILE_CREATE<<24);
 assert(StageAdmitDirectoryMutation(&data,&objects,TRUE,&hold)==0&&hold&&StageDirectoryCollisionHolds==1&&ProbeRefs==1);
 StageDirectoryCollisionComplete(hold);assert(StageDirectoryCollisionHolds==0&&ProbeRefs==0);
 Source.Name=u(L"\\Device\\V");
 assert(StageAdmitDirectoryMutation(&data,&objects,TRUE,&hold)==0&&hold&&StageDirectoryCollisionHolds==1);
 StageDirectoryCollisionComplete(hold);assert(StageDirectoryCollisionHolds==0&&ProbeRefs==0);
 ProbeStatus=STATUS_OBJECT_PATH_NOT_FOUND;assert(StageAdmitDirectoryMutation(&data,&objects,TRUE,&hold)==1&&!hold&&!StageDirectoryCollisionHolds);ProbeStatus=0;
 reset();
 iopb.Parameters.Create.Options=FILE_OPEN<<24;assert(StageExistingDirectory(&data,&objects,&Source));assert(iopb.Parameters.Create.Options&FILE_DIRECTORY_FILE);assert(Dirty==1&&ProbeRefs==0&&ProbeCalls==1);
 iopb.Parameters.Create.Options=FILE_OPEN<<24;ProbeStatus=STATUS_SHARING_VIOLATION;assert(!StageExistingDirectory(&data,&objects,&Source));assert(!(iopb.Parameters.Create.Options&FILE_DIRECTORY_FILE));ProbeStatus=0;
 STAGE_STREAM stream={.Name=child};STAGE_ADMISSION_TOKEN_SLOT token=slot();add(&StageStreams,&stream.Link);assert(StageDirectoryBeginMutation(&root,NULL,&token)==STATUS_SHARING_VIOLATION);head(&StageStreams);
 add(&StageAllocationReservations,&stream.ReservationLink);assert(StageDirectoryBeginMutation(&root,NULL,&token)==STATUS_SHARING_VIOLATION);head(&StageAllocationReservations);
 STAGE_VIEW view={.Name=child};stream.Name=sibling;stream.View=&view;add(&StageStreams,&stream.Link);assert(StageDirectoryBeginMutation(&root,NULL,&token)==STATUS_SHARING_VIOLATION);head(&StageStreams);stream.View=NULL;
 stream.Name=child;add(&StageStreams,&stream.Link);assert(StageDirectoryBeginMutation(&sibling,&root,&token)==STATUS_SHARING_VIOLATION);head(&StageStreams);
 EXCHANGE exchange={0};UNICODE_STRING target=u(L"\\Device\\V\\Protected\\folder\\new.txt");memcpy(exchange.Request.Path,target.Buffer,target.Length);exchange.Request.PathLength=target.Length;stream.Name=sibling;stream.RenameExchange=&exchange;add(&StageStreams,&stream.Link);assert(StageDirectoryBeginMutation(&root,NULL,&token)==STATUS_SHARING_VIOLATION);head(&StageStreams);
 assert(StageDirectoryBeginMutation(&root,NULL,&token)==0&&token.DirectoryMutation&&StageDirectoryMutationActive);STAGE_ADMISSION_TOKEN_SLOT other=slot();assert(StageDirectoryBeginMutation(&root,NULL,&other)==STATUS_SHARING_VIOLATION);
 Irql=DISPATCH_LEVEL;StageDirectoryEndMutation(FALSE);Irql=0;assert(!StageDirectoryMutationActive);assert(StageDirectoryBeginMutation(&root,NULL,&token)==STATUS_SHARING_VIOLATION); /* stale lookup */
 token=slot();assert(StageDirectoryBeginMutation(&root,NULL,&token)==0);Irql=DISPATCH_LEVEL;StageDirectoryEndMutation(TRUE);Irql=0;assert(StageDirectoryMutationActive);reset();
 FILE_RENAME_INFORMATION rename={0};UNICODE_STRING newname=u(L"\\Device\\V\\Protected\\new");memcpy(rename.FileName,newname.Buffer,newname.Length);rename.FileNameLength=newname.Length;
 iopb.Parameters.SetFileInformation.FileInformationClass=FileRenameInformation;iopb.Parameters.SetFileInformation.InfoBuffer=&rename;iopb.Parameters.SetFileInformation.Length=sizeof(rename);PVOID ctx=NULL;token=slot();
 assert(StageExternalRename(&data,&objects,FALSE,&ctx,&token)==0&&token.DirectoryMutation&&PrepareCalls==1);StageDirectoryEndMutation(FALSE);
 reset();Source.Name=u(L"\\Device\\V\\Outside\\folder");token=slot();assert(StageExternalRename(&data,&objects,TRUE,&ctx,&token)==1&&data.IoStatus.Status==STATUS_NOT_SAME_DEVICE&&!token.DirectoryMutation);
 reset();token=slot();stream=(STAGE_STREAM){.Name=u(L"\\Device\\V\\Protected\\folder\\deep\\cpf.txt")};add(&StageStreams,&stream.Link);assert(StageExternalRename(&data,&objects,TRUE,&ctx,&token)==1&&data.IoStatus.Status==STATUS_SHARING_VIOLATION&&!token.DirectoryMutation);
 reset();Destination.Name=u(L"\\Device\\V\\Outside\\folder");newname=Destination.Name;memcpy(rename.FileName,newname.Buffer,newname.Length);rename.FileNameLength=newname.Length;token=slot();assert(StageExternalRename(&data,&objects,FALSE,&ctx,&token)==0&&token.DirectoryMutation);StageDirectoryEndMutation(FALSE);
 reset();Source.Name=root;token=slot();assert(StageExternalRename(&data,&objects,FALSE,&ctx,&token)==1&&data.IoStatus.Status==STATUS_ACCESS_DENIED);
 reset();FILE_DISPOSITION_INFORMATION disposition={.DeleteFile=TRUE};iopb.Parameters.SetFileInformation.FileInformationClass=FileDispositionInformation;iopb.Parameters.SetFileInformation.InfoBuffer=&disposition;iopb.Parameters.SetFileInformation.Length=sizeof(disposition);BOOLEAN handled=FALSE;token=slot();assert(StageNativeDirectoryInformation(&data,&objects,&token,&handled)==0&&handled&&token.DirectoryMutation);StageDirectoryEndMutation(FALSE);
 reset();token=slot();stream=(STAGE_STREAM){.Name=u(L"\\Device\\V\\Protected\\folder\\file")};add(&StageStreams,&stream.Link);assert(StageNativeDirectoryInformation(&data,&objects,&token,&handled)==1&&handled&&data.IoStatus.Status==STATUS_SHARING_VIOLATION);
 disposition.DeleteFile=FALSE;assert(StageNativeDirectoryInformation(&data,&objects,&token,&handled)==0&&handled&&!token.DirectoryMutation);
 Source.Name=root;assert(StageNativeDirectoryInformation(&data,&objects,&token,&handled)==0&&handled&&!token.DirectoryMutation);
 ULONG flags=0;iopb.Parameters.SetFileInformation.FileInformationClass=FileDispositionInformationEx;iopb.Parameters.SetFileInformation.InfoBuffer=&flags;iopb.Parameters.SetFileInformation.Length=sizeof(flags);assert(StageNativeDirectoryInformation(&data,&objects,&token,&handled)==0&&handled&&!token.DirectoryMutation);
 reset();flags=FILE_DISPOSITION_DELETE|FILE_DISPOSITION_ON_CLOSE;token=slot();assert(StageNativeDirectoryInformation(&data,&objects,&token,&handled)==1&&handled&&data.IoStatus.Status==STATUS_NOT_SUPPORTED&&!token.DirectoryMutation);
 reset();Kind=SafeUploadVolumeRemovable;Fs=2;Source.Name=u(L"\\Device\\R\\outside");token=slot();assert(StageNativeDirectoryInformation(&data,&objects,&token,&handled)==0&&!handled&&!token.DirectoryMutation);
 reset();iopb.Parameters.SetFileInformation.FileInformationClass=FileBasicInformation;token=slot();assert(StageNativeDirectoryInformation(&data,&objects,&token,&handled)==0&&handled&&!token.DirectoryMutation);
 assert(NamespaceDepth==0&&ProbeRefs==0);puts("directory production shim: F1-F3, subtree boundaries, allocation/rename pending, stale capture, native failure and draining controls PASS");
}
int main(void) { tests();return 0; }
