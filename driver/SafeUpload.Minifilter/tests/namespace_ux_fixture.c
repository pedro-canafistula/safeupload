/* Extra injectable OS edges for the whole production native pre/post path.
 * Combined with directory_ux_fixture.c by test_namespace_ux.py. */
/* GLOBALS */
static void (*LookupHook)(void);
/* STUBS */
typedef unsigned char UCHAR;
typedef int FLT_POST_OPERATION_FLAGS;
#define _Flt_CompletionContext_Outptr_
#define _Use_decl_annotations_
#define _Outptr_result_maybenull_
#define FLT_IS_IRP_OPERATION(d) ((void)(d),TRUE)
#define FLT_PREOP_SUCCESS_WITH_CALLBACK 2
#define FLT_PREOP_SYNCHRONIZE 3
#define FLTFL_POST_OPERATION_DRAINING 1
#define FILE_RENAME_REPLACE_IF_EXISTS 1
#define FileMaximumInformation 100
#define SL_OPEN_TARGET_DIRECTORY 4
#define BooleanFlagOn(a,b) (!!FlagOn(a,b))
static PFLT_FILE_NAME_INFORMATION StageMvpNamespaceCreateName;
static FILE_ID_INFORMATION StageMvpNamespaceCreateIdentity;
static PVOID StageMvpNamespaceRegistryContext, StageMvpNamespaceCreateContext;
static BOOLEAN StageMvpNamespaceCreateCallback;
static unsigned char StageMvpNamespaceCompletionTag;
static int CancelCalls, PreflightCalls, CancelStatus, PrivateOpen, LegacyPostCalls, LegacyDenied;
static int MutatingOwners, RenameOwnsMutation, RenameCompleteCalls, CompletedSuccess, CompletedDraining;
static int SubjectStatus, DestinationAccessStatus, SubjectChecks, DestinationChecks, CancelOpenCalls;
static PVOID SecurityEvidence=(PVOID)(uintptr_t)73;
static BOOLEAN SafeUploadStageProtocolNativeForwardAllowed(int a,int b){(void)a;(void)b;return FALSE;}
static PVOID FltGetRequestorProcess(PFLT_CALLBACK_DATA d){(void)d;return (PVOID)(uintptr_t)100;}
static PVOID StageFindView(PVOID owner,PUNICODE_STRING name){(void)owner;(void)name;return NULL;}
static BOOLEAN StageHiddenName(PVOID owner,PUNICODE_STRING name){(void)owner;(void)name;return FALSE;}
static BOOLEAN SafeUploadStageProtectedName(PFLT_FILE_NAME_INFORMATION n,int kind)
{ return SafeUploadPolicyMatchesCurrentOrPendingDestination(kind,&n->Name,FALSE); }
static BOOLEAN SafeUploadPolicySameProtectedScope(PUNICODE_STRING a,PUNICODE_STRING b)
{ return SafeUploadPolicyMatchesCurrentOrPendingDestination(1,a,FALSE)&&SafeUploadPolicyMatchesCurrentOrPendingDestination(1,b,FALSE); }
static BOOLEAN SafeUploadPolicyMatchesExtension(PUNICODE_STRING n)
{ UNICODE_STRING ext=u(L".txt"),suffix=*n;if(n->Length<ext.Length)return FALSE;suffix.Buffer+=n->Length/2-ext.Length/2;suffix.Length=ext.Length;return RtlEqualUnicodeString(&suffix,&ext,TRUE); }
static FLT_PREOP_CALLBACK_STATUS SafeUploadPreCreate(PFLT_CALLBACK_DATA d,PCFLT_RELATED_OBJECTS o,PVOID *ctx)
{ (void)d;(void)o;*ctx=(PVOID)(uintptr_t)32;return FLT_PREOP_SUCCESS_WITH_CALLBACK; }
static int SafeUploadPostCreate(PFLT_CALLBACK_DATA d,PCFLT_RELATED_OBJECTS o,PVOID ctx,FLT_POST_OPERATION_FLAGS flags)
{ (void)o;assert(ctx==(PVOID)(uintptr_t)32);LegacyPostCalls++;if(LegacyDenied&&!flags)d->IoStatus.Status=STATUS_ACCESS_DENIED;return 0; }
static VOID FltCancelFileOpen(PFLT_INSTANCE i,PFILE_OBJECT o){(void)i;(void)o;assert(!NamespaceDepth);CancelOpenCalls++;}
static NTSTATUS StageMvpCancelNames(PFLT_INSTANCE i,PUNICODE_STRING s,PUNICODE_STRING t,BOOLEAN cancel)
{ (void)i;(void)s;(void)t;assert(StageDirectoryMutationActive&&!NamespaceDepth&&Irql==0);
 if(!cancel){PreflightCalls++;return PrivateOpen?STATUS_SHARING_VIOLATION:0;}CancelCalls++;return CancelStatus; }
static BOOLEAN SafeUploadStageWritersBeginMutatingIo(PFLT_CALLBACK_DATA d,PFLT_INSTANCE i,PFILE_OBJECT f,PVOID *ctx,PBOOLEAN tracked)
{ (void)d;(void)i;(void)f;assert(!NamespaceDepth);MutatingOwners++;*ctx=(PVOID)(uintptr_t)24;*tracked=FALSE;return TRUE; }
static VOID SafeUploadStageWritersAttachMutatingIo(PVOID rename,PVOID *io)
{ if(rename&&*io){assert(!RenameOwnsMutation);RenameOwnsMutation=1;*io=NULL;} }
static VOID SafeUploadStageWritersEndMutatingIo(PVOID ctx)
{ if(ctx){assert(ctx==(PVOID)(uintptr_t)24&&MutatingOwners==1);MutatingOwners--;} }
static BOOLEAN SafeUploadStageWritersIsRenameContext(PVOID ctx){return ctx==(PVOID)(uintptr_t)16;}
static VOID SafeUploadStageWritersCompleteRename(PFLT_INSTANCE i,PVOID ctx,BOOLEAN success,BOOLEAN draining)
{ (void)i;if(!ctx)return;assert(SafeUploadStageWritersIsRenameContext(ctx));
 if(RenameOwnsMutation){SafeUploadStageWritersEndMutatingIo((PVOID)(uintptr_t)24);RenameOwnsMutation=0;}
 RenameCompleteCalls++;CompletedSuccess=success;CompletedDraining=draining; }
static VOID SafeUploadStageWritersSetMutatingIoCompletion(PVOID ctx,PFLT_CALLBACK_DATA d,int flags)
{ (void)ctx;(void)d;(void)flags;assert(StageDirectoryMutationActive); }
static NTSTATUS SafeUploadStageCheckSubjectAccess(PFLT_CALLBACK_DATA d,PVOID descriptor,ACCESS_MASK access)
{ (void)d;assert(!NamespaceDepth&&descriptor==SecurityEvidence&&access==DELETE);SubjectChecks++;return SubjectStatus; }
static NTSTATUS SafeUploadStageCheckRenameAccess(PFLT_CALLBACK_DATA d,PFLT_INSTANCE i,PUNICODE_STRING n,BOOLEAN replace)
{ (void)d;(void)i;(void)n;(void)replace;assert(!NamespaceDepth);DestinationChecks++;return DestinationAccessStatus; }
/* TESTS */
static VOID namespace_reset(void)
{
 reset();NativeDirectory=0;CancelCalls=PreflightCalls=CancelStatus=PrivateOpen=LegacyPostCalls=LegacyDenied=0;
 MutatingOwners=RenameOwnsMutation=RenameCompleteCalls=CompletedSuccess=CompletedDraining=0;
 SubjectChecks=DestinationChecks=SubjectStatus=DestinationAccessStatus=CancelOpenCalls=0;LookupHook=NULL;
 assert(!StageMvpNamespaceCreateName&&!StageMvpNamespaceRegistryContext&&!StageMvpNamespaceCreateContext);
 Source.Name=u(L"\\Device\\V\\Protected\\file.txt");Destination.Name=u(L"\\Device\\V\\Protected\\new.txt");
}
static VOID moved_out_and_back(void)
{
 LookupHook=NULL;STAGE_ADMISSION_TOKEN_SLOT b=slot();assert(StageNamespaceBeginMutation(&b)==0);
 StageDirectoryEndMutation(FALSE);/* outside writer changes bytes */
 b=slot();assert(StageNamespaceBeginMutation(&b)==0);StageDirectoryEndMutation(FALSE);
}
static VOID directory_interleaving(void)
{
 LookupHook=NULL;UNICODE_STRING folder=u(L"\\Device\\V\\Protected\\folder");
 STAGE_ADMISSION_TOKEN_SLOT b=slot();assert(StageDirectoryBeginMutation(&folder,NULL,&b)==0);StageDirectoryEndMutation(FALSE);
}
static VOID namespace_tests(void)
{
 (void)&InterlockedCompareExchange64;
 IOPB io={.MajorFunction=IRP_MJ_CREATE};CALLBACK_DATA data={.Iopb=&io};
 FILE_OBJECT file={.FileName=u(L"\\Protected\\file.txt"),.DeleteAccess=TRUE};
 RELATED_OBJECTS objects={.Instance=(PVOID)1,.FileObject=&file};io.TargetFileObject=&file;
 IO_SECURITY_CONTEXT security={.DesiredAccess=DELETE|FILE_READ_ATTRIBUTES};io.Parameters.Create.SecurityContext=&security;
 io.Parameters.Create.Options=(FILE_OPEN<<24)|FILE_DELETE_ON_CLOSE;PVOID ctx=NULL;BOOLEAN handled;
 /* An NTFS denial, or a legacy post denial, cannot cancel another save. */
 for(int denial=0;denial<2;denial++){
  namespace_reset();STAGE_ADMISSION_TOKEN_SLOT token=slot();ctx=NULL;
  assert(StageMvpNamespacePre(&data,&objects,&ctx,&handled,&token)==FLT_PREOP_SUCCESS_WITH_CALLBACK&&handled);
  assert(CancelCalls==0&&PreflightCalls==1&&StageDirectoryMutationActive);
  data.IoStatus.Status=denial?STATUS_SUCCESS:STATUS_ACCESS_DENIED;LegacyDenied=denial;
  StageMvpNamespacePost(&data,&objects,0);assert(CancelCalls==0&&LegacyPostCalls==1);
  StageDirectoryEndMutation(FALSE);
 }
 namespace_reset();STAGE_ADMISSION_TOKEN_SLOT token=slot();ctx=NULL;
 assert(StageMvpNamespacePre(&data,&objects,&ctx,&handled,&token)==FLT_PREOP_SUCCESS_WITH_CALLBACK);
 data.IoStatus.Status=0;StageMvpNamespacePost(&data,&objects,0);
 assert(CancelCalls==1&&StageDirectoryMutationActive&&!CancelOpenCalls);StageDirectoryEndMutation(FALSE);
 /* Preflight refuses open private handles without altering a save. */
 namespace_reset();PrivateOpen=1;token=slot();ctx=NULL;
 assert(StageMvpNamespacePre(&data,&objects,&ctx,&handled,&token)==FLT_PREOP_COMPLETE&&data.IoStatus.Status==STATUS_SHARING_VIOLATION);
 assert(!CancelCalls&&!StageMvpNamespaceCreateName);StageDirectoryEndMutation(FALSE);
 /* Exact object substitution after lower CREATE never supplies authority. */
 namespace_reset();token=slot();ctx=NULL;
 assert(StageMvpNamespacePre(&data,&objects,&ctx,&handled,&token)==FLT_PREOP_SUCCESS_WITH_CALLBACK);
 SourceId=9;data.IoStatus.Status=0;StageMvpNamespacePost(&data,&objects,0);
 assert(!CancelCalls&&CancelOpenCalls==1&&data.IoStatus.Status==STATUS_SHARING_VIOLATION);StageDirectoryEndMutation(FALSE);
 /* Whole native rename path: stale file and folder generations refuse before
  * cancellation or lower forwarding, even when the final name/ID match. */
 FILE_RENAME_INFORMATION rename={0};rename.Flags=FILE_RENAME_REPLACE_IF_EXISTS|0x100;
 io.MajorFunction=IRP_MJ_SET_INFORMATION;io.Parameters.SetFileInformation.FileInformationClass=FileRenameInformationEx;
 io.Parameters.SetFileInformation.InfoBuffer=&rename;io.Parameters.SetFileInformation.Length=sizeof(rename);
 rename.FileNameLength=2;rename.FileName[0]=L'x';
 for(int domain=0;domain<2;domain++){
  namespace_reset();token=slot();ctx=NULL;LookupHook=domain?directory_interleaving:moved_out_and_back;
  assert(StageMvpNamespacePre(&data,&objects,&ctx,&handled,&token)==FLT_PREOP_COMPLETE&&handled);
  assert(data.IoStatus.Status==STATUS_SHARING_VIOLATION&&!CancelCalls&&!MutatingOwners&&!ctx);
 }
 for(int completion=0;completion<3;completion++){
  namespace_reset();token=slot();ctx=NULL;assert(StageMvpNamespacePre(&data,&objects,&ctx,&handled,&token)==FLT_PREOP_SYNCHRONIZE);
  assert(ctx==&StageMvpNamespaceCompletionTag&&MutatingOwners==1&&RenameOwnsMutation&&PrepareCalls==1&&CancelCalls==1);
  assert(rename.Flags==(FILE_RENAME_REPLACE_IF_EXISTS|0x100));/* flags unchanged */
  STAGE_ADMISSION_TOKEN_SLOT folder=slot();assert(StageDirectoryBeginMutation(&Source.Name,NULL,&folder)==STATUS_SHARING_VIOLATION);
  data.IoStatus.Status=completion==1?STATUS_ACCESS_DENIED:STATUS_SUCCESS;
  StageMvpNamespacePost(&data,&objects,completion==2?FLTFL_POST_OPERATION_DRAINING:0);
  assert(RenameCompleteCalls==1&&!MutatingOwners&&!RenameOwnsMutation&&CompletedSuccess==(completion==0)&&CompletedDraining==(completion==2));
  assert(StageDirectoryMutationActive);StageDirectoryEndMutation(completion==2);
  assert(StageDirectoryMutationActive==(completion==2));
 }
 /* Immutable target descriptor survives detachment; denied subject or parent
  * checks fail before cancellation, never falling back to SYSTEM authority. */
 namespace_reset();STAGE_STREAM stream={.OriginalInstance=objects.Instance};STAGE_VIEW target={.Security=SecurityEvidence};
 SubjectStatus=STATUS_ACCESS_DENIED;assert(StageRenameAuthorizeReplacement(&data,&stream,&target,&Destination.Name,TRUE)==STATUS_ACCESS_DENIED);
 assert(SubjectChecks==1&&DestinationChecks==0&&!CancelCalls);
 SubjectStatus=0;DestinationAccessStatus=STATUS_ACCESS_DENIED;
 assert(StageRenameAuthorizeReplacement(&data,&stream,&target,&Destination.Name,TRUE)==STATUS_ACCESS_DENIED);
 assert(SubjectChecks==2&&DestinationChecks==1&&!CancelCalls);
 DestinationAccessStatus=0;assert(StageRenameAuthorizeReplacement(&data,&stream,&target,&Destination.Name,TRUE)==0);
 assert(SubjectChecks==3&&DestinationChecks==2&&!CancelCalls);
 puts("native namespace production pre/post: denied CREATE/replacement, bindings, both generation races, registry ownership PASS");
}
