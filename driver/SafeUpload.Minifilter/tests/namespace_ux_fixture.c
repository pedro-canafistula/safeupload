/* Extra injectable OS edges for the whole production native pre/post path.
 * Combined with directory_ux_fixture.c by test_namespace_ux.py. */
/* GLOBALS */
static void (*LookupHook)(void);
/* STUBS */
typedef unsigned char UCHAR;
typedef int KIRQL;
#define __declspec(x)
static int StageListLock,SpinDepth;
static VOID StageStreamAcquireSpinLock(int *lock,KIRQL *old){assert(lock==&StageListLock&&!SpinDepth);*old=Irql;Irql=2;SpinDepth=1;}
static VOID StageStreamReleaseSpinLock(int *lock,KIRQL old){assert(lock==&StageListLock&&SpinDepth==1&&Irql==2);SpinDepth=0;Irql=old;}
typedef EXCHANGE *PSAFEUPLOAD_EXCHANGE;
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
#define FLT_FSTYPE_UNKNOWN 0
#define FILE_OPENED 1
#define FILE_CREATED 2
#define FILE_OVERWRITTEN 3
#define FILE_SUPERSEDED 0
#define FILE_EXISTS 4
#define STATUS_REPARSE 0x104
#define STATUS_PENDING 0x103
#define STATUS_OPLOCK_BREAK_IN_PROGRESS 0x108
#define SL_OPEN_TARGET_DIRECTORY 4
#define BooleanFlagOn(a,b) (!!FlagOn(a,b))
static PFLT_FILE_NAME_INFORMATION StageMvpNamespaceCreateName;
static FILE_ID_INFORMATION StageMvpNamespaceCreateIdentity;
static PVOID StageMvpNamespaceRegistryContext, StageMvpNamespaceCreateContext;
static BOOLEAN StageMvpNamespaceCreateCallback;
static unsigned char StageMvpNamespaceCompletionTag;
static int CancelCalls, PreflightCalls, CancelStatus, PrivateOpen, LegacyPostCalls, LegacyDenied, LegacyPreCalls;
static int MutatingOwners, RenameOwnsMutation, RenameCompleteCalls, CompletedSuccess, CompletedDraining;
static int SubjectStatus, DestinationAccessStatus, SubjectChecks, DestinationChecks, CancelOpenCalls;
static int PendingCancellation, NativeReplaceChecks;
static PVOID SecurityEvidence=(PVOID)(uintptr_t)73;
static BOOLEAN SafeUploadStageProtocolNativeForwardAllowed(int a,int b){(void)a;(void)b;return FALSE;}
static PVOID FltGetRequestorProcess(PFLT_CALLBACK_DATA d){(void)d;return (PVOID)(uintptr_t)100;}
static int PrivateView;
static PVOID StageFindView(PVOID owner,PUNICODE_STRING name){(void)owner;(void)name;return PrivateView?(PVOID)(uintptr_t)200:NULL;}
static BOOLEAN StageHiddenName(PVOID owner,PUNICODE_STRING name){(void)owner;(void)name;return FALSE;}
static BOOLEAN SafeUploadStageProtectedName(PFLT_FILE_NAME_INFORMATION n,int kind)
{ return SafeUploadPolicyMatchesCurrentOrPendingDestination(kind,&n->Name,FALSE); }
static BOOLEAN SafeUploadPolicySameProtectedScope(PUNICODE_STRING a,PUNICODE_STRING b)
{ return SafeUploadPolicyMatchesCurrentOrPendingDestination(1,a,FALSE)&&SafeUploadPolicyMatchesCurrentOrPendingDestination(1,b,FALSE); }
static BOOLEAN SafeUploadPolicyMatchesExtension(PUNICODE_STRING n)
{ UNICODE_STRING ext=u(L".txt"),suffix=*n;if(n->Length<ext.Length)return FALSE;suffix.Buffer+=n->Length/2-ext.Length/2;suffix.Length=ext.Length;return RtlEqualUnicodeString(&suffix,&ext,TRUE); }
static int LegacyPreComplete;
static FLT_PREOP_CALLBACK_STATUS SafeUploadPreCreate(PFLT_CALLBACK_DATA d,PCFLT_RELATED_OBJECTS o,PVOID *ctx)
{ (void)o;LegacyPreCalls++;if(LegacyPreComplete){d->IoStatus.Status=STATUS_ACCESS_DENIED;*ctx=NULL;return FLT_PREOP_COMPLETE;}
  *ctx=(PVOID)(uintptr_t)32;return FLT_PREOP_SUCCESS_WITH_CALLBACK; }
/* D7 edges: pool, list, unload gate and mandatory teardown. */
#define STAGE_TAG 0x55537467u
#define POOL_FLAG_NON_PAGED 0x40
#define FILE_READ_DATA 0x1
#define STATUS_STOPPED_ON_SYMLINK -45
static volatile LONG StageUnloadAdmissionClosed;
static int MandatoryTeardown, AllocFail, Allocs, Frees;
static BOOLEAN SafeUploadStageMandatoryTeardownActive(void){return (BOOLEAN)MandatoryTeardown;}
static PVOID ExAllocatePool2(int flags,size_t size,ULONG tag)
{ assert(flags==POOL_FLAG_NON_PAGED&&tag==STAGE_TAG&&!NamespaceDepth);if(AllocFail)return NULL;Allocs++;return calloc(1,size); }
static VOID ExFreePoolWithTag(PVOID p,ULONG tag){assert(p&&tag==STAGE_TAG);Frees++;free(p);}
static VOID InsertTailList(PLIST_ENTRY h,PLIST_ENTRY e){assert(SpinDepth==1);e->Flink=h;e->Blink=h->Blink;h->Blink->Flink=e;h->Blink=e;}
static BOOLEAN RemoveEntryList(PLIST_ENTRY e){assert(SpinDepth==1);PLIST_ENTRY b=e->Blink,f=e->Flink;b->Flink=f;f->Blink=b;return f==b;}
static int SafeUploadPostCreate(PFLT_CALLBACK_DATA d,PCFLT_RELATED_OBJECTS o,PVOID ctx,FLT_POST_OPERATION_FLAGS flags)
{ (void)o;assert(ctx==(PVOID)(uintptr_t)32);LegacyPostCalls++;if(LegacyDenied&&!flags)d->IoStatus.Status=STATUS_ACCESS_DENIED;return 0; }
static VOID FltCancelFileOpen(PFLT_INSTANCE i,PFILE_OBJECT o){(void)i;(void)o;assert(!NamespaceDepth);CancelOpenCalls++;}
static NTSTATUS StageMvpCancelNames(PFLT_INSTANCE i,PUNICODE_STRING s,PUNICODE_STRING t,BOOLEAN cancel,PBOOLEAN required)
{ (void)i;(void)s;(void)t;assert(StageDirectoryMutationActive&&!NamespaceDepth&&Irql==0);
 if(required)*required=(BOOLEAN)PendingCancellation;
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
static NTSTATUS SafeUploadStageCheckNativeRename(PFLT_CALLBACK_DATA d,PFLT_INSTANCE i,PUNICODE_STRING s,
 PUNICODE_STRING t,const FILE_ID_INFORMATION *src,const FILE_ID_INFORMATION *parent,const FILE_ID_INFORMATION *target,BOOLEAN exists,BOOLEAN replace)
{ (void)d;(void)i;(void)s;(void)t;(void)src;(void)parent;(void)target;(void)exists;(void)replace;
 assert(!NamespaceDepth&&StageDirectoryMutationActive);NativeReplaceChecks++;return DestinationAccessStatus; }
/* TESTS */
/* Compile the actual StageAdmit demotion and the actual StageCreate fallback
 * that used to expose a public delete-on-close when no requester view exists.
 * Other-owner state stays outside that view and must survive a refused open. */
static BOOLEAN classified_writer(PFLT_CALLBACK_DATA Data,PCFLT_RELATED_OBJECTS Objects,BOOLEAN writer)
{
 ULONG disposition=Data->Iopb->Parameters.Create.Options>>24;
 (void)Objects; /* keep negative mutation executable under -Werror */
 /* PRODUCTION_DEMOTION */
 return writer;
}
static BOOLEAN readmitted_writer(PFLT_CALLBACK_DATA Data,PCFLT_RELATED_OBJECTS Objects,
 BOOLEAN requestedWriter,BOOLEAN writer)
{
 ULONG disposition=Data->Iopb->Parameters.Create.Options>>24;
 (void)Objects;
 /* PRODUCTION_READMISSION */
 return writer;
}
static NTSTATUS requester_without_view(BOOLEAN Writer,PBOOLEAN Handled)
{
 PVOID view=NULL;BOOLEAN PrivateNamespace=FALSE;NTSTATUS status=STATUS_SUCCESS;
 *Handled=TRUE;
 /* PRODUCTION_PRIVATE_FALLBACK */
 status=STATUS_ACCESS_DENIED; /* ordinary staged/refuse path selected */
Exit:
 return status;
}

static VOID namespace_reset(void)
{
 reset();NativeDirectory=0;CancelCalls=PreflightCalls=CancelStatus=PrivateOpen=LegacyPostCalls=LegacyDenied=LegacyPreCalls=0;
 MutatingOwners=RenameOwnsMutation=RenameCompleteCalls=CompletedSuccess=CompletedDraining=0;
 SubjectChecks=DestinationChecks=SubjectStatus=DestinationAccessStatus=CancelOpenCalls=0;LookupHook=NULL;
 PendingCancellation=NativeReplaceChecks=0;
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
static VOID d7_reset(void)
{
 namespace_reset();head(&StageMvpReparseOpens);StageUnloadAdmissionClosed=0;
 MandatoryTeardown=AllocFail=Allocs=Frees=LegacyPreComplete=PrivateView=0;TagAttributes=0;
}
/* No context leaked, no list residue, and the fenced singleton never touched (namespace_reset asserts it). */
static VOID d7_done(void){assert(Allocs==Frees&&StageMvpReparseOpens.Flink==&StageMvpReparseOpens&&!StageDirectoryMutationActive);}
/* Admit a D7 CREATE and return its context exactly as StagePostOperationCore would find it. */
static PSTAGE_MVP_REPARSE_OPEN d7_admit(PFLT_CALLBACK_DATA data,PCFLT_RELATED_OBJECTS objects)
{
 PVOID ctx=NULL;BOOLEAN handled=FALSE;STAGE_ADMISSION_TOKEN_SLOT token=slot();
 assert(StageMvpNamespacePre(data,objects,&ctx,&handled,&token)==FLT_PREOP_SUCCESS_WITH_CALLBACK&&handled);
 assert(ctx&&ctx!=&StageMvpNamespaceCompletionTag&&LegacyPreCalls==1&&!StageDirectoryMutationActive&&!CancelCalls&&!PreflightCalls);
 PSTAGE_MVP_REPARSE_OPEN open=StageMvpReparseOpenTake(ctx);assert(open==ctx&&!StageMvpReparseOpenTake(ctx));
 assert(!StageMvpReparseOpenTake((PVOID)(uintptr_t)32)); /* foreign contexts are never dereferenced or matched */
 return open;
}
static VOID d7_post(PFLT_CALLBACK_DATA data,PCFLT_RELATED_OBJECTS objects,PSTAGE_MVP_REPARSE_OPEN open,NTSTATUS status,uintptr_t info,int flags)
{ data->IoStatus.Status=status;data->IoStatus.Information=info;StageMvpReparseOpenPost(data,objects,open,flags); }
static VOID namespace_tests(void)
{
 (void)&InterlockedCompareExchange64;
 STAGE_STREAM installation={0};EXCHANGE pending={0};
 for(int start=0;start<=2;start++){Irql=start;StageInstallRenameExchange(&installation,&pending);assert(Irql==start&&!SpinDepth&&installation.RenameExchange==&pending);}Irql=0;
 IOPB io={.MajorFunction=IRP_MJ_CREATE};CALLBACK_DATA data={.Iopb=&io};
 FILE_OBJECT file={.FileName=u(L"\\Protected\\file.txt"),.DeleteAccess=TRUE,.FsContext=(PVOID)1};
 RELATED_OBJECTS objects={.Instance=(PVOID)1,.FileObject=&file};io.TargetFileObject=&file;
 IO_SECURITY_CONTEXT security={.DesiredAccess=DELETE|FILE_READ_ATTRIBUTES};io.Parameters.Create.SecurityContext=&security;
 io.Parameters.Create.Options=(FILE_OPEN<<24)|FILE_DELETE_ON_CLOSE;PVOID ctx=NULL;BOOLEAN handled;
 data.IoStatus.Information=FILE_OPENED;
 /* An NTFS denial, or a legacy post denial, cannot cancel another save. */
 for(int denial=0;denial<2;denial++){
  namespace_reset();STAGE_ADMISSION_TOKEN_SLOT token=slot();ctx=NULL;
  assert(StageMvpNamespacePre(&data,&objects,&ctx,&handled,&token)==FLT_PREOP_SUCCESS_WITH_CALLBACK&&handled);
  assert(CancelCalls==0&&PreflightCalls==1&&StageDirectoryMutationActive);
  data.IoStatus.Information=FILE_OPENED;data.IoStatus.Status=denial?STATUS_SUCCESS:STATUS_ACCESS_DENIED;LegacyDenied=denial;
  StageMvpNamespacePost(&data,&objects,0);assert(CancelCalls==0&&LegacyPostCalls==1);
  StageDirectoryEndMutation(FALSE);
 }
 namespace_reset();STAGE_ADMISSION_TOKEN_SLOT token=slot();ctx=NULL;
 assert(StageMvpNamespacePre(&data,&objects,&ctx,&handled,&token)==FLT_PREOP_SUCCESS_WITH_CALLBACK);
 data.IoStatus.Information=FILE_OPENED;data.IoStatus.Status=0;StageMvpNamespacePost(&data,&objects,0);
 assert(CancelCalls==1&&StageDirectoryMutationActive&&!CancelOpenCalls);StageDirectoryEndMutation(FALSE);
 /* Preflight refuses open private handles without altering a save. */
 namespace_reset();PrivateOpen=1;token=slot();ctx=NULL;
 assert(StageMvpNamespacePre(&data,&objects,&ctx,&handled,&token)==FLT_PREOP_COMPLETE&&data.IoStatus.Status==STATUS_SHARING_VIOLATION);
 assert(!CancelCalls&&!StageMvpNamespaceCreateName);StageDirectoryEndMutation(FALSE);
 /* Exact object substitution after lower CREATE never supplies authority. */
 namespace_reset();token=slot();ctx=NULL;
 assert(StageMvpNamespacePre(&data,&objects,&ctx,&handled,&token)==FLT_PREOP_SUCCESS_WITH_CALLBACK);
 SourceId=9;data.IoStatus.Information=FILE_OPENED;data.IoStatus.Status=0;StageMvpNamespacePost(&data,&objects,0);
 assert(!CancelCalls&&CancelOpenCalls==1&&data.IoStatus.Status==STATUS_SHARING_VIOLATION);StageDirectoryEndMutation(FALSE);
 /* Cross-owner sealed save: native decline must never be followed by
  * writer demotion and a legacy public delete-on-close open. The saved
  * version is represented by the cancellation/preflight boundary, independent
  * of the requester's always-absent private view in StageFindView. */
 namespace_reset();io.Parameters.Create.Options|=FILE_OPEN_REPARSE_POINT;token=slot();ctx=NULL;
 assert(StageMvpNamespacePre(&data,&objects,&ctx,&handled,&token)==FLT_PREOP_SUCCESS_NO_CALLBACK&&!handled);
 assert(StageMvpNamespaceOpen(&data)&&!StageMvpNamespaceCreateEligible(&data,&objects));
 BOOLEAN otherOwnerSealed=TRUE,privateHandled=FALSE;
 BOOLEAN writer=classified_writer(&data,&objects,TRUE);assert(writer);
 assert(requester_without_view(writer,&privateHandled)==STATUS_ACCESS_DENIED&&privateHandled);
 assert(otherOwnerSealed); /* no legacy public CREATE or cancellation ran */
 assert(!CancelCalls&&!PreflightCalls&&!LegacyPreCalls&&!StageDirectoryMutationActive);
 /* D7 (owner 2026-10-21): without DOC, a DELETE/WRITE_ATTRIBUTES-only OPEN_REPARSE_POINT open is a native-route
  * request and is demoted like any namespace-only open; content-writing or DELETE_CHILD variants keep writer intent. */
 io.Parameters.Create.Options&=~FILE_DELETE_ON_CLOSE;
 security.DesiredAccess=FILE_WRITE_ATTRIBUTES;
 assert(StageMvpNamespaceReparseOpen(&data)&&StageMvpNamespaceCreateEligible(&data,&objects));
 assert(!classified_writer(&data,&objects,TRUE));
 assert(!readmitted_writer(&data,&objects,TRUE,FALSE));
 security.DesiredAccess=FILE_WRITE_ATTRIBUTES|FILE_DELETE_CHILD;
 assert(!StageMvpNamespaceReparseOpen(&data)&&classified_writer(&data,&objects,TRUE));
 security.DesiredAccess=FILE_WRITE_ATTRIBUTES|FILE_WRITE_DATA;
 assert(!StageMvpNamespaceReparseOpen(&data)&&classified_writer(&data,&objects,TRUE));
 io.Parameters.Create.Options|=FILE_DELETE_ON_CLOSE;
 security.DesiredAccess=DELETE|FILE_READ_ATTRIBUTES;
 io.Parameters.Create.Options&=~FILE_OPEN_REPARSE_POINT;
 assert(StageMvpNamespaceCreateEligible(&data,&objects));
 /* A fault in the existing-object probe is a refusal, never an unowned
  * native DOC. Absence keeps writer intent for private create/refusal. */
 namespace_reset();IdentityStatus=STATUS_ACCESS_DENIED;token=slot();ctx=NULL;
 assert(StageMvpNamespacePre(&data,&objects,&ctx,&handled,&token)==FLT_PREOP_COMPLETE&&handled);
 assert(data.IoStatus.Status==IdentityStatus&&!CancelCalls&&!LegacyPreCalls&&!StageDirectoryMutationActive);
 namespace_reset();IdentityStatus=STATUS_OBJECT_NAME_NOT_FOUND;token=slot();ctx=NULL;
 assert(StageMvpNamespacePre(&data,&objects,&ctx,&handled,&token)==FLT_PREOP_SUCCESS_NO_CALLBACK&&!handled);
 writer=classified_writer(&data,&objects,TRUE);assert(writer);
 assert(requester_without_view(writer,&privateHandled)==STATUS_ACCESS_DENIED&&privateHandled);
 /* The private receipt wait detached the last view; its reader decision must
  * not survive readmission, including a later excluded reparse create. */
 assert(readmitted_writer(&data,&objects,TRUE,FALSE));
 io.Parameters.Create.Options|=FILE_OPEN_REPARSE_POINT;
 assert(readmitted_writer(&data,&objects,TRUE,FALSE));
 io.Parameters.Create.Options&=~FILE_OPEN_REPARSE_POINT;
 /* Every successful opened-object result is checked before exposure, including
  * the real alternate oplock success. Reparse/pending/non-open cannot cancel. */
 NTSTATUS outcomes[]={STATUS_SUCCESS,STATUS_OPLOCK_BREAK_IN_PROGRESS,0x40000000};
 for(unsigned k=0;k<sizeof(outcomes)/sizeof(outcomes[0]);k++)for(unsigned info=0;info<=3;info++)for(int substitute=0;substitute<2;substitute++){
  namespace_reset();token=slot();ctx=NULL;io.Parameters.Create.Options|=FILE_COMPLETE_IF_OPLOCKED;
  assert(StageMvpNamespacePre(&data,&objects,&ctx,&handled,&token)==FLT_PREOP_SUCCESS_WITH_CALLBACK);
  SourceId=substitute?9:1;data.IoStatus.Status=outcomes[k];data.IoStatus.Information=info;
  StageMvpNamespacePost(&data,&objects,0);
  assert(CancelCalls==!substitute&&CancelOpenCalls==substitute&&StageDirectoryMutationActive);
  if(!substitute)assert(data.IoStatus.Status==outcomes[k]);else assert(data.IoStatus.Status==STATUS_SHARING_VIOLATION);
  StageDirectoryEndMutation(FALSE);
 }
 NTSTATUS nonopens[]={STATUS_REPARSE,STATUS_PENDING,STATUS_ACCESS_DENIED};
 for(unsigned k=0;k<sizeof(nonopens)/sizeof(nonopens[0]);k++){
  namespace_reset();token=slot();ctx=NULL;
  assert(StageMvpNamespacePre(&data,&objects,&ctx,&handled,&token)==FLT_PREOP_SUCCESS_WITH_CALLBACK);
  data.IoStatus.Status=nonopens[k];data.IoStatus.Information=FILE_OPENED;StageMvpNamespacePost(&data,&objects,0);
  assert(!CancelCalls&&!CancelOpenCalls);StageDirectoryEndMutation(FALSE);
 }
 namespace_reset();data.IoStatus.Status=STATUS_SUCCESS;data.IoStatus.Information=FILE_EXISTS;
 assert(!StageMvpNamespaceCreateOpened(&data,&objects));data.IoStatus.Information=FILE_OPENED;file.FsContext=NULL;
 assert(!StageMvpNamespaceCreateOpened(&data,&objects));file.FsContext=(PVOID)1;
 /* Normal fenced SET_INFORMATION completion is always synchronized, even if
  * inner routing forgot to request a callback. CREATE must never synchronize. */
 for(int r=0;r<=3;r++)if(r!=FLT_PREOP_COMPLETE){
  assert(StageNamespacePostStatus(IRP_MJ_SET_INFORMATION,TRUE,r)==FLT_PREOP_SYNCHRONIZE);
  assert(StageNamespacePostStatus(IRP_MJ_CREATE,TRUE,FLT_PREOP_SUCCESS_WITH_CALLBACK)==FLT_PREOP_SUCCESS_WITH_CALLBACK);
 }
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
  assert(!NativeReplaceChecks); /* no unpublished cancellation obligation */
  assert(ctx==&StageMvpNamespaceCompletionTag&&MutatingOwners==1&&RenameOwnsMutation&&PrepareCalls==1&&CancelCalls==1);
  assert(rename.Flags==(FILE_RENAME_REPLACE_IF_EXISTS|0x100));/* flags unchanged */
  STAGE_ADMISSION_TOKEN_SLOT folder=slot();assert(StageDirectoryBeginMutation(&Source.Name,NULL,&folder)==STATUS_SHARING_VIOLATION);
  data.IoStatus.Status=completion==1?STATUS_ACCESS_DENIED:STATUS_SUCCESS;
  StageMvpNamespacePost(&data,&objects,completion==2?FLTFL_POST_OPERATION_DRAINING:0);
  assert(RenameCompleteCalls==1&&!MutatingOwners&&!RenameOwnsMutation&&CompletedSuccess==(completion==0)&&CompletedDraining==(completion==2));
  assert(StageDirectoryMutationActive);StageDirectoryEndMutation(completion==2);
  assert(StageDirectoryMutationActive==(completion==2));
 }
 /* Supplemental authority is necessary only before cancelling private work.
  * A denial leaves every pending version intact; lower flags are unchanged. */
 namespace_reset();PendingCancellation=1;DestinationAccessStatus=STATUS_ACCESS_DENIED;token=slot();ctx=NULL;
 assert(StageMvpNamespacePre(&data,&objects,&ctx,&handled,&token)==FLT_PREOP_COMPLETE&&handled);
 assert(NativeReplaceChecks==1&&!CancelCalls&&!MutatingOwners&&data.IoStatus.Status==STATUS_ACCESS_DENIED);
 StageDirectoryEndMutation(FALSE);
 namespace_reset();PendingCancellation=1;token=slot();ctx=NULL;
 assert(StageMvpNamespacePre(&data,&objects,&ctx,&handled,&token)==FLT_PREOP_SYNCHRONIZE);
 assert(NativeReplaceChecks==1&&CancelCalls==1&&rename.Flags==(FILE_RENAME_REPLACE_IF_EXISTS|0x100));
 data.IoStatus.Status=0;StageMvpNamespacePost(&data,&objects,0);StageDirectoryEndMutation(FALSE);
 namespace_reset();PendingCancellation=1;DestinationAccessStatus=STATUS_ACCESS_DENIED;rename.Flags=0;token=slot();ctx=NULL;
 assert(StageMvpNamespacePre(&data,&objects,&ctx,&handled,&token)==FLT_PREOP_COMPLETE&&handled);
 assert(NativeReplaceChecks==1&&!CancelCalls&&!MutatingOwners&&data.IoStatus.Status==STATUS_ACCESS_DENIED);
 StageDirectoryEndMutation(FALSE);rename.Flags=FILE_RENAME_REPLACE_IF_EXISTS|0x100;
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
 /* D7 (owner 2026-10-21): OPEN_REPARSE_POINT opens of regular files take the native route. */
 io.MajorFunction=IRP_MJ_CREATE;io.Parameters.Create.SecurityContext=&security;file.FsContext=(PVOID)1;
 Source.Stream=(UNICODE_STRING){0};
 ACCESS_MASK d7access[]={DELETE|FILE_READ_ATTRIBUTES|SYNCHRONIZE,FILE_WRITE_ATTRIBUTES|SYNCHRONIZE,
  DELETE|FILE_WRITE_ATTRIBUTES,DELETE|FILE_READ_DATA};
 /* 1. DELETE / WRITE_ATTRIBUTES / READ_DATA variants: native, demoted, no allocation of a version, no cancellation. */
 for(unsigned a=0;a<sizeof(d7access)/sizeof(d7access[0]);a++){
  d7_reset();io.Parameters.Create.Options=(FILE_OPEN<<24)|FILE_OPEN_REPARSE_POINT;security.DesiredAccess=d7access[a];
  assert(StageMvpNamespaceReparseOpen(&data)&&StageMvpNamespaceCreateEligible(&data,&objects)&&!classified_writer(&data,&objects,TRUE));
  PSTAGE_MVP_REPARSE_OPEN open=d7_admit(&data,&objects);
  d7_post(&data,&objects,open,STATUS_SUCCESS,FILE_OPENED,0);
  assert(data.IoStatus.Status==STATUS_SUCCESS&&!CancelOpenCalls&&!CancelCalls&&LegacyPostCalls==1);d7_done();
 }
 security.DesiredAccess=DELETE|FILE_READ_ATTRIBUTES|SYNCHRONIZE;
 /* OPEN_IF is narrowed to OPEN before the lower CREATE. */
 d7_reset();io.Parameters.Create.Options=(FILE_OPEN_IF<<24)|FILE_OPEN_REPARSE_POINT;
 {PSTAGE_MVP_REPARSE_OPEN open=d7_admit(&data,&objects);assert((io.Parameters.Create.Options>>24)==FILE_OPEN);
  d7_post(&data,&objects,open,STATUS_SUCCESS,FILE_OPENED,0);assert(data.IoStatus.Status==STATUS_SUCCESS);d7_done();}
 io.Parameters.Create.Options=(FILE_OPEN<<24)|FILE_OPEN_REPARSE_POINT;
 /* 2. A reparse point seen only in post is cancelled; a symlink the pre lookup stops on is refused in pre. */
 d7_reset();{PSTAGE_MVP_REPARSE_OPEN open=d7_admit(&data,&objects);TagAttributes=FILE_ATTRIBUTE_REPARSE_POINT;
  d7_post(&data,&objects,open,STATUS_SUCCESS,FILE_OPENED,0);
  assert(data.IoStatus.Status==STATUS_ACCESS_DENIED&&CancelOpenCalls==1&&!LegacyPostCalls&&!CancelCalls);d7_done();}
 d7_reset();IdentityStatus=STATUS_STOPPED_ON_SYMLINK;token=slot();ctx=NULL;
 assert(StageMvpNamespacePre(&data,&objects,&ctx,&handled,&token)==FLT_PREOP_COMPLETE&&handled);
 assert(data.IoStatus.Status==STATUS_ACCESS_DENIED&&!ctx&&!LegacyPreCalls&&!Allocs&&!CancelCalls);d7_done();
 /* 3. Query faults, short replies and a substituted regular object all cancel; missing object evidence is refused
  * without object calls; informational and oplock-break success with FILE_OPENED still validates and passes. */
 for(int fault=0;fault<5;fault++){
  d7_reset();PSTAGE_MVP_REPARSE_OPEN open=d7_admit(&data,&objects);
  if(fault==0)TagStatus=STATUS_ACCESS_DENIED;else if(fault==1)TagShort=1;else if(fault==2)IdQueryStatus=STATUS_ACCESS_DENIED;
  else if(fault==3)IdShort=1;else SourceId=9;
  d7_post(&data,&objects,open,STATUS_SUCCESS,FILE_OPENED,0);
  assert(data.IoStatus.Status==STATUS_ACCESS_DENIED&&CancelOpenCalls==1&&!LegacyPostCalls&&!CancelCalls);d7_done();
 }
 d7_reset();{PSTAGE_MVP_REPARSE_OPEN open=d7_admit(&data,&objects);file.FsContext=NULL;
  d7_post(&data,&objects,open,STATUS_SUCCESS,FILE_OPENED,0);file.FsContext=(PVOID)1;
  assert(data.IoStatus.Status==STATUS_ACCESS_DENIED&&!CancelOpenCalls&&!LegacyPostCalls);d7_done();}
 NTSTATUS d7success[]={0x40000000,STATUS_OPLOCK_BREAK_IN_PROGRESS};
 for(unsigned k=0;k<2;k++){d7_reset();PSTAGE_MVP_REPARSE_OPEN open=d7_admit(&data,&objects);
  d7_post(&data,&objects,open,d7success[k],FILE_OPENED,0);
  assert(data.IoStatus.Status==d7success[k]&&!CancelOpenCalls&&LegacyPostCalls==1);d7_done();}
 /* 4. A failed or reparsed lower CREATE validates nothing and keeps the legacy post; a legacy-post denial is a single refusal. */
 NTSTATUS d7nonopen[]={STATUS_ACCESS_DENIED,STATUS_OBJECT_NAME_NOT_FOUND,STATUS_REPARSE};
 for(unsigned k=0;k<3;k++){d7_reset();PSTAGE_MVP_REPARSE_OPEN open=d7_admit(&data,&objects);
  d7_post(&data,&objects,open,d7nonopen[k],FILE_OPENED,0);
  assert(data.IoStatus.Status==d7nonopen[k]&&!CancelOpenCalls&&LegacyPostCalls==1);d7_done();}
 d7_reset();{PSTAGE_MVP_REPARSE_OPEN open=d7_admit(&data,&objects);LegacyDenied=1;
  d7_post(&data,&objects,open,STATUS_SUCCESS,FILE_OPENED,0);
  assert(data.IoStatus.Status==STATUS_ACCESS_DENIED&&!CancelOpenCalls&&LegacyPostCalls==1);d7_done();}
 /* 5. Every pre refusal frees its context; a draining post only frees it. */
 for(int refusal=0;refusal<4;refusal++){
  d7_reset();if(refusal==0)StageUnloadAdmissionClosed=1;else if(refusal==1)MandatoryTeardown=1;
  else if(refusal==2)AllocFail=1;else LegacyPreComplete=1;
  token=slot();ctx=NULL;
  assert(StageMvpNamespacePre(&data,&objects,&ctx,&handled,&token)==FLT_PREOP_COMPLETE&&handled&&!ctx);
  assert(data.IoStatus.Status==(refusal<2?STATUS_DEVICE_NOT_READY:STATUS_ACCESS_DENIED));
  assert(LegacyPreCalls==(refusal==3)&&Allocs==(refusal==3)&&!CancelCalls);d7_done();
 }
 d7_reset();{PSTAGE_MVP_REPARSE_OPEN open=d7_admit(&data,&objects);TagAttributes=FILE_ATTRIBUTE_REPARSE_POINT;
  d7_post(&data,&objects,open,STATUS_SUCCESS,FILE_OPENED,FLTFL_POST_OPERATION_DRAINING);
  assert(data.IoStatus.Status==STATUS_SUCCESS&&!CancelOpenCalls&&!LegacyPostCalls);d7_done();}
 /* 6. DOC, DELETE_CHILD and content-writing reparse opens stay excluded (writer, staged or refused as before). */
 d7_reset();io.Parameters.Create.Options=(FILE_OPEN<<24)|FILE_OPEN_REPARSE_POINT|FILE_DELETE_ON_CLOSE;
 assert(!StageMvpNamespaceReparseOpen(&data)&&!StageMvpNamespaceCreateEligible(&data,&objects)&&classified_writer(&data,&objects,TRUE));
 token=slot();ctx=NULL;assert(StageMvpNamespacePre(&data,&objects,&ctx,&handled,&token)==FLT_PREOP_SUCCESS_NO_CALLBACK&&!handled);
 assert(!Allocs&&!LegacyPreCalls&&!CancelCalls);d7_done();
 io.Parameters.Create.Options=(FILE_OPEN<<24)|FILE_OPEN_REPARSE_POINT;
 security.DesiredAccess=DELETE|FILE_DELETE_CHILD;assert(!StageMvpNamespaceCreateEligible(&data,&objects)&&classified_writer(&data,&objects,TRUE));
 security.DesiredAccess=DELETE|FILE_WRITE_DATA;assert(!StageMvpNamespaceCreateEligible(&data,&objects)&&classified_writer(&data,&objects,TRUE));
 security.DesiredAccess=DELETE|FILE_READ_ATTRIBUTES|SYNCHRONIZE;
 /* Declines after eligibility refuse: unresolved name, stream name, non-absent lookup failure. Unprotected names
  * and genuine private views keep their existing routes. A proved-absent name opens natively with a zero identity. */
 d7_reset();NameStatus=STATUS_ACCESS_DENIED;token=slot();ctx=NULL;
 assert(StageMvpNamespacePre(&data,&objects,&ctx,&handled,&token)==FLT_PREOP_COMPLETE&&handled&&data.IoStatus.Status==STATUS_ACCESS_DENIED);
 assert(!LegacyPreCalls&&!Allocs);NameStatus=0;d7_done();
 d7_reset();Source.Stream=u(L":s");token=slot();ctx=NULL;
 assert(StageMvpNamespacePre(&data,&objects,&ctx,&handled,&token)==FLT_PREOP_COMPLETE&&handled&&data.IoStatus.Status==STATUS_ACCESS_DENIED);
 Source.Stream=(UNICODE_STRING){0};assert(!LegacyPreCalls&&!Allocs);d7_done();
 d7_reset();Source.Name=u(L"\\Device\\V\\Elsewhere\\file.txt");token=slot();ctx=NULL;
 assert(StageMvpNamespacePre(&data,&objects,&ctx,&handled,&token)==FLT_PREOP_SUCCESS_NO_CALLBACK&&!handled&&!Allocs);d7_done();
 d7_reset();PrivateView=1;token=slot();ctx=NULL; /* 8. private route, unchanged */
 assert(StageMvpNamespacePre(&data,&objects,&ctx,&handled,&token)==FLT_PREOP_SUCCESS_NO_CALLBACK&&!handled&&!Allocs&&!LegacyPreCalls);d7_done();
 for(int raced=0;raced<2;raced++){
  d7_reset();IdentityStatus=STATUS_OBJECT_NAME_NOT_FOUND;PSTAGE_MVP_REPARSE_OPEN open=d7_admit(&data,&objects);
  assert(open->Identity.FileId==0&&open->Identity.VolumeSerialNumber==0);
  d7_post(&data,&objects,open,raced?STATUS_SUCCESS:STATUS_OBJECT_NAME_NOT_FOUND,FILE_OPENED,0);
  assert(CancelOpenCalls==raced&&data.IoStatus.Status==(raced?STATUS_ACCESS_DENIED:STATUS_OBJECT_NAME_NOT_FOUND));d7_done();
 }
 /* 9. Unexpected successful outcomes for this OPEN-only route and STATUS_PENDING are refused, never passed on. */
 uintptr_t d7infos[]={FILE_CREATED,FILE_OVERWRITTEN,FILE_SUPERSEDED,FILE_EXISTS,7};
 for(unsigned k=0;k<5;k++){d7_reset();PSTAGE_MVP_REPARSE_OPEN open=d7_admit(&data,&objects);
  d7_post(&data,&objects,open,STATUS_SUCCESS,d7infos[k],0);
  assert(data.IoStatus.Status==STATUS_ACCESS_DENIED&&CancelOpenCalls==1&&!LegacyPostCalls);d7_done();}
 d7_reset();{PSTAGE_MVP_REPARSE_OPEN open=d7_admit(&data,&objects);
  d7_post(&data,&objects,open,STATUS_PENDING,FILE_OPENED,0);
  assert(data.IoStatus.Status==STATUS_ACCESS_DENIED&&!CancelOpenCalls&&!LegacyPostCalls);d7_done();}
 /* 7. A reparse attribute on an open handle refuses a native disposition before any cancellation. */
 d7_reset();FILE_DISPOSITION_INFORMATION dispose={.DeleteFile=TRUE};
 io.MajorFunction=IRP_MJ_SET_INFORMATION;io.Parameters.SetFileInformation.FileInformationClass=FileDispositionInformation;
 io.Parameters.SetFileInformation.InfoBuffer=&dispose;io.Parameters.SetFileInformation.Length=sizeof(dispose);
 file.DeleteAccess=TRUE;file.WriteAccess=FALSE;TagAttributes=FILE_ATTRIBUTE_REPARSE_POINT;token=slot();ctx=NULL;
 assert(StageMvpNamespacePre(&data,&objects,&ctx,&handled,&token)==FLT_PREOP_COMPLETE&&handled&&data.IoStatus.Status==STATUS_ACCESS_DENIED);
 assert(!CancelCalls&&!PreflightCalls&&!MutatingOwners&&!CancelOpenCalls);StageDirectoryEndMutation(FALSE);d7_done();
 d7_reset();TagAttributes=0;token=slot();ctx=NULL; /* the same disposition on a regular file still takes the fenced D2 path */
 assert(StageMvpNamespacePre(&data,&objects,&ctx,&handled,&token)==FLT_PREOP_SYNCHRONIZE&&handled&&ctx==&StageMvpNamespaceCompletionTag);
 assert(PreflightCalls==1&&CancelCalls==1);data.IoStatus.Status=0;StageMvpNamespacePost(&data,&objects,0);StageDirectoryEndMutation(FALSE);
 io.MajorFunction=IRP_MJ_CREATE;
 puts("native namespace production pre/post: denied CREATE/replacement, bindings, both generation races, registry ownership, D7 reparse-flag opens PASS");
}
