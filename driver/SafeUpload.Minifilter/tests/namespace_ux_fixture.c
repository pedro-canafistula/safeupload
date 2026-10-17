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
static PVOID StageFindView(PVOID owner,PUNICODE_STRING name){(void)owner;(void)name;return NULL;}
static BOOLEAN StageHiddenName(PVOID owner,PUNICODE_STRING name){(void)owner;(void)name;return FALSE;}
static BOOLEAN SafeUploadStageProtectedName(PFLT_FILE_NAME_INFORMATION n,int kind)
{ return SafeUploadPolicyMatchesCurrentOrPendingDestination(kind,&n->Name,FALSE); }
static BOOLEAN SafeUploadPolicySameProtectedScope(PUNICODE_STRING a,PUNICODE_STRING b)
{ return SafeUploadPolicyMatchesCurrentOrPendingDestination(1,a,FALSE)&&SafeUploadPolicyMatchesCurrentOrPendingDestination(1,b,FALSE); }
static BOOLEAN SafeUploadPolicyMatchesExtension(PUNICODE_STRING n)
{ UNICODE_STRING ext=u(L".txt"),suffix=*n;if(n->Length<ext.Length)return FALSE;suffix.Buffer+=n->Length/2-ext.Length/2;suffix.Length=ext.Length;return RtlEqualUnicodeString(&suffix,&ext,TRUE); }
static FLT_PREOP_CALLBACK_STATUS SafeUploadPreCreate(PFLT_CALLBACK_DATA d,PCFLT_RELATED_OBJECTS o,PVOID *ctx)
{ (void)d;(void)o;LegacyPreCalls++;*ctx=(PVOID)(uintptr_t)32;return FLT_PREOP_SUCCESS_WITH_CALLBACK; }
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
static NTSTATUS SafeUploadStageCheckNativeReplace(PFLT_CALLBACK_DATA d,PFLT_INSTANCE i,PUNICODE_STRING s,
 PUNICODE_STRING t,const FILE_ID_INFORMATION *src,const FILE_ID_INFORMATION *parent,const FILE_ID_INFORMATION *target,BOOLEAN exists)
{ (void)d;(void)i;(void)s;(void)t;(void)src;(void)parent;(void)target;(void)exists;
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
 /* Metadata-only opens excluded from native routing must also keep ordinary
  * admission, even when they carry no DOC bit. */
 io.Parameters.Create.Options&=~FILE_DELETE_ON_CLOSE;
 security.DesiredAccess=FILE_WRITE_ATTRIBUTES;
 assert(classified_writer(&data,&objects,TRUE));
 assert(readmitted_writer(&data,&objects,TRUE,FALSE));
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
