/* Real registry completion + admission gate; OS lifetime edges are injected. */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#define assert(c) do{if(!(c)){fprintf(stderr,"line %d: %s\n",__LINE__,#c);exit(97);}}while(0)
typedef void VOID,*PVOID,*PFLT_INSTANCE;
typedef uint8_t BOOLEAN;
typedef uint16_t USHORT;
typedef uint32_t ULONG;
typedef int32_t LONG;
typedef wchar_t WCHAR;
typedef struct { USHORT Length,MaximumLength;WCHAR *Buffer; } UNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;
typedef struct LIST {struct LIST *Flink,*Blink;} LIST_ENTRY,*PLIST_ENTRY;
typedef struct ENTRY {
 LIST_ENTRY Link;PFLT_INSTANCE Instance;LONG State,ActivationEnforced,AliasProbePending,ScopeNameClassification;
 BOOLEAN Retired,Listed,Compact,CompactStream,StreamIdentityKnown;
 USHORT NameChars,StreamChars;WCHAR Name[128],StreamName[128];uint64_t StreamSuffixHash;
 LONG RenameInFlight,RenameVersion,UnknownReasons,References;
} STAGE_REGISTRY_ENTRY,*PSTAGE_REGISTRY_ENTRY;
typedef struct {
 PVOID MutatingIoContext;BOOLEAN DirectoryRename,LinkOperation,Ambiguous,StreamSuffixRetained,CompactStreamIdentity;
 LONG Abandoned;ULONG NameChars,NewStreamChars;WCHAR Name[128],StreamName[128];uint64_t CompactStreamSuffixHash;
 ULONG Signature;PSTAGE_REGISTRY_ENTRY Entry;
} STAGE_REGISTRY_RENAME_CONTEXT,*PSTAGE_REGISTRY_RENAME_CONTEXT;
#define _In_
#define _In_opt_
#define TRUE 1
#define FALSE 0
#define APC_LEVEL 1
#define SAFEUPLOAD_REGISTRY_STATE_ACTIVATING 1
#define SAFEUPLOAD_REGISTRY_STATE_UNKNOWN 2
#define SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME 4
#define STAGE_SCOPE_CLASS_UNRESOLVED 0
#define STAGE_SCOPE_CLASS_OUTSIDE 2
#define SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS 128
#define SAFEUPLOAD_WRITER_REGISTRY_NAME_BUDGET 65536
#define SAFEUPLOAD_REGISTRY_POOL_TAG 42
#define RtlZeroMemory(p,n) memset((p),0,(n))
#define RtlCopyMemory(p,s,n) memcpy((p),(s),(n))
#define CONTAINING_RECORD(p,t,f) ((t*)((char*)(p)-offsetof(t,f)))
static int RegistryLock,lockDepth,irql,freed,ioOwners,rechecks;
static LIST_ENTRY RegistryEntries;
static ULONG RegistryNameBytes,RegistryReservedNameBytes;
static int64_t RegistryRenameFailures;
static UNICODE_STRING name(const WCHAR *s){size_t n=0;while(s[n])n++;return (UNICODE_STRING){n*2,n*2,(WCHAR*)s};}
static BOOLEAN RtlEqualUnicodeString(PCUNICODE_STRING a,PCUNICODE_STRING b,BOOLEAN ignore){(void)ignore;return a->Length==b->Length&&!memcmp(a->Buffer,b->Buffer,a->Length);}
static UNICODE_STRING StageRegistryBaseName(PCUNICODE_STRING n){return *n;}
static int KeGetCurrentIrql(void){return irql;}
static LONG InterlockedCompareExchange(volatile LONG *p,LONG value,LONG compare){LONG old=*p;if(old==compare)*p=value;return old;}
static LONG InterlockedExchange(volatile LONG *p,LONG value){LONG old=*p;*p=value;return old;}
static LONG InterlockedIncrement(volatile LONG *p){return ++*p;}
static LONG InterlockedDecrement(volatile LONG *p){return --*p;}
static int64_t InterlockedIncrement64(int64_t *p){return ++*p;}
static VOID FltAcquirePushLockExclusive(int *p){assert(p==&RegistryLock&&!lockDepth&&irql<=1);lockDepth++;}
static VOID FltAcquirePushLockShared(int *p){FltAcquirePushLockExclusive(p);}
static VOID FltReleasePushLock(int *p){assert(p==&RegistryLock&&lockDepth==1);lockDepth--;}
static BOOLEAN SafeUploadStageWritersIsRenameContext(PVOID p){return p&&((PSTAGE_REGISTRY_RENAME_CONTEXT)p)->Signature==42;}
static VOID SafeUploadStageWritersEndMutatingIo(PVOID p){assert(p&&!lockDepth&&ioOwners==1);ioOwners--;}
static BOOLEAN StageRegistryQueueDeferredRename(PFLT_INSTANCE i,PSTAGE_REGISTRY_RENAME_CONTEXT c,BOOLEAN s,BOOLEAN d){(void)i;(void)c;(void)s;(void)d;return FALSE;}
static VOID StageRegistryPublishGlobalUnknown(ULONG reason){assert(reason==4);}
static VOID StageRegistryMarkUnknown(PFLT_INSTANCE i,ULONG reason,BOOLEAN unused){(void)i;(void)unused;assert(reason==4);}
static VOID StageRegistryMarkEntryUnknown(PSTAGE_REGISTRY_ENTRY e,ULONG reason){e->State=2;e->UnknownReasons|=reason;}
static VOID StageRegistrySetEntryUnknownLocked(PSTAGE_REGISTRY_ENTRY e,ULONG reason){assert(lockDepth==1);StageRegistryMarkEntryUnknown(e,reason);}
static VOID StageRegistryCompleteDirectoryRename(PFLT_INSTANCE i,PSTAGE_REGISTRY_RENAME_CONTEXT c,BOOLEAN s,BOOLEAN d){(void)i;(void)c;(void)s;(void)d;assert(FALSE);}
static BOOLEAN StageRegistryEntryWaiting(PSTAGE_REGISTRY_ENTRY e){return e->State==1;}
static BOOLEAN StageRegistryTakeWriterReleaseWake(PSTAGE_REGISTRY_ENTRY e){(void)e;return FALSE;}
static VOID SafeUploadStageWritersQueueRecheck(void){assert(!lockDepth);rechecks++;}
static VOID StageRegistryDereference(PSTAGE_REGISTRY_ENTRY e){assert(e->References==1);e->References--;}
static VOID ExFreePoolWithTag(PVOID p,ULONG tag){assert(tag==42&&!lockDepth);freed++;free(p);}
static BOOLEAN StageRegistryBeginAliasProbe(PSTAGE_REGISTRY_ENTRY e){e->AliasProbePending=1;return TRUE;}
static uint64_t StageRegistryStreamSuffixHash(PCUNICODE_STRING n){(void)n;return 1;}
static ULONG StageRegistryNameStorageBytes(USHORT a,USHORT b){return (ULONG)(a+b)*2;}
static ULONG StageRegistryEntryNameStorageBytes(PSTAGE_REGISTRY_ENTRY e){return StageRegistryNameStorageBytes(e->NameChars,e->StreamChars);}
/* PRODUCTION */
static STAGE_REGISTRY_RENAME_CONTEXT *context(STAGE_REGISTRY_ENTRY *e,PCUNICODE_STRING next)
{
 STAGE_REGISTRY_RENAME_CONTEXT *c=calloc(1,sizeof(*c));assert(c);c->Entry=e;c->Signature=42;c->NameChars=next->Length/2;memcpy(c->Name,next->Buffer,next->Length);
 c->MutatingIoContext=(PVOID)1;ioOwners=1;e->RenameInFlight=1;e->RenameVersion=11;e->References=1;return c;
}
int main(void)
{
 UNICODE_STRING old=name(L"\\Device\\V\\Protected\\old.txt"),next=name(L"\\Device\\V\\Protected\\new.txt");
 for(int state=1;state<=2;state++)for(int completion=0;completion<4;completion++){
  STAGE_REGISTRY_ENTRY e={.State=state,.ActivationEnforced=1,.Listed=TRUE,.Instance=(PVOID)1,.NameChars=old.Length/2};
  memcpy(e.Name,old.Buffer,old.Length);e.UnknownReasons=state==2?128:0;
  RegistryEntries.Flink=RegistryEntries.Blink=&e.Link;e.Link.Flink=e.Link.Blink=&RegistryEntries;
  RegistryNameBytes=old.Length;RegistryReservedNameBytes=0;
  assert(SafeUploadStageWritersNameActivating((PVOID)1,&old));assert(!SafeUploadStageWritersNameActivating((PVOID)1,&next));
  STAGE_REGISTRY_RENAME_CONTEXT *c=context(&e,&next);irql=completion==3?2:0;
  SafeUploadStageWritersCompleteRename((PVOID)1,c,completion!=1,completion==2||completion==3);irql=0;
  assert(!ioOwners&&e.RenameInFlight==0&&e.RenameVersion==12&&!e.References&&!lockDepth);
  if(completion==0){
   assert(!SafeUploadStageWritersNameActivating((PVOID)1,&old));assert(SafeUploadStageWritersNameActivating((PVOID)1,&next));
   assert(e.State==state&&e.UnknownReasons==(state==2?128:0));
  }else{
   assert(SafeUploadStageWritersNameActivating((PVOID)1,&old));
   if(completion>=2)assert(e.State==2&&(e.UnknownReasons&4));
  }
 }
 assert(freed==8);puts("registry production rename completion + new-name Activating/Sticky Unknown gate PASS");return 0;
}
