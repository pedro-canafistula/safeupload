/* Deterministic DDI fixture; the production bodies are inserted by the runner. */
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
typedef int32_t LONG, NTSTATUS;
typedef uint32_t ULONG, UINT32, *PULONG;
typedef uint16_t WCHAR, *PWCHAR, USHORT;
typedef uint64_t ULONGLONG;
typedef int BOOLEAN, *PBOOLEAN, KIRQL;
typedef void VOID, *PVOID, *HANDLE, *PFLT_INSTANCE, *PFLT_VOLUME, *PFLT_CONTEXT;
typedef struct { int64_t QuadPart; } LARGE_INTEGER;
typedef struct _LIST { struct _LIST *Flink, *Blink; } LIST_ENTRY, *PLIST_ENTRY;
typedef struct { USHORT Length, MaximumLength; WCHAR *Buffer; } UNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;
typedef struct { PVOID DataSectionObject, SharedCacheMap; } SOP, *PSECTION_OBJECT_POINTERS;
typedef struct { PSECTION_OBJECT_POINTERS SectionObjectPointer; } FILE_OBJECT, *PFILE_OBJECT;
typedef struct { LONG Invalid, Ended; PVOID Sop; } LIFETIME, *PSTAGE_SOP_LIFETIME;
typedef struct { LONG WriterLock, WritersUntracked; PVOID WriterSopLifetime; BOOLEAN WriterSopLifetimeInvalid; } STREAM_CONTEXT, *PSAFEUPLOAD_STREAM_CONTEXT;
typedef struct { LONG WritersUntracked, RegistryUnknownReasons; ULONGLONG RegistryRenameLossGeneration; } INSTANCE_CONTEXT, *PSAFEUPLOAD_INSTANCE_CONTEXT;
typedef struct { int unused; } STAGE_SCOPE_CLASSIFICATION_RECEIPT;
typedef struct { HANDLE Handle; PFILE_OBJECT Object; PFLT_INSTANCE Instance; } ANCHOR, *PSTAGE_ANCHOR;
typedef struct _ENTRY {
    LIST_ENTRY Link;
    LONG StateLock, H, W, T, UnknownReasons, RenameInFlight, RenameVersion;
    LONG AliasProbePending, ActivationEnforced, ActivationGeneration, ScopeNameClassification, LastSState;
    LONG ScopeScanNextLink, TransactionVersion;
    ULONG State;
    BOOLEAN Listed, Retired, Compact, CompactStream, StreamIdentityKnown;
    USHORT NameChars, StreamChars;
    WCHAR Name[32];
    PFLT_INSTANCE Instance;
    PVOID SectionObjectPointer;
    PSTAGE_SOP_LIFETIME Lifetime;
    ULONGLONG RenameLossGeneration;
} ENTRY, STAGE_REGISTRY_ENTRY, *PSTAGE_REGISTRY_ENTRY;
#define TRUE 1
#define FALSE 0
#define PASSIVE_LEVEL 0
#define KernelMode 0
#define STATUS_SUCCESS 0
#define STATUS_UNSUCCESSFUL ((NTSTATUS)-1)
#define STATUS_PENDING 0x103
#define STATUS_RETRY ((NTSTATUS)-2)
#define STATUS_FILE_INVALID ((NTSTATUS)-3)
#define STATUS_MORE_ENTRIES 0x105
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)-4)
#define NT_SUCCESS(s) ((s) >= 0)
#define POOL_FLAG_PAGED 1
#define FLT_FLUSH_TYPE_FLUSH_AND_PURGE 1
#define SAFEUPLOAD_REGISTRY_POOL_TAG 1
#define STAGE_SCOPE_CLASS_OUTSIDE 1
#define STAGE_SCOPE_CLASS_SCOPED 2
#define STAGE_SECTION_PROBE_WAIT_MS 2000
#define STAGE_SECTION_PROBE_POLL_MS 10
#define STAGE_SECTION_WAITERS_MAX 4
#define PAGED_CODE() assert(irql == 0)
#define CONTAINING_RECORD(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define RtlCopyMemory memcpy
#define RtlEqualMemory(a,b,n) (memcmp(a,b,n)==0)
#define STAGE_ACT_EXIT() goto Exit
/* PRODUCTION_CONSTANTS */
static LIST_ENTRY RegistryEntries;
static LONG RegistryLock, NameActivationWaiters;
static int irql, registryLocks, stateLocks, refs, handles;
static LONG RegistrySopMapGeneration, RegistryChangeSequence;
static int owners, globalUnknown, trusted, transition, teardown, reclaimThread, topLevel;
static int directoryRename, sections, spilledWriters, spilledIo, writable, markersClear, readMapping, writeProbes;
static int flushes, promotes, queued, delays, runOnDelay, casAllowed, siblingsFree, instanceAvailable;
static int failure, flushMutation, classifyAlias, unionScoped, currentScoped;
static NTSTATUS flushStatus;
static ULONGLONG now;
static ULONG policyGeneration, traceFlags;
static SOP sop, replacement;
static FILE_OBJECT file;
static LIFETIME life;
static STREAM_CONTEXT context;
static INSTANCE_CONTEXT instanceContext;
static ENTRY entry;
static VOID StageRegistryActivationProcess(PSTAGE_REGISTRY_ENTRY, PFLT_INSTANCE, PFLT_VOLUME, PULONG, PBOOLEAN);
static BOOLEAN StageRegistryOriginalContext(PSTAGE_REGISTRY_ENTRY, PSAFEUPLOAD_STREAM_CONTEXT, PVOID);
static BOOLEAN SafeUploadStageWritersNameActivating(PFLT_INSTANCE, PCUNICODE_STRING);
static LONG InterlockedCompareExchange(volatile LONG *p,LONG n,LONG c){LONG o=*p;if(o==c)*p=n;return o;}
static LONG InterlockedExchange(volatile LONG *p,LONG n){LONG o=*p;*p=n;return o;}
static LONG InterlockedIncrement(volatile LONG *p){return ++*p;}
static LONG InterlockedDecrement(volatile LONG *p){return --*p;}
static LONG InterlockedCompareExchange64(volatile LONG *p,LONG n,LONG c){return InterlockedCompareExchange(p,n,c);}
static LONG InterlockedIncrement64(volatile LONG *p){return ++*p;}
static PVOID InterlockedCompareExchangePointer(PVOID volatile *p,PVOID n,PVOID c){PVOID o=*p;if(o==c)*p=n;return o;}
static void FltAcquirePushLockShared(LONG *p){assert(p==&RegistryLock && !stateLocks);++registryLocks;}
static void FltAcquirePushLockExclusive(LONG *p){FltAcquirePushLockShared(p);}
static void FltReleasePushLock(LONG *p){assert(p==&RegistryLock && registryLocks);--registryLocks;}
static void StageAcquireSpinLock(LONG *p,KIRQL *old){(void)p;*old=irql;irql=2;++stateLocks;}
static void StageReleaseSpinLock(LONG *p,KIRQL old){(void)p;assert(stateLocks);--stateLocks;irql=old;}
static PSTAGE_SOP_LIFETIME StageRegistryLifetime(PSTAGE_REGISTRY_ENTRY e){return e->Lifetime;}
static BOOLEAN StageRegistryLifetimeEnded(PSTAGE_REGISTRY_ENTRY e){return e->Lifetime && e->Lifetime->Ended;}
static int SafeUploadStageWritersGlobalUnknown(void){return globalUnknown;}
static int SafeUploadStageWritersOwnerCount(void){return owners;}
static int SafeUploadInstanceIsTrusted(PFLT_INSTANCE i){(void)i;return trusted;}
static int SafeUploadStageMandatoryTeardownActive(void){return teardown;}
static int SafeUploadPolicyScopeTransitionActive(void){return transition;}
static int StageRegistryIsReclaimIoThread(void){return reclaimThread;}
static int KeGetCurrentIrql(void){return irql;}
static PVOID IoGetTopLevelIrp(void){return topLevel?(PVOID)1:NULL;}
static ULONGLONG KeQueryInterruptTime(void){return now;}
static void SafeUploadStageWritersQueueRecheck(void){assert(!registryLocks&&!stateLocks);++queued;}
static void runWorker(void){ULONG budget=32;BOOLEAN more=FALSE;StageRegistryActivationProcess(&entry,entry.Instance,(PVOID)2,&budget,&more);assert(!more);}
static NTSTATUS KeDelayExecutionThread(int mode,BOOLEAN alert,LARGE_INTEGER *interval){
    (void)mode;(void)alert;assert(!registryLocks&&!stateLocks&&interval->QuadPart<0);++delays;
    /* Oversleep deliberately: monotonic deadline, not counted intervals. */
    now+=5000000;
    if(runOnDelay && queued){runOnDelay=0;runWorker();}
    return 0;
}
static UNICODE_STRING StageRegistryBaseName(PCUNICODE_STRING n){return *n;}
static BOOLEAN RtlEqualUnicodeString(PCUNICODE_STRING a,PCUNICODE_STRING b,BOOLEAN insensitive){
    (void)insensitive;return a->Length==b->Length&&RtlEqualMemory(a->Buffer,b->Buffer,a->Length);
}
static void *ExAllocatePool2(int f,size_t n,int tag){(void)f;(void)tag;return calloc(1,n);}
static void ExFreePoolWithTag(PVOID p,int tag){(void)tag;free(p);}
static void StageRegistryMarkEntryUnknown(PSTAGE_REGISTRY_ENTRY e,LONG reason){e->UnknownReasons|=reason;e->State=SAFEUPLOAD_REGISTRY_STATE_UNKNOWN;}
static void StageRegistrySetEntryUnknownLocked(PSTAGE_REGISTRY_ENTRY e,LONG reason){StageRegistryMarkEntryUnknown(e,reason);}
static void StageRegistryPublishGlobalUnknown(LONG r){globalUnknown|=r;}
static void StageRegistryPrepareActivation(PSTAGE_REGISTRY_ENTRY e,BOOLEAN unknown){e->State=unknown?SAFEUPLOAD_REGISTRY_STATE_UNKNOWN:SAFEUPLOAD_REGISTRY_STATE_ACTIVATING;}
static void StageRegistryResolveAliasProbe(PSTAGE_REGISTRY_ENTRY e,BOOLEAN a,BOOLEAN b,PBOOLEAN activated){(void)e;(void)a;(void)b;*activated=FALSE;}
static void StageRegistryCancelAliasProbeForInstanceUnknown(PSTAGE_REGISTRY_ENTRY e){e->AliasProbePending=0;}
static void StageRegistryRecordDeferral(PSTAGE_REGISTRY_ENTRY e,NTSTATUS s,UINT32 step){(void)e;(void)s;(void)step;}
static void StageRegistryRecordClassificationResult(PSTAGE_REGISTRY_ENTRY e,NTSTATUS s,UINT32 step){(void)e;(void)s;(void)step;}
static BOOLEAN StageRegistryDirectoryRenameInFlightLocked(PFLT_INSTANCE i,PCUNICODE_STRING n){(void)i;(void)n;return directoryRename;}
static BOOLEAN StageAnchorTake(PSTAGE_REGISTRY_ENTRY e,PSTAGE_ANCHOR *a){(void)e;*a=NULL;return FALSE;}
static void StageAnchorDestroy(PSTAGE_ANCHOR a){(void)a;assert(0);}
static void StageAnchorEndVisit(PSTAGE_REGISTRY_ENTRY e,PFLT_INSTANCE i,PSTAGE_ANCHOR *a,HANDLE *h,PFILE_OBJECT *o,BOOLEAN r){(void)e;(void)i;(void)a;(void)h;(void)o;(void)r;}
static NTSTATUS StageRegistryOpenIdentity(PSTAGE_REGISTRY_ENTRY e,PFLT_INSTANCE i,PFLT_VOLUME v,HANDLE *h,PFILE_OBJECT *o,UINT32 *step,PBOOLEAN noNames,BOOLEAN names){
    (void)e;(void)i;(void)v;(void)step;(void)noNames;(void)names;assert(!registryLocks&&!stateLocks);++handles;*h=(PVOID)3;*o=&file;return 0;
}
static NTSTATUS FltGetStreamContext(PFLT_INSTANCE i,PFILE_OBJECT o,PFLT_CONTEXT *c){(void)i;(void)o;++refs;*c=&context;return 0;}
static NTSTATUS FltGetInstanceContext(PFLT_INSTANCE i,PFLT_CONTEXT *c){(void)i;if(!instanceAvailable)return -1;++refs;*c=&instanceContext;return 0;}
static void FltReleaseContext(PVOID c){(void)c;assert(refs>0);--refs;}
static void ObDereferenceObject(PVOID o){(void)o;}
static void FltClose(HANDLE h){(void)h;assert(handles>0);--handles;}
static void StageRegistryParkScopeScan(PSTAGE_REGISTRY_ENTRY e){(void)e;}
static NTSTATUS StageRegistryClassifyAllLinkNames(PSTAGE_REGISTRY_ENTRY e,PFLT_INSTANCE i,PFLT_VOLUME v,PULONG b,PBOOLEAN no,PBOOLEAN u,PBOOLEAN c,STAGE_SCOPE_CLASSIFICATION_RECEIPT *r){
    (void)e;(void)i;(void)v;(void)r;assert(*b);--*b;*no=FALSE;*u=unionScoped;*c=currentScoped;return failure?STATUS_RETRY:0;
}
static void StageRegistryResolveAliasProbeVersioned(PSTAGE_REGISTRY_ENTRY e,BOOLEAN a,BOOLEAN b,BOOLEAN c,ULONG d,PBOOLEAN act,PVOID r){(void)e;(void)a;(void)b;(void)c;(void)d;(void)r;*act=FALSE;}
static BOOLEAN StageRegistryResolveAliasProbeForGeneration(PSTAGE_REGISTRY_ENTRY e,PFLT_INSTANCE i,BOOLEAN a,BOOLEAN b,ULONG d,PBOOLEAN act,PVOID r){
    (void)i;(void)a;(void)b;(void)d;(void)r;*act=classifyAlias && !e->UnknownReasons;e->AliasProbePending=0;return *act;
}
static BOOLEAN StageRegistrySetLinkScopeClassificationVersioned(PSTAGE_REGISTRY_ENTRY e,BOOLEAN a,BOOLEAN b,ULONG d,PVOID r){(void)e;(void)a;(void)b;(void)d;(void)r;return TRUE;}
static int StageRegistrySnapshotSpilledWriters(PSTAGE_REGISTRY_ENTRY e){(void)e;return spilledWriters;}
static int StageRegistrySnapshotSpilledMutatingIo(PSTAGE_REGISTRY_ENTRY e){(void)e;return spilledIo;}
static UINT32 StageRegistrySnapshotC(PSTAGE_REGISTRY_ENTRY e,PVOID a,int b,PVOID c){(void)e;(void)a;(void)b;(void)c;return (UINT32)sections;}
static BOOLEAN MmDoesFileHaveUserWritableReferences(PSECTION_OBJECT_POINTERS s){assert(s==&sop);return writable;}
static BOOLEAN MmCanFileBeTruncated(PSECTION_OBJECT_POINTERS s,PVOID size){assert(s==&sop&&size==NULL);return !readMapping&&!writeProbes;}
static NTSTATUS FltFlushBuffers2(PFLT_INSTANCE i,PFILE_OBJECT o,ULONG type,PVOID data){
    (void)i;(void)data;assert(!registryLocks&&!stateLocks&&o==&file);assert(type==0);
    ++flushes;
    if(flushMutation==1)file.SectionObjectPointer=&replacement;
    if(flushMutation==2)context.WriterSopLifetime=NULL;
    if(flushMutation==3)writable=TRUE;
    if(flushMutation==4)entry.W=1;
    if(flushMutation==5)entry.UnknownReasons=SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY;
    if(flushMutation==6)++policyGeneration;
    if(flushMutation==7)++RegistrySopMapGeneration;
    if(flushMutation==8)writeProbes=TRUE;
    return flushStatus;
}
static BOOLEAN StageRegistryUnknownSopMarkersClear(PFLT_INSTANCE i,ULONGLONG *g){(void)i;*g=RegistrySopMapGeneration;return markersClear;}
static LONG SafeUploadCurrentPolicyGeneration(void){return (LONG)policyGeneration;}
static void SafeUploadPolicyReadLiveSnapshot(ULONG *g,ULONG *f){*g=policyGeneration;*f=0;}
static BOOLEAN StageRegistrySiblingIncarnationsRetiredLocked(PSTAGE_REGISTRY_ENTRY e,BOOLEAN arm){(void)e;(void)arm;return siblingsFree;}
static BOOLEAN SafeUploadPolicyRenameLossGenerationEnter(ULONGLONG *g,ULONGLONG expected,KIRQL *old){*old=irql;return *g==expected;}
static void SafeUploadPolicyRenameLossGenerationLeave(KIRQL old){assert(irql==old);}
static BOOLEAN StageRegistryTryPromoteStateNoInline(PSTAGE_REGISTRY_ENTRY e,ULONGLONG g,ULONG p,ULONG f,ULONG flags){
    (void)g;(void)p;(void)f;assert(registryLocks&&stateLocks);if(!casAllowed)return FALSE;
    assert(!writable&&!e->H&&!e->W&&!e->T&&!e->UnknownReasons&&flushes==1);
    assert(StageRegistryOriginalContext(e,&context,&sop));e->State=SAFEUPLOAD_REGISTRY_STATE_PROTECTED;++promotes;traceFlags=flags;return TRUE;
}
/* PRODUCTION_BODIES */
static void init(void){
    assert(!refs&&!handles&&!registryLocks&&!stateLocks&&!NameActivationWaiters);
    memset(&entry,0,sizeof(entry));memset(&context,0,sizeof(context));memset(&instanceContext,0,sizeof(instanceContext));
    life=(LIFETIME){0,0,&sop};entry.Lifetime=&life;context.WriterSopLifetime=&life;
    entry.Instance=(PVOID)1;entry.SectionObjectPointer=&sop;file.SectionObjectPointer=&sop;
    entry.Listed=TRUE;entry.ActivationEnforced=1;entry.ActivationGeneration=1;entry.StreamIdentityKnown=TRUE;
    entry.State=SAFEUPLOAD_REGISTRY_STATE_ACTIVATING;entry.ScopeNameClassification=STAGE_SCOPE_CLASS_SCOPED;
    entry.Name[0]='x';entry.NameChars=1;
    RegistryEntries.Flink=&entry.Link;RegistryEntries.Blink=&entry.Link;entry.Link.Flink=&RegistryEntries;entry.Link.Blink=&RegistryEntries;
    /* Neither the ordinary reader nor cache lifetime ends in this fixture. */
    sop.DataSectionObject=(PVOID)4;sop.SharedCacheMap=(PVOID)5;
    owners=globalUnknown=transition=teardown=reclaimThread=topLevel=directoryRename=0;
    sections=spilledWriters=spilledIo=writable=flushes=promotes=queued=delays=runOnDelay=readMapping=writeProbes=0;
    failure=flushMutation=0;flushStatus=0;now=0;policyGeneration=1;RegistrySopMapGeneration=1;
    trusted=markersClear=casAllowed=siblingsFree=instanceAvailable=classifyAlias=unionScoped=currentScoped=TRUE;
}
int main(void){
    (void)&MmCanFileBeTruncated; /* The base worker uses this separate RO-map result. */
    init();runWorker();assert(promotes==1&&flushes==1);
    assert((traceFlags&SAFEUPLOAD_PROMOTION_BASIS_CACHE_FLUSH)!=0);
    assert((traceFlags&SAFEUPLOAD_PROMOTION_BASIS_SOP_EMPTY)==0);
    init();sop.DataSectionObject=sop.SharedCacheMap=NULL;runWorker();assert(promotes==1&&flushes==1);
    assert((traceFlags&SAFEUPLOAD_PROMOTION_BASIS_SOP_EMPTY)!=0);
    /* Distinct real blockers; no repeated observation substitutes for them. */
    for(int n=0;n<24;++n){init();
        switch(n){
        case 0:entry.H=1;break;case 1:entry.W=1;break;case 2:entry.T=1;break;
        case 3:sections=1;break;case 4:writable=1;break;case 5:entry.RenameInFlight=1;break;
        case 6:spilledWriters=1;break;case 7:spilledIo=1;break;
        case 8:entry.UnknownReasons=1;break;case 9:globalUnknown=1;break;
        case 10:instanceContext.RegistryUnknownReasons=1;break;case 11:owners=1;break;
        case 12:context.WriterSopLifetime=NULL;break;case 13:life.Invalid=1;break;
        case 14:life.Ended=1;break;case 15:markersClear=FALSE;break;
        case 16:entry.ActivationGeneration=0;break;case 17:siblingsFree=FALSE;break;
        case 18:flushStatus=-1;break;case 19:flushStatus=STATUS_PENDING;break;
        case 20:casAllowed=FALSE;break;case 21:directoryRename=TRUE;break;
        case 22:readMapping=TRUE;break;case 23:writeProbes=TRUE;break;
        }runWorker();assert(promotes==0);if(n==22||n==23)assert(flushes==0);
    }
    for(int n=1;n<=8;++n){init();flushMutation=n;runWorker();assert(promotes==0);}
    init();UNICODE_STRING name={2,2,entry.Name};runOnDelay=1;
    /* Parked S=YES, then last mapped writer leaves without another callback. */
    writable=1;runWorker();assert(promotes==0);writable=0;
    now=600000000;SafeUploadStageWritersAwaitNameActivation(entry.Instance,&name);
    assert(promotes==1&&queued==1&&delays==1&&!SafeUploadStageWritersNameActivating(entry.Instance,&name));
    init();SafeUploadStageWritersAwaitNameActivation(entry.Instance,&name);
    assert(queued==1&&delays==4&&now==20000000&&SafeUploadStageWritersNameActivating(entry.Instance,&name));
    /* Unknown, active writers, unsafe context, transitions and saturation never wait. */
    for(int n=0;n<15;++n){init();switch(n){
        case 0:entry.State=SAFEUPLOAD_REGISTRY_STATE_UNKNOWN;break;
        case 1:entry.UnknownReasons=1;break;case 2:globalUnknown=1;break;
        case 3:entry.H=1;break;case 4:entry.W=1;break;case 5:entry.T=1;break;
        case 6:sections=1;break;case 7:life.Invalid=1;break;case 8:entry.Lifetime=NULL;break;
        case 9:owners=1;break;case 10:transition=1;break;case 11:teardown=1;break;
        case 12:topLevel=1;break;case 13:reclaimThread=1;break;case 14:instanceContext.WritersUntracked=1;break;
        }SafeUploadStageWritersAwaitNameActivation(entry.Instance,&name);assert(!queued&&!delays&&!promotes);
    }
    init();NameActivationWaiters=4;SafeUploadStageWritersAwaitNameActivation(entry.Instance,&name);
    assert(NameActivationWaiters==4&&!queued&&!delays);NameActivationWaiters=0;
    init();assert(!refs&&!handles&&!registryLocks&&!stateLocks);
    puts("PASS: retained cache, exact flush/rechecks, live/lost evidence, request wake, monotonic bounded wait");
    return 0;
}
