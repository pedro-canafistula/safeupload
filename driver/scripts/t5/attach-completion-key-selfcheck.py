#!/usr/bin/env python3
"""Compile production attach completion/lookup bodies with deterministic reuse.

Host shims check ordering and ownership; they do not qualify Filter Manager,
Windows cancellation, IRQL, lock hold time or a protected driver/agent pair.
"""
import importlib.util
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
PATH = ROOT / 'driver/SafeUpload.Minifilter/StageStream.c'
spec = importlib.util.spec_from_file_location(
    'teardown', Path(__file__).with_name('teardown-participation-selfcheck.py'))
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)


def body(source, name):
    return t.body('StageStream.c', name, {'StageStream.c': source})


def duplicate_loop(source):
    queue = body(source, 'StageAttachQueueCreate')
    start = queue.index('for (link = StageAttachLookup.Flink;')
    opening = queue.index('{', start)
    end, depth = opening + 1, 1
    while depth:
        depth += (queue[end] == '{') - (queue[end] == '}')
        end += 1
    return queue[start:end]


def contract(source):
    def order(text, *parts):
        at = -1
        for part in parts:
            at = text.index(part, at + 1)

    finish = body(source, 'StageAttachFinishCallback')
    order(finish, 'NT_ASSERT(!Transaction->CancelRegistered);',
          'StageStreamAcquireSpinLock(&StageAttachLock, &irql);',
          'data = Transaction->CallbackData;', 'Transaction->CallbackData = NULL;',
          'StageStreamReleaseSpinLock(&StageAttachLock, irql);',
          'NT_ASSERT(data != NULL);', 'FltCompletePendedPreOperation(data, Result, Context);')
    assert finish.count('FltCompletePendedPreOperation(') == 1
    for forbidden in ('RemoveLookup', 'ReleaseActive', 'Dereference', 'KeWait',
                      'StageAcquire(', 'ExAllocate', 'for (', 'while ('):
        assert forbidden not in finish, forbidden
    assert '#pragma alloc_text(PAGE, StageAttachFinishCallback)' not in source
    complete = body(source, 'StageAttachComplete')
    calls = re.findall(r'StageAttachFinishCallback\(([^;]+)\);', complete)
    assert calls == [
        'Transaction, FLT_PREOP_SUCCESS_WITH_CALLBACK, record',
        'Transaction, FLT_PREOP_SUCCESS_NO_CALLBACK, NULL',
        'Transaction, FLT_PREOP_COMPLETE, NULL',
        'Transaction, FLT_PREOP_COMPLETE, NULL'], calls
    assert 'FltCompletePendedPreOperation(' not in complete
    order(complete, 'InterlockedCompareExchange(&Transaction->CompletionClaimed, 1, 0)',
          'FltClearCancelCompletion(Transaction->CallbackData)',
          'if (clearStatus == STATUS_CANCELLED)',
          'KeWaitForSingleObject(&Transaction->CancelCallbackExited,',
          'Transaction->CancelRegistered = FALSE;',
          'KeWaitForSingleObject(&Transaction->PreOpReturnEvent,',
          'StageAttachFinishCallback(')
    tail = complete[complete.rindex('StageAttachFinishCallback('):]
    assert 'CallbackData' not in tail
    order(tail, 'StageAttachFinishCallback(', 'stream->AttachCompletionFence = FALSE;',
          'CompletionFinished:', 'SafeUploadPolicyAdmissionRelease(Transaction->AdmissionToken)',
          'KeSetEvent(&Transaction->Completed,')
    # Key retirement never substitutes for the existing teardown/resource drain.
    drain = body(source, 'StageAttachDrainTransaction')
    order(drain, 'StageAttachComplete(Transaction, status);',
          'Transaction->Stream->AttachLifecycleInFlight = FALSE;',
          'InterlockedDecrement(&Transaction->Stream->RpcReferences)',
          'StageAttachReleaseRelatedObjects(Transaction);',
          'lookupRemoved = StageAttachRemoveLookup(Transaction);',
          'StageAttachTransactionDereference(Transaction);',
          'if (lookupRemoved) StageAttachReleaseActive();')
    assert 'if (current->CallbackData == Data)' in duplicate_loop(source)
    assert 'status = STATUS_INVALID_DEVICE_STATE;' in duplicate_loop(source)
    cancel = body(source, 'StageAttachCancelCallback')
    order(cancel, 'StageStreamAcquireSpinLock(&StageAttachLock,',
          'if (candidate->CallbackData == Data)', 'StageAttachReference(transaction);',
          'StageStreamReleaseSpinLock(&StageAttachLock,',
          'InterlockedExchange(&transaction->CancelCallbackState, 2)',
          'KeSetEvent(&transaction->CancelCallbackExited,',
          'StageAttachTransactionDereference(transaction);')
    instance = body(source, 'StageAttachHasInstance')
    assert 'if (tx->InstanceIdentity == Instance)' in instance
    assert 'CallbackData' not in instance
    teardown = body(source, 'SafeUploadStageAttachInstanceTeardownStart')
    order(teardown, 'if (tx->InstanceIdentity == Instance)',
          'InterlockedExchange(&tx->TeardownRequested, 1)',
          'InterlockedExchange(&tx->CancelRequested, 1)',
          'while (StageAttachHasInstance(Instance))')
    assert source.count('Transaction->CallbackData = NULL;') == 1


SHIM = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#define CHECK(c) ((c) ? (void)0 : (fprintf(stderr,"line %d: %s\n",__LINE__,#c),exit(97)))
#define NT_ASSERT CHECK
#define TRUE 1
#define FALSE 0
#define PASSIVE_LEVEL 0
#define DISPATCH_LEVEL 2
#define STATUS_SUCCESS 0
#define STATUS_CANCELLED -1
#define STATUS_ACCESS_DENIED -2
#define STATUS_DELETE_PENDING -3
#define STATUS_DEVICE_NOT_READY -4
#define STATUS_RETRY -5
#define STATUS_INVALID_DEVICE_STATE -6
#define NT_SUCCESS(s) ((s)>=0)
#define FLT_PREOP_SUCCESS_WITH_CALLBACK 1
#define FLT_PREOP_SUCCESS_NO_CALLBACK 2
#define FLT_PREOP_COMPLETE 3
#define Executive 0
#define KernelMode 0
#define IO_NO_INCREMENT 0
#define STAGE_WAIT_SERVICE 1
#define STAGE_ATTACH_LIMIT_GLOBAL 4
#define DELETE 0x10000
#define FlagOn(v,f) ((v)&(f))
typedef void VOID,*PVOID,*PFLT_INSTANCE;
typedef int BOOLEAN,KIRQL,NTSTATUS,FLT_PREOP_CALLBACK_STATUS;
typedef int32_t LONG; typedef int64_t LONG64; typedef unsigned ULONG;
typedef struct EVENT { int set; } EVENT;
typedef struct LIST_ENTRY { struct LIST_ENTRY *Flink,*Blink; } LIST_ENTRY,*PLIST_ENTRY;
#define CONTAINING_RECORD(p,type,member) ((type*)((char*)(p)-offsetof(type,member)))
static void InitializeListHead(LIST_ENTRY *p){p->Flink=p->Blink=p;}
static void InsertTailList(LIST_ENTRY *head,LIST_ENTRY *p){p->Flink=head;p->Blink=head->Blink;head->Blink->Flink=p;head->Blink=p;}
static void RemoveEntryList(LIST_ENTRY *p){p->Blink->Flink=p->Flink;p->Flink->Blink=p->Blink;}
typedef struct DATA { struct { NTSTATUS Status; uintptr_t Information; } IoStatus; int canceled; } DATA,*PFLT_CALLBACK_DATA;
typedef struct FILE_OBJECT { PVOID FsContext2; } FILE_OBJECT;
typedef struct HANDLE { PVOID WriterLease; int GrantedAccess; } HANDLE,*PSTAGE_HANDLE;
typedef int SAFEUPLOAD_STAGE_WRITER_REFUSAL, NATIVE_RECORD;
typedef NATIVE_RECORD *PSAFEUPLOAD_STAGE_NATIVE_RECORD;
typedef struct NAME { int Name; } NAME;
typedef struct STREAM STREAM;
typedef struct VIEW { STREAM *Current; BOOLEAN Detached; LONG64 Generation; } VIEW;
struct STREAM {
 VIEW *View; BOOLEAN AttachCompletionKnown,AttachTerminalPending,AttachAcknowledged,
 AttachCompletionPending,AttachCompletionFence,AttachCompletionMayExist,
 AllocationRecoveryPending,AllocationRecoveryInFlight,AllocationReceiptPending,
 AllocationTupleKnown,ReservationLinked,BoundAllocation,DiscardOnClose,Discarded,
 AttachLifecycleInFlight;
 STREAM *AllocationReceiptParent; ULONG AllocationReceiptReferences;
 struct { uint64_t AuthorityRevision; } SeedCompletion;
 LONG RpcReferences; NTSTATUS DrainStatus; int Wait;
};
typedef STREAM *PSTAGE_STREAM;
typedef struct TX {
 LIST_ENTRY LookupLink; DATA *CallbackData; PFLT_INSTANCE InstanceIdentity;
 LONG References,CompletionClaimed,CancelRequested,TeardownRequested,CancelCallbackState,ExposeClaimed;
 BOOLEAN CancelRegistered,WorkerOwnsCompletion,NativePath,NeedsAttachCommit,
 BindingInstalled,OrdinaryPublicOpen,LookupLinked,UnexposedRetirementAllowed;
 EVENT CancelCallbackExited,PreOpReturnEvent,Completed;
 STREAM *Stream; NATIVE_RECORD *NativeRecord; FILE_OBJECT *ReferencedFileObject;
 PVOID AdmissionToken,RequestorProcess; NAME *NameInfo;
 struct { FILE_OBJECT *FileObject; PFLT_INSTANCE Instance; } RelatedObjects;
 uint64_t NativeGeneration,NativePrepareRevision,NativePrepareAuthority;
 int PublicOpenReceipt; LONG64 ExpectedGeneration; int RelatedReleased;
} TX,STAGE_ATTACH_TRANSACTION,*PSTAGE_ATTACH_TRANSACTION;
static int StageAttachLock,StageNamespaceResource;
static LIST_ENTRY StageAttachLookup;
static PFLT_INSTANCE StageAttachCaptures[STAGE_ATTACH_LIMIT_GLOBAL];
static LONG StageAttachActiveCount,StageAttachCaptureCount;
static EVENT StageAttachDrained,StageAttachChanged,StageAttachQueueEvent;
static struct { int WakeInline; } StageCounters;
static int StageStopping,spin,irql,namespaceHeld,mandatory,instanceTeardown,cancelMode;
static int completions,clearCalls,joinCalls,relatedReleases,finalReleases,objectDrops,recordDrops,privateClears;
static int expectedResult; static NTSTATUS workerStatus,expectedIoStatus;
static TX *finishing; static DATA *originalData; static NATIVE_RECORD record;
#define InterlockedCompareExchange(p,v,c) (*(p)==(c)?(*(p)=(v),(c)):*(p))
#define InterlockedExchange(p,v) (*(p)=(v))
#define InterlockedIncrement(p) (++*(p))
#define InterlockedDecrement(p) (--*(p))
static int KeGetCurrentIrql(void){return irql;}
static void StageStreamAcquireSpinLock(int *p,KIRQL *old){CHECK(p==&StageAttachLock&&!spin);*old=irql;irql=DISPATCH_LEVEL;spin=1;}
static void StageStreamReleaseSpinLock(int *p,KIRQL old){CHECK(p==&StageAttachLock&&spin);spin=0;irql=old;}
static void StageAcquire(int *p){CHECK(p==&StageNamespaceResource&&!spin&&!namespaceHeld);namespaceHeld=1;}
static void StageRelease(int *p){CHECK(p==&StageNamespaceResource&&!spin&&namespaceHeld);namespaceHeld=0;}
static void KeSetEvent(EVENT *p,int increment,int wait){(void)increment;(void)wait;p->set=1;}
static BOOLEAN SafeUploadStageMandatoryTeardownActive(void){return mandatory;}
static BOOLEAN StageAttachIsInstanceTearingDown(PFLT_INSTANCE instance){CHECK(instance==finishing->InstanceIdentity);return instanceTeardown;}
static BOOLEAN FltIsIoCanceled(DATA *p){CHECK(p==originalData);return p->canceled;}
static void StageAttachTransactionDereference(TX *tx){
 CHECK(!spin);CHECK(tx->References>0);--tx->References;
 if(!tx->References){CHECK(!tx->LookupLinked);if(tx==finishing){CHECK(tx->RelatedReleased);++finalReleases;}}
}
static void StageAttachCancelCallback(DATA *Data);
static NTSTATUS FltClearCancelCompletion(DATA *data){
 CHECK(!spin&&!namespaceHeld&&finishing->CancelRegistered&&finishing->CallbackData==data);
 ++clearCalls;return cancelMode==2?STATUS_CANCELLED:cancelMode==5?STATUS_ACCESS_DENIED:STATUS_SUCCESS;
}
static NTSTATUS KeWaitForSingleObject(EVENT *event,int reason,int mode,int alert,PVOID timeout){
 (void)reason;(void)mode;(void)alert;(void)timeout;CHECK(!spin&&!namespaceHeld);
 if(event==&finishing->CancelCallbackExited){
  CHECK(finishing->CancelRegistered&&finishing->CallbackData==originalData);++joinCalls;
  StageAttachCancelCallback(originalData);
 }
 CHECK(event->set);return STATUS_SUCCESS;
}
static BOOLEAN SafeUploadPolicyAdmissionMustRetry(void){return FALSE;}
static PVOID StageFindView(PVOID process,int *name){(void)process;(void)name;return NULL;}
static NTSTATUS SafeUploadStageNativeMarkForwarded(NATIVE_RECORD *r,uint64_t g,uint64_t v,uint64_t a,int *receipt){
 (void)g;(void)v;(void)a;(void)receipt;CHECK(namespaceHeld&&r==&record);return STATUS_SUCCESS;
}
static NTSTATUS StageAttachExchangeNative(TX *tx){(void)tx;CHECK(!namespaceHeld&&!spin);return STATUS_ACCESS_DENIED;}
static NTSTATUS SafeUploadStageNativeMarkNotForwarded(NATIVE_RECORD *r){CHECK(r==&record);return STATUS_SUCCESS;}
static void SafeUploadStageNativeReleaseRecord(NATIVE_RECORD *r){CHECK(r==&record);++recordDrops;}
static void ObDereferenceObject(FILE_OBJECT *file){CHECK(file==finishing->ReferencedFileObject&&!spin&&!namespaceHeld);++objectDrops;}
static void StageRemoveAllocationNameReservation(STREAM *s){CHECK(namespaceHeld);s->ReservationLinked=FALSE;}
static void StageQueueStream(STREAM *s,int *counter){(void)s;(void)counter;CHECK(namespaceHeld&&!spin);}
static BOOLEAN StageBoundSeedReady(STREAM *s){(void)s;return TRUE;}
static NTSTATUS SafeUploadStagePublicRevalidateWriter(PVOID lease,SAFEUPLOAD_STAGE_WRITER_REFUSAL *r){(void)lease;(void)r;return STATUS_SUCCESS;}
static NTSTATUS SafeUploadStagePublicWriterMetadataCurrent(PVOID lease,SAFEUPLOAD_STAGE_WRITER_REFUSAL *r){(void)lease;(void)r;return STATUS_SUCCESS;}
static NTSTATUS SafeUploadStageNativeBindWriter(PFLT_INSTANCE instance,FILE_OBJECT *file,PVOID lease){(void)instance;(void)file;(void)lease;return STATUS_SUCCESS;}
static void SafeUploadPolicyAdmissionRelease(PVOID token){CHECK(token!=NULL&&!spin);}
static NTSTATUS SafeUploadPolicyAdmissionAcquire(PVOID *token){*token=(PVOID)1;return STATUS_SUCCESS;}
static uint64_t SafeUploadStageProtocolNativeAuthority(void){return 1;}
static void StageAttachRollbackBinding(TX *tx,STREAM *s){CHECK(tx->Stream==s);tx->BindingInstalled=FALSE;}
static void StageClearPrivateDelete(STREAM *s){(void)s;CHECK(namespaceHeld&&!spin);++privateClears;}
static NTSTATUS StageAttachWorkerBody(TX *tx){CHECK(tx==finishing);return workerStatus;}
static NTSTATUS StageAttachRetireUnexposed(TX *tx,STREAM *s){(void)tx;(void)s;return STATUS_ACCESS_DENIED;}
static void StageAttachReleaseRelatedObjects(TX *tx){
 CHECK(!spin&&!namespaceHeld&&tx->Completed.set&&tx->LookupLinked&&StageAttachActiveCount==1);
 CHECK(tx->CallbackData==NULL&&tx->References==2);tx->RelatedReleased=1;++relatedReleases;
}
static void FltCompletePendedPreOperation(DATA *data,FLT_PREOP_CALLBACK_STATUS result,PVOID context);
'''


SIGNATURES = (
    ('StageAttachReference', 'static void StageAttachReference(TX *Transaction)'),
    ('StageAttachRemoveLookup', 'static BOOLEAN StageAttachRemoveLookup(TX *Transaction)'),
    ('StageAttachReleaseActive', 'static void StageAttachReleaseActive(void)'),
    ('StageAttachCancelCallback', 'static void StageAttachCancelCallback(DATA *Data)'),
    ('StageAttachHasInstance', 'static BOOLEAN StageAttachHasInstance(PFLT_INSTANCE Instance)'),
    ('StageAttachFinishCallback', 'static void StageAttachFinishCallback(TX *Transaction, FLT_PREOP_CALLBACK_STATUS Result, PVOID Context)'),
    ('StageAttachComplete', 'static void StageAttachComplete(TX *Transaction, NTSTATUS Status)'),
    ('StageAttachDrainTransaction', 'static void StageAttachDrainTransaction(TX *Transaction)'),
)


CASES = r'''
static void FltCompletePendedPreOperation(DATA *data,FLT_PREOP_CALLBACK_STATUS result,PVOID context){
 CHECK(!spin&&!namespaceHeld&&KeGetCurrentIrql()==PASSIVE_LEVEL);
 CHECK(data==originalData&&result==expectedResult);
 CHECK(context==(result==FLT_PREOP_SUCCESS_WITH_CALLBACK?&record:NULL));
 CHECK(finishing->LookupLinked&&finishing->References==2&&StageAttachActiveCount==1);
 CHECK(!finishing->Completed.set&&!finishing->CancelRegistered);
 CHECK(StageAttachHasInstance(finishing->InstanceIdentity));
 CHECK(check_create_key(data,finishing->InstanceIdentity)==STATUS_SUCCESS);
 CHECK(finishing->CallbackData==NULL);
 CHECK(data->IoStatus.Status==expectedIoStatus);
 if(result==FLT_PREOP_COMPLETE&&expectedIoStatus<0)CHECK(!data->IoStatus.Information);
 if(cancelMode==2)CHECK(joinCalls==1&&finishing->CancelCallbackExited.set&&finishing->CancelCallbackState==2);
 ++completions;
 /* A stale cancellation lookup after key transfer must not target the old tx. */
 LONG oldCancel=finishing->CancelRequested,oldState=finishing->CancelCallbackState;
 StageAttachCancelCallback(data);
 CHECK(finishing->CancelRequested==oldCancel&&finishing->CancelCallbackState==oldState);
 /* Reentrant CREATE reuses the exact address while the old lookup remains. */
 TX next={0};next.CallbackData=data;next.InstanceIdentity=finishing->InstanceIdentity;next.References=2;
 next.LookupLinked=TRUE;next.CancelRegistered=TRUE;InitializeListHead(&next.LookupLink);
 KIRQL old;StageStreamAcquireSpinLock(&StageAttachLock,&old);
 InsertTailList(&StageAttachLookup,&next.LookupLink);++StageAttachActiveCount;
 StageStreamReleaseSpinLock(&StageAttachLock,old);
 CHECK(check_create_key(data,next.InstanceIdentity)==STATUS_INVALID_DEVICE_STATE);
 StageAttachCancelCallback(data);
 CHECK(next.CancelRequested==1&&next.CancelCallbackState==2&&next.References==2);
 CHECK(finishing->CancelRequested==oldCancel&&finishing->CancelCallbackState==oldState);
 CHECK(StageAttachRemoveLookup(&next));StageAttachTransactionDereference(&next);StageAttachReleaseActive();
 CHECK(next.References==0&&StageAttachActiveCount==1&&!StageAttachDrained.set);
 /* A teardown beginning after hand-back still sees the old transaction. */
 StageStreamAcquireSpinLock(&StageAttachLock,&old);
 for(LIST_ENTRY *link=StageAttachLookup.Flink;link!=&StageAttachLookup;link=link->Flink){
  TX *tx=CONTAINING_RECORD(link,TX,LookupLink);
  if(tx->InstanceIdentity==finishing->InstanceIdentity)tx->TeardownRequested=1;
 }
 StageStreamReleaseSpinLock(&StageAttachLock,old);
 CHECK(finishing->TeardownRequested==1&&StageAttachHasInstance(finishing->InstanceIdentity));
 data->IoStatus.Status=1234; /* address now belongs to Filter Manager/new I/O */
}
static void run_case(int kind,int cancellation){
 TX tx={0};DATA data={0};NAME name={0};FILE_OBJECT file={0};STREAM stream={0};VIEW view={0};
 spin=irql=namespaceHeld=StageStopping=mandatory=instanceTeardown=0;cancelMode=cancellation;
 completions=clearCalls=joinCalls=relatedReleases=finalReleases=objectDrops=recordDrops=privateClears=0;
 StageAttachDrained.set=StageAttachChanged.set=StageAttachQueueEvent.set=0;
 InitializeListHead(&StageAttachLookup);StageAttachActiveCount=1;StageAttachCaptureCount=0;
 finishing=&tx;originalData=&data;tx.CallbackData=&data;tx.InstanceIdentity=(PVOID)1;
 tx.LookupLinked=TRUE;tx.References=2;tx.CancelRegistered=TRUE;tx.PreOpReturnEvent.set=1;
 tx.AdmissionToken=(PVOID)1;tx.NameInfo=&name;tx.RelatedObjects.FileObject=&file;
 InsertTailList(&StageAttachLookup,&tx.LookupLink);
 data.IoStatus.Status=42;data.IoStatus.Information=99;
 workerStatus=(kind==1||kind==2||kind==4)?STATUS_ACCESS_DENIED:STATUS_SUCCESS;
 tx.NativePath=kind<3;tx.NativeRecord=tx.NativePath?&record:NULL;
 tx.OrdinaryPublicOpen=kind==1;tx.ReferencedFileObject=&file;
 if(kind>=3){tx.Stream=&stream;tx.NeedsAttachCommit=TRUE;tx.BindingInstalled=TRUE;
  stream.View=&view;view.Current=&stream;stream.AttachCompletionKnown=TRUE;
  stream.AttachLifecycleInFlight=TRUE;stream.RpcReferences=1;stream.AttachCompletionPending=TRUE;}
 if(cancellation==1)data.canceled=1;
 if(cancellation==3)mandatory=1;
 if(cancellation==4)instanceTeardown=1;
 CHECK(check_create_key(&data,tx.InstanceIdentity)==STATUS_INVALID_DEVICE_STATE);
 expectedResult=cancellation||kind==2||kind>=3?FLT_PREOP_COMPLETE:
  kind==0?FLT_PREOP_SUCCESS_WITH_CALLBACK:FLT_PREOP_SUCCESS_NO_CALLBACK;
 expectedIoStatus=expectedResult==FLT_PREOP_COMPLETE?(workerStatus<0?workerStatus:
  cancellation?STATUS_CANCELLED:STATUS_SUCCESS):42;
 StageAttachDrainTransaction(&tx);
 CHECK(completions==1&&clearCalls==1&&joinCalls==(cancellation==2));
 CHECK(tx.CallbackData==NULL&&tx.Completed.set&&tx.RelatedReleased&&tx.References==0);
 CHECK(relatedReleases==1&&finalReleases==1&&!tx.LookupLinked&&!StageAttachActiveCount);
 CHECK(StageAttachDrained.set&&!StageAttachHasInstance(tx.InstanceIdentity));
 CHECK(data.IoStatus.Status==1234&&!spin&&!namespaceHeld);
 CHECK(check_create_key(&data,tx.InstanceIdentity)==STATUS_SUCCESS);
 if(kind>=3){CHECK(!stream.AttachLifecycleInFlight&&!stream.RpcReferences);
  CHECK(privateClears==(kind==3&&!cancellation));}
 CHECK(objectDrops==(kind==0&&!cancellation));
 CHECK(recordDrops==(kind<3&&!(kind==0&&!cancellation)));
 /* CompletionClaimed still prevents a second hand-back after final drain. */
 StageAttachComplete(&tx,STATUS_SUCCESS);CHECK(completions==1);
}
int main(void){
 for(int kind=0;kind<5;++kind)for(int cancel=0;cancel<6;++cancel)run_case(kind,cancel);
 puts("30 completion/reuse/cancellation/teardown interleavings PASS");return 0;
}
'''


def run_native(source, compiler='cc'):
    definitions = '\n'.join(signature + '\n' + body(source, name)
                            for name, signature in SIGNATURES)
    # Execute the unmodified duplicate-check loop from StageAttachQueueCreate.
    check = '''static NTSTATUS check_create_key(DATA *Data,PFLT_INSTANCE instance){
 PLIST_ENTRY link;ULONG instanceCount=0;KIRQL irql;NTSTATUS status=STATUS_SUCCESS;
 TX local={0},*transaction=&local;
 struct { PFLT_INSTANCE Instance; } related={instance},*Objects=&related;
 (void)Data;
 StageStreamAcquireSpinLock(&StageAttachLock,&irql);
''' + duplicate_loop(source) + '''
 StageStreamReleaseSpinLock(&StageAttachLock,irql);
Fail: (void)instanceCount;return status;
}
'''
    with tempfile.TemporaryDirectory(prefix='t5-attach-key-') as directory:
        path = Path(directory)
        (path / 'test.c').write_text(SHIM + definitions + check + CASES)
        build = subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror',
                                str(path / 'test.c'), '-o', str(path / 'test')],
                               capture_output=True, text=True)
        if build.returncode:
            return build, None
        run = subprocess.run([str(path / 'test')], capture_output=True, text=True,
                             cwd=path, timeout=5)
        return build, run


class AttachCompletionKey(unittest.TestCase):
    def test_production_locks_handoff_sites_and_rundown_contract(self):
        contract(PATH.read_text())

    def test_native_production_completion_reuse_cancellation_and_teardown(self):
        for compiler in ('cc', 'clang'):
            with self.subTest(compiler=compiler):
                build, run = run_native(PATH.read_text(), compiler)
                self.assertEqual(0, build.returncode, build.stderr)
                self.assertEqual(0, run.returncode, run.stderr)
                self.assertIn('30 completion/reuse/cancellation/teardown interleavings PASS', run.stdout)

    def test_native_mutations_compile_but_fail_execution(self):
        # body() blanks comments without moving code; mutate that same text so
        # a commented production body cannot silently evade a counterfactual.
        source = t.strip_code(PATH.read_text())
        build, run = run_native(source)
        self.assertEqual(0, build.returncode, build.stderr)
        self.assertEqual(0, run.returncode, run.stderr)
        mutations = (
            ('StageAttachFinishCallback', 'Transaction->CallbackData = NULL;', '(void)Transaction;'),
            ('StageAttachFinishCallback', 'StageStreamAcquireSpinLock(&StageAttachLock, &irql);', 'irql = PASSIVE_LEVEL;'),
            ('StageAttachFinishCallback', 'StageStreamReleaseSpinLock(&StageAttachLock, irql);', '(void)irql;'),
            ('StageAttachFinishCallback', 'data = Transaction->CallbackData;',
             'StageAttachRemoveLookup(Transaction);\n    data = Transaction->CallbackData;'),
            ('StageAttachFinishCallback', 'data = Transaction->CallbackData;',
             'data = Transaction->CallbackData;\n    --StageAttachActiveCount;'),
            ('StageAttachFinishCallback', 'Transaction->CallbackData = NULL;',
             'FltCompletePendedPreOperation(data, Result, Context);\n    Transaction->CallbackData = NULL;'),
            ('StageAttachComplete', 'FLT_PREOP_SUCCESS_WITH_CALLBACK, record', 'FLT_PREOP_SUCCESS_WITH_CALLBACK, NULL'),
            ('StageAttachComplete', 'FLT_PREOP_SUCCESS_NO_CALLBACK, NULL', 'FLT_PREOP_COMPLETE, NULL'),
            ('StageAttachComplete', 'if (NT_SUCCESS(Status) && cancelled) Status = STATUS_CANCELLED;', '(void)cancelled;'),
            ('StageAttachComplete', 'KeWaitForSingleObject(&Transaction->CancelCallbackExited,\n                Executive, KernelMode, FALSE, NULL);', '(void)Transaction;'),
            ('StageAttachCancelCallback', 'candidate->CallbackData == Data', 'candidate->CallbackData != Data'),
            ('StageAttachHasInstance', 'tx->InstanceIdentity == Instance', 'tx->InstanceIdentity == Instance && tx->CallbackData != NULL'),
            ('StageAttachQueueCreate', 'current->CallbackData == Data', 'FALSE'),
            ('StageAttachDrainTransaction', 'StageAttachReleaseRelatedObjects(Transaction);\n    lookupRemoved = StageAttachRemoveLookup(Transaction);',
             'lookupRemoved = StageAttachRemoveLookup(Transaction);\n    StageAttachReleaseRelatedObjects(Transaction);'),
        )
        for name, old, new in mutations:
            original = body(source, name)
            self.assertIn(old, original)
            changed = source.replace(original, original.replace(old, new))
            self.assertNotEqual(source, changed)
            with self.subTest(function=name, mutation=old):
                build, run = run_native(changed)
                self.assertEqual(0, build.returncode, build.stderr)
                self.assertNotEqual(0, run.returncode, run.stdout)

    def test_source_mutations_preserve_exact_barriers(self):
        source = PATH.read_text()
        mutations = (
            ('NT_ASSERT(!Transaction->CancelRegistered);', 'NT_ASSERT(TRUE);'),
            ('NT_ASSERT(data != NULL);', 'NT_ASSERT(TRUE);'),
            ('StageAttachFinishCallback(Transaction, FLT_PREOP_COMPLETE, NULL);',
             'FltCompletePendedPreOperation(Transaction->CallbackData, FLT_PREOP_COMPLETE, NULL);'),
            ('Transaction->CallbackData = NULL;', 'Transaction->CallbackData = NULL;\n    StageAttachReleaseActive();'),
            ('static VOID StageAttachFinishCallback(', '#pragma alloc_text(PAGE, StageAttachFinishCallback)\nstatic VOID StageAttachFinishCallback('),
        )
        for old, new in mutations:
            self.assertIn(old, source)
            with self.subTest(mutation=old), self.assertRaises((AssertionError, ValueError)):
                contract(source.replace(old, new))


if __name__ == '__main__':
    unittest.main(verbosity=2)
