#!/usr/bin/env python3
"""10k persistence defect: actual native retry loop + source mutations; no VM verdict."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('teardown', Path(__file__).with_name('teardown-participation-selfcheck.py'))
teardown = importlib.util.module_from_spec(spec); spec.loader.exec_module(teardown)


def sources():
    agent = ROOT / 'agente/SafeUpload.Agent.Service/Interception'
    result = {p: (agent / p).read_text() for p in (
        'StagedJournalReplacement.cs', 'StagedTransferJournal.cs', 'StagedJournalFile.cs',
        'MinifilterInterceptor.cs', 'StagedDestinationFile.cs')}
    for p in ('StageStream.c', 'StageProtocol.c'):
        result[p] = (ROOT / 'driver/SafeUpload.Minifilter' / p).read_text()
    return result


def contract(src):
    def require(value):
        if not value: raise AssertionError('manifest persistence retry contract')
    def body(file, name): return teardown.body(file, name, src)
    replace = body('StagedJournalReplacement.cs', 'ReplaceAsync')
    for guard in ('attempt < MaximumAttempts - 1 && IsTransientRename(error)',
                  'token.ThrowIfCancellationRequested()', 'try { replace(); return; }',
                  'TimeSpan.FromMilliseconds(20 << attempt)'):
        require(guard in replace)
    require('MaximumAttempts = 6;' in src['StagedJournalReplacement.cs'])
    require('error.InnerException is Win32Exception { NativeErrorCode: 5 or 32 or 33 }' in src['StagedJournalReplacement.cs'])
    commit = body('StagedJournalReplacement.cs', 'CommitAsync')
    require(commit.index('stream.Flush(flushToDisk: true)') < commit.index('await ReplaceAsync('))
    require('StagedDestinationFile.CommitHandle(stream.SafeFileHandle, destination)' in commit)
    journal = body('StagedTransferJournal.cs', 'ReplaceAsync')
    require(journal.index('await StagedJournalReplacement.CommitAsync') < journal.index('replacementReturned = true;'))
    require('new StagedJournalPersistenceException' in journal and 'ForgetScanned(entry.Transfer.TransferId)' in journal)
    require('StagedJournalReplacement' not in src['StagedDestinationFile.cs'])  # No public-mutation retry.
    reader = body('StagedJournalFile.cs', 'Open')
    require('writable ? 1U : 5U' in reader)
    require('writable ? FileShare.Read : FileShare.Read | FileShare.Delete' in reader)
    handler = src['MinifilterInterceptor.cs']
    for guard in ('request.Operation is Operation.StageAttachCommit or Operation.StageCompletionPermit &&',
                  'ex is StagedJournalPersistenceException', 'retry.Result = StageV20Result.RetryableFailure'):
        require(guard in handler)
    retry = body('StageStream.c', 'StageAttachExchangeRetry')
    require('for (;;) {' in retry and retry.count('StageAttachRetryAllowed(Transaction)') >= 4)
    require('persistenceAttempt == 5) break;' in retry)
    require('20U << persistenceAttempt' in retry and '++persistenceAttempt;' in retry)
    require(retry.count('InterlockedCompareExchange(&Transaction->CancelRequested, 0, 0) != 0') >= 3)
    require('InterlockedIncrement64' not in retry and 'Request->RequestId =' not in retry.replace('Request->RequestId ==', ''))
    # The actual host-C run below also enforces no wait with Namespace held.
    require(retry.index('StageRelease(&StageNamespaceResource);', retry.index('for (;;)')) <
            retry.index('KeDelayExecutionThread('))


SHIM = r'''
#include <assert.h>
#include <stdlib.h>
/* Negative controls exit without generating host core dumps. */
#undef assert
#define assert(condition) ((condition) ? (void)0 : exit(97))
#include <stdint.h>
#include <stddef.h>
typedef void VOID; typedef int NTSTATUS,BOOLEAN,LONG; typedef uint32_t ULONG,UINT32,*PUINT32;
typedef int64_t LONGLONG; typedef struct {LONGLONG QuadPart;} LARGE_INTEGER;
typedef struct {UINT32 RequestId;} REQUEST,*PSAFEUPLOAD_REQUEST;
typedef struct {UINT32 OwnerProcessId;} VIEW;
typedef struct {VIEW *View;BOOLEAN AttachPrepareKnown,AttachCompletionMayExist,AttachCompletionKnown,
 AttachCommitKnown,AttachPrepareMayExist,AttachCommitMayExist;UINT32 AttachCommitResult;} STREAM,*PSTAGE_STREAM;
typedef struct {STREAM *Stream;LONG CancelRequested,TeardownRequested;
 BOOLEAN UnexposedRetirementAllowed,ServiceRequestMayExist;} TRANSACTION,*PSTAGE_ATTACH_TRANSACTION;
#define TRUE 1
#define FALSE 0
#define STATUS_SUCCESS 0
#define STATUS_DEVICE_BUSY -1
#define STATUS_CANCELLED -2
#define STATUS_ACCESS_DENIED -3
#define STATUS_PORT_DISCONNECTED -4
#define STATUS_INVALID_PARAMETER -5
#define STATUS_VOLUME_DISMOUNTED -6
#define STATUS_INVALID_DEVICE_STATE -7
#define STATUS_INVALID_BUFFER_SIZE -8
#define SAFEUPLOAD_OPERATION_STAGE_ATTACH_PREPARE 12
#define SAFEUPLOAD_OPERATION_STAGE_ATTACH_COMMIT 13
#define SAFEUPLOAD_OPERATION_STAGE_ATTACH_ABORT 14
#define SAFEUPLOAD_OPERATION_STAGE_ATTACH_COMPLETION_PERMITTED 15
#define SAFEUPLOAD_OPERATION_STAGE_RETIRE_UNEXPOSED 16
#define SAFEUPLOAD_OPERATION_STAGE_RETIRE_ATTACHED_PRIVATE 18
#define SAFEUPLOAD_OPERATION_STAGE_ATTACH_HANDLE_OBSERVED 19
#define SAFEUPLOAD_STAGE_RESULT_ATTACH_PREPARED 6
#define SAFEUPLOAD_STAGE_RESULT_ATTACH_COMMITTED 7
#define SAFEUPLOAD_STAGE_RESULT_ATTACH_COMMIT_DENIED 8
#define SAFEUPLOAD_STAGE_RESULT_ATTACH_ABORTED 9
#define SAFEUPLOAD_STAGE_RESULT_ATTACH_ALREADY_COMMITTED 10
#define SAFEUPLOAD_STAGE_RESULT_ATTACH_RETIRED_UNEXPOSED 12
#define SAFEUPLOAD_STAGE_RESULT_ATTACH_RETIRED_PRIVATE 15
#define SAFEUPLOAD_STAGE_RESULT_COMPLETION_PERMITTED 16
#define SAFEUPLOAD_STAGE_RESULT_HANDLE_OBSERVED 17
#define SAFEUPLOAD_STAGE_RESULT_RETRYABLE_FAILURE 19
#define NT_ASSERT assert
#define PASSIVE_LEVEL 0
#define KernelMode 0
#define KeGetCurrentIrql() 0
#define InterlockedCompareExchange(p,v,c) (*(p))
static int mandatory,allowed,calls,waits,namespaceDepth,stopAfterWait,retryCount,mode;
static LONGLONG previousWait;
static UINT32 originalId,issuedSequence;
static int StageNamespaceResource;
#define SafeUploadStageMandatoryTeardownActive() mandatory
#define SafeUploadStageProtocolIsReady() allowed
#define StageAttachRetryAllowed(t) (allowed && !(t)->CancelRequested && !(t)->TeardownRequested)
static void StageAcquire(int *p){(void)p;assert(!namespaceDepth);namespaceDepth++;}
static void StageRelease(int *p){(void)p;assert(namespaceDepth==1);namespaceDepth--;}
static NTSTATUS exchange(REQUEST *r,UINT32 *out,BOOLEAN *may){
 assert(!namespaceDepth);assert(++calls<20);*may=TRUE;
 if(!r->RequestId)r->RequestId=++issuedSequence;
 if(!originalId)originalId=r->RequestId;
 assert(originalId==r->RequestId);
 if(mode==1){*out=0;return STATUS_ACCESS_DENIED;}
 if(mode==2){*out=0;return STATUS_DEVICE_BUSY;}
 if(mode==3){*out=SAFEUPLOAD_STAGE_RESULT_RETRYABLE_FAILURE;return STATUS_ACCESS_DENIED;}
 if(calls<=retryCount){*out=SAFEUPLOAD_STAGE_RESULT_RETRYABLE_FAILURE;return STATUS_DEVICE_BUSY;}
 *out=SAFEUPLOAD_STAGE_RESULT_ATTACH_COMMITTED;return STATUS_SUCCESS;
}
#define SafeUploadStageAttachmentExchangeV20(owner,name,volume,op,tid,gen,stage,driver,parent,r,o,m) exchange(r,o,m)
static NTSTATUS KeDelayExecutionThread(int modeValue,BOOLEAN alert,LARGE_INTEGER *interval){
 assert(modeValue==KernelMode&&!alert&&!namespaceDepth);++waits;
 LONGLONG ms=-(interval->QuadPart)/(10*1000);assert(ms>=20&&ms<=320);
 assert(ms==(previousWait? (previousWait<320?previousWait*2:320):20));previousWait=ms;
 if(waits==stopAfterWait)allowed=FALSE;
 if(stopAfterWait==-1)mandatory=TRUE;
 return STATUS_SUCCESS;
}
static BOOLEAN StageProtocolStatusResultValid(UINT32 Operation,UINT32 Result)
'''

CASES = r'''
static void reset(void){mandatory=0;allowed=1;calls=waits=namespaceDepth=0;
 stopAfterWait=0;retryCount=3;mode=0;previousWait=0;originalId=0;issuedSequence=70;}
int main(void){
 assert(StageProtocolStatusResultValid(13,SAFEUPLOAD_STAGE_RESULT_RETRYABLE_FAILURE));
 assert(StageProtocolStatusResultValid(15,SAFEUPLOAD_STAGE_RESULT_RETRYABLE_FAILURE));
 assert(!StageProtocolStatusResultValid(12,SAFEUPLOAD_STAGE_RESULT_RETRYABLE_FAILURE));
 assert(!StageProtocolStatusResultValid(14,SAFEUPLOAD_STAGE_RESULT_RETRYABLE_FAILURE));
 assert(!StageProtocolStatusResultValid(13,UINT32_MAX));
 for(UINT32 op=13;op<=15;op+=2){
  VIEW v={77};STREAM s={0};s.View=&v;TRANSACTION t={0};t.Stream=&s;
  REQUEST r={0};UINT32 out=0;reset();
  assert(StageAttachExchangeRetry(&t,op,&r,&out)==STATUS_SUCCESS);
  assert(calls==4&&waits==3&&out==SAFEUPLOAD_STAGE_RESULT_ATTACH_COMMITTED&&r.RequestId==71);
  assert(t.ServiceRequestMayExist&&(op==13?s.AttachCommitMayExist:s.AttachCompletionMayExist));
  reset();retryCount=100;
  assert(StageAttachExchangeRetry(&t,op,&r,&out)==STATUS_DEVICE_BUSY);
  assert(calls==6&&waits==5&&previousWait==320&&out==SAFEUPLOAD_STAGE_RESULT_RETRYABLE_FAILURE);
  assert(t.ServiceRequestMayExist&&(op==13?s.AttachCommitMayExist:s.AttachCompletionMayExist));
  reset();stopAfterWait=1;
  assert(StageAttachExchangeRetry(&t,op,&r,&out)==STATUS_CANCELLED);assert(calls==1&&waits==1);
  reset();stopAfterWait=-1;
  assert(StageAttachExchangeRetry(&t,op,&r,&out)==STATUS_PORT_DISCONNECTED);assert(calls==1&&waits==1);
  reset();mode=1;assert(StageAttachExchangeRetry(&t,op,&r,&out)==STATUS_ACCESS_DENIED);assert(calls==1&&!waits);
  reset();mode=2;assert(StageAttachExchangeRetry(&t,op,&r,&out)==STATUS_DEVICE_BUSY);assert(calls==1&&!waits);
  reset();mode=3;assert(StageAttachExchangeRetry(&t,op,&r,&out)==STATUS_ACCESS_DENIED);assert(calls==1&&!waits);
 }
 VIEW v={77};STREAM s={0};s.View=&v;TRANSACTION t={0};t.Stream=&s;
 REQUEST r={0};UINT32 out=0;reset();
 assert(StageAttachExchangeRetry(&t,19,&r,&out)==STATUS_DEVICE_BUSY);assert(calls==1&&!waits);
 return 0;
}
'''


def run_native(src):
    status = teardown.body('StageProtocol.c', 'StageProtocolStatusResultValid', src)
    retry = teardown.body('StageStream.c', 'StageAttachExchangeRetry', src)
    source = SHIM + status + '\nstatic NTSTATUS StageAttachExchangeRetry(TRANSACTION *Transaction, UINT32 Operation, REQUEST *Request, UINT32 *Result)\n' + retry + CASES
    with tempfile.TemporaryDirectory(prefix='t5-manifest-retry-') as directory:
        path = Path(directory); (path / 'test.c').write_text(source)
        build = subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                                str(path / 'test.c'), '-o', str(path / 'test')], capture_output=True, text=True)
        if build.returncode: return build, None
        return build, subprocess.run([str(path / 'test')], cwd=path, capture_output=True, text=True, timeout=5)


class ManifestRetry(unittest.TestCase):
    def test_source_contract(self): contract(sources())

    def test_actual_native_retry_and_runtime_mutations(self):
        src = sources(); build, run = run_native(src)
        self.assertEqual(0, build.returncode, build.stderr); self.assertEqual(0, run.returncode, run.stderr)
        mutations = [
            ('StageProtocol.c', 'Result == SAFEUPLOAD_STAGE_RESULT_ATTACH_ALREADY_COMMITTED ||\n            Result == SAFEUPLOAD_STAGE_RESULT_RETRYABLE_FAILURE', 'Result == SAFEUPLOAD_STAGE_RESULT_ATTACH_ALREADY_COMMITTED'),
            ('StageProtocol.c', 'Result == SAFEUPLOAD_STAGE_RESULT_COMPLETION_PERMITTED ||\n            Result == SAFEUPLOAD_STAGE_RESULT_RETRYABLE_FAILURE', 'Result == SAFEUPLOAD_STAGE_RESULT_COMPLETION_PERMITTED'),
            ('StageStream.c', 'persistenceAttempt == 5) break;', 'FALSE) break;'),
            ('StageStream.c', '20U << persistenceAttempt', '20U'),
            ('StageStream.c', 'if (!StageAttachRetryAllowed(Transaction) ||', 'if (FALSE ||'),
            ('StageStream.c', '*Result != SAFEUPLOAD_STAGE_RESULT_RETRYABLE_FAILURE', 'FALSE'),
            ('StageStream.c', 'status != STATUS_DEVICE_BUSY ||', 'FALSE ||'),
            ('StageStream.c', 'if (SafeUploadStageMandatoryTeardownActive()) return STATUS_PORT_DISCONNECTED;', 'if (FALSE) return STATUS_PORT_DISCONNECTED;'),
            ('StageStream.c', 'if (requestMayExist) {', 'if (FALSE) {'),
            ('StageStream.c', 'requestMayExist = FALSE;\n        *Result = 0;', 'requestMayExist = FALSE;\n        Request->RequestId = 0;\n        *Result = 0;'),
            ('StageStream.c', '(VOID)KeDelayExecutionThread(KernelMode, FALSE, &persistenceRetryInterval);', 'StageAcquire(&StageNamespaceResource);\n        (VOID)KeDelayExecutionThread(KernelMode, FALSE, &persistenceRetryInterval);'),
            ('StageStream.c', '(Operation != SAFEUPLOAD_OPERATION_STAGE_ATTACH_COMMIT &&\n             Operation != SAFEUPLOAD_OPERATION_STAGE_ATTACH_COMPLETION_PERMITTED)', 'FALSE'),
        ]
        for file, old, new in mutations:
            self.assertIn(old, src[file]); changed = dict(src); changed[file] = changed[file].replace(old, new)
            with self.subTest(fault=old):
                build, run = run_native(changed)
                self.assertEqual(0, build.returncode, build.stderr)
                self.assertNotEqual(0, run.returncode, run.stderr)

    def test_each_source_mutation_is_caught(self):
        src = sources(); contract(src)
        mutations = [
            ('StagedJournalReplacement.cs', 'MaximumAttempts = 6', 'MaximumAttempts = 600'),
            ('StagedJournalReplacement.cs', 'attempt < MaximumAttempts - 1 && IsTransientRename(error)', 'true'),
            ('StagedJournalReplacement.cs', 'try { replace(); return; }', 'try { replace(); }'),
            ('StagedJournalReplacement.cs', 'NativeErrorCode: 5 or 32 or 33', 'NativeErrorCode: 5 or 32 or 33 or 87'),
            ('StagedTransferJournal.cs', 'await StagedJournalReplacement.CommitAsync', 'await UncalledReplacement.CommitAsync'),
            ('StagedJournalFile.cs', 'writable ? 1U : 5U', 'writable ? 1U : 1U'),
            ('StagedJournalFile.cs', 'writable ? FileShare.Read : FileShare.Read | FileShare.Delete', 'FileShare.ReadWrite | FileShare.Delete'),
            ('MinifilterInterceptor.cs', 'ex is StagedJournalPersistenceException', 'ex is IOException'),
        ]
        for file, old, new in mutations:
            self.assertIn(old, src[file]); changed = dict(src); changed[file] = changed[file].replace(old, new)
            with self.subTest(fault=old), self.assertRaises((AssertionError, ValueError)): contract(changed)


if __name__ == '__main__': unittest.main()
