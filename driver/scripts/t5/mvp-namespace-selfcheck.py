#!/usr/bin/env python3
"""Compile actual unbound namespace predicates/cancellation with cc and clang.

Host-only controls; not Windows, PREfast, grant or NTFS qualification.
All scratch lives in TMPDIR or the checkout's .scratch.
"""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
KERNEL = ROOT / 'driver/SafeUpload.Minifilter/StageStream.c'


def body(source, name):
    match = re.search(r'(?m)^static (?:BOOLEAN|NTSTATUS|FLT_PREOP_CALLBACK_STATUS|FLT_POSTOP_CALLBACK_STATUS) ' + name + r'\([^;]*?\)\s*\{', source)
    assert match, name
    end = source.index('{', match.start()) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end]


SHIM = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(c) do { if (!(c)) exit(97); } while(0)
typedef int BOOLEAN;
typedef int NTSTATUS;
typedef unsigned long ULONG;
#define TRUE 1
#define FALSE 0
#define NULLABLE
#define _In_
#define _In_opt_
#define _IRQL_requires_max_(x)
#define _IRQL_requires_(x)
#define PAGED_CODE() ((void)0)
#define FlagOn(a,b) ((a)&(b))
#define SAFEUPLOAD_STAGING_PROTOTYPE 1
#define BooleanFlagOn(a,b) (!!FlagOn(a,b))
#define FILE_WRITE_ATTRIBUTES 0x100
#define FILE_DELETE_CHILD 0x40
#define DELETE 0x10000
#define FILE_DELETE_ON_CLOSE 0x1000
#define FILE_CREATE 2
#define FILE_SUPERSEDE 0
#define FILE_OVERWRITE 4
#define FILE_OVERWRITE_IF 5
#define FILE_OPEN 1
#define FILE_OPEN_IF 3
#define FILE_WRITE_DATA 2
#define FILE_APPEND_DATA 4
#define FILE_WRITE_EA 16
#define GENERIC_WRITE 0x40000000u
#define GENERIC_ALL 0x10000000u
#define MAXIMUM_ALLOWED 0x02000000u
#define STAGE_LIMIT 128
#define STATUS_SUCCESS 0
#define STATUS_SHARING_VIOLATION -1
#define NT_SUCCESS(s) ((s)>=0)
#define SafeUploadVolumeFixed 1
typedef struct { unsigned DesiredAccess; } SECURITY;
typedef SECURITY *PIO_SECURITY_CONTEXT;
typedef struct { struct { struct { SECURITY *SecurityContext; unsigned Options; } Create; } Parameters; } IOPB;
typedef struct { IOPB *Iopb; } DATA, *PFLT_CALLBACK_DATA;
typedef const char **PUNICODE_STRING;
typedef struct { const char *Name; int protectedName, monitored; } NAME, *PFLT_FILE_NAME_INFORMATION;
static int sameScope;
static BOOLEAN SafeUploadStageProtectedName(NAME *n, int kind) { CHECK(kind==1);return n->protectedName; }
static BOOLEAN SafeUploadPolicySameProtectedScope(const char **a,const char **b) { CHECK(a&&b);return sameScope; }
static BOOLEAN SafeUploadPolicyMatchesExtension(const char **n) { return strstr(*n,".txt")!=NULL; }
typedef void *PFLT_INSTANCE;
typedef struct LIST { struct LIST *Flink,*Blink; } LIST_ENTRY,*PLIST_ENTRY;
typedef struct { int Detached; void *Current; } VIEW;
typedef struct STREAM {
    LIST_ENTRY Link; void *OriginalInstance;
    int Discarded,PrivateCancellationAccepted,Disposed,MvpPublicationObserved;
    const char *Name; int Resource;
    struct { unsigned OpenCount; } ShareAccess;
    void *RenameExchange;
    int AllocationRpcInFlight,SealRpcInFlight,SealRpcPending,PrivateCancellationBusy,BoundAllocation;
    int Sealed,DiscardDisposition,DiscardOnClose; VIEW *View; long RpcReferences;
} STAGE_STREAM,*PSTAGE_STREAM;
static LIST_ENTRY StageStreams;
static int StageNamespaceResource, resources, calls, queued, rpcFailure;
static struct { int WakeInline; } StageCounters;
#define CONTAINING_RECORD(p,t,m) ((t*)((char*)(p)-offsetof(t,m)))
static int RtlEqualUnicodeString(const char **a,const char **b,int ignore) { CHECK(ignore);return strcmp(*a,*b)==0; }
static void StageAcquire(int *r) { CHECK(!*r);*r=1;resources++; }
static void StageRelease(int *r) { CHECK(*r);*r=0;resources--; }
static long InterlockedIncrement(long *p) { return ++*p; }
static long InterlockedDecrement(long *p) { return --*p; }
static void StageQueueStream(STAGE_STREAM *s,int *counter) { CHECK(s&&counter);queued++; }
static int StageCancelSealedPrivate(STAGE_STREAM *s,int native) {
    CHECK(resources==0 && s->RpcReferences==1 && native);calls++;
    if(rpcFailure)return -9;
    s->PrivateCancellationAccepted=1;return 0;
}
/* PRODUCTION */
static void reset(STAGE_STREAM *rows, int count) {
    CHECK(resources==0); calls=queued=rpcFailure=0;
    StageStreams.Flink=StageStreams.Blink=&StageStreams;
    memset(rows,0,sizeof(*rows)*(size_t)count);
    for(int i=0;i<count;i++) {
        rows[i].OriginalInstance=(void*)1;rows[i].Name="source.txt";rows[i].Sealed=1;
        rows[i].Link.Flink=&StageStreams;rows[i].Link.Blink=StageStreams.Blink;
        StageStreams.Blink->Flink=&rows[i].Link;StageStreams.Blink=&rows[i].Link;
    }
}
int main(void) {
    SECURITY security={0};IOPB io={0};DATA data={&io};io.Parameters.Create.SecurityContext=&security;
    for(unsigned disposition=0;disposition<6;disposition++) {
        io.Parameters.Create.Options=disposition<<24;
        for(unsigned i=0;i<64;i++) {
            unsigned bits[]={FILE_WRITE_DATA,FILE_APPEND_DATA,FILE_WRITE_EA,GENERIC_WRITE,GENERIC_ALL,MAXIMUM_ALLOWED};
            security.DesiredAccess=0x10000u|0x100u|0x80u|0x20000u|0x100000u|1u; /* DELETE, attrs, READ_CONTROL, SYNCHRONIZE, READ_DATA */
            for(unsigned b=0;b<6;b++)if(i&(1u<<b))security.DesiredAccess|=bits[b];
            CHECK(StageMvpNamespaceOpen(&data)==((disposition==1||disposition==3)&&i==0));
            if(disposition==FILE_OPEN&&i==0)CHECK(!SafeUploadCreateIsWriter(&data));
            if(i!=0)CHECK(SafeUploadCreateIsWriter(&data));
        }
    }
    NAME source={"source.txt",1,1},target={"target.txt",1,1};
    sameScope=1;CHECK(!StageMvpRenameNeedsCopy(&source,&target));
    source.Name="source.bin";CHECK(StageMvpRenameNeedsCopy(&source,&target));
    target.protectedName=0;CHECK(!StageMvpRenameNeedsCopy(&source,&target));
    target.protectedName=1;source.Name="source.txt";sameScope=0;CHECK(StageMvpRenameNeedsCopy(&source,&target));
    const char *name="source.txt",*other="target.txt";STAGE_STREAM rows[3];
    reset(rows,2);CHECK(StageMvpCancelNames((void*)1,&name,NULL)==0);CHECK(calls==2);
    CHECK(rows[0].RpcReferences==0&&rows[1].RpcReferences==0);
    reset(rows,2);rows[1].ShareAccess.OpenCount=1;
    CHECK(StageMvpCancelNames((void*)1,&name,NULL)==-1);CHECK(calls==0);
    reset(rows,2);rows[1].Name="target.txt";rows[1].ShareAccess.OpenCount=1;
    CHECK(StageMvpCancelNames((void*)1,&name,&other)==-1);CHECK(calls==0);
    reset(rows,1);rpcFailure=1;CHECK(StageMvpCancelNames((void*)1,&name,NULL)==-9);CHECK(rows[0].RpcReferences==0);
    reset(rows,1);rows[0].Sealed=0;CHECK(StageMvpCancelNames((void*)1,&name,NULL)==0);
    CHECK(rows[0].DiscardOnClose&&rows[0].DiscardDisposition&&queued==1&&calls==0);
    reset(rows,1);rows[0].MvpPublicationObserved=1;CHECK(StageMvpCancelNames((void*)1,&name,NULL)==0&&calls==0);
    reset(rows,1);rows[0].SealRpcInFlight=1;CHECK(StageMvpCancelNames((void*)1,&name,NULL)==-1&&calls==0);
    CHECK(resources==0);return 0;
}
'''


class MvpNamespace(unittest.TestCase):
    def test_compiled_production_predicates_and_cancellation(self):
        source = KERNEL.read_text()
        production = '\n'.join(body(source, name) for name in
            ('StageMvpNamespaceOpen', 'StageMvpRenameNeedsCopy', 'StageMvpCancelNames'))
        production += '\n' + body((ROOT / 'driver/SafeUpload.Minifilter/Filter.c').read_text(), 'SafeUploadCreateIsWriter')
        scratch = Path(os.environ.get('TMPDIR', ROOT / '.scratch'))
        scratch.mkdir(exist_ok=True)
        for compiler in ('cc', 'clang'):
            self.assertIsNotNone(shutil.which(compiler))
            with tempfile.TemporaryDirectory(dir=scratch, prefix='mvp-namespace-') as temp:
                path = Path(temp) / 'shim.c'; path.write_text(SHIM.replace('/* PRODUCTION */', production))
                subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', str(path), '-o', str(path.with_suffix(''))], check=True)
                subprocess.run([str(path.with_suffix(''))], check=True)
                # Removing a content-write bit must fail a real compiled
                # control, rather than passing a source-string assertion.
                mutated = production.replace('FILE_APPEND_DATA | FILE_WRITE_EA |', 'FILE_APPEND_DATA |')
                self.assertNotEqual(mutated, production)
                path.write_text(SHIM.replace('/* PRODUCTION */', mutated))
                subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', str(path), '-o', str(path.with_suffix(''))], check=True)
                self.assertEqual(subprocess.run([str(path.with_suffix(''))]).returncode, 97)

    def test_native_route_and_final_fence_contract(self):
        source = KERNEL.read_text()
        native = body(source, 'StageMvpNamespacePre')
        self.assertIn('*Handled = TRUE;', native)
        self.assertIn('SafeUploadPreCreate(Data, Objects, CompletionContext)', native)
        self.assertIn('SafeUploadPostCreate(Data, Objects, legacyContext, Flags)', source)
        self.assertIn('StageMvpCancelNames(', native)
        self.assertIn('FLT_PREOP_SYNCHRONIZE;', native)
        # PREfast correction 7172c017 uses a dedicated completion tag. Keep
        # checking that its completion releases the actual interlocked fence.
        self.assertIn('*CompletionContext = (PVOID)&StageMvpNamespaceCompletionTag;', native)
        post = body(source, 'StagePostOperationCore')
        tagged = post.index('if (CompletionContext == (PVOID)&StageMvpNamespaceCompletionTag) {')
        finish = post.index('return FLT_POSTOP_FINISHED_PROCESSING;', tagged)
        self.assertIn('InterlockedExchange(&StageMvpNamespaceFence, 0);', post[tagged:finish])
        self.assertNotRegex(native, r'rename->\w+\s*=(?!=)')
        self.assertNotIn('STATUS_NOT_SUPPORTED', body(source, 'StageMvpRenameNeedsCopy'))
        core = body(source, 'StageDispatchCore')
        self.assertLess(core.index('StageMvpNamespacePre('), core.index('SafeUploadPreCreate('))
        guarded = re.findall(r'if \(KeGetCurrentIrql\(\) == PASSIVE_LEVEL\) \{([^{}]*)\}', core)
        namespace_calls = [block for block in guarded if 'StageMvpNamespacePre(' in block]
        self.assertEqual(len(namespace_calls), 2)
        for block in namespace_calls:
            self.assertLess(block.index('*CompletionContext = NULL;'), block.index('StageMvpNamespacePre('))
        create = body(source, 'StageCreate')
        self.assertIn('namespaceSequence != StageMvpNamespaceSequence', create)
        rename = body(source, 'StageRename')
        self.assertIn('namespaceSequence != StageMvpNamespaceSequence', rename)
        external = body(source, 'StageExternalRename')
        self.assertLess(external.index('&StageMvpNamespaceFence'), external.index('allow = SafeUploadPublicationRename'))
        publisher = (ROOT / 'agente/SafeUpload.Agent.Service/Interception/StagedTransferPublisher.cs').read_text()
        self.assertLess(publisher.index('CommitUnboundPublicationAsync('), publisher.index('StagedDestinationFile.CommitHandle('))


if __name__ == '__main__':
    unittest.main()
