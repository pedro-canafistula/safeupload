#!/usr/bin/env python3
"""Execute production Context.c lookup/allocation paths with a Filter Manager shim."""
from pathlib import Path
import importlib.util
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('retirement', Path(__file__).with_name('test_context_retirement.py'))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
PATH = ROOT / 'driver/SafeUpload.Minifilter/Context.c'
SHIM = r'''
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#undef assert
#define assert(x) do{if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);exit(97);}}while(0)
#define SAFEUPLOAD_STAGING_PROTOTYPE 1
#define PAGED_CODE() ((void)0)
#define NT_SUCCESS(s) ((s)>=0)
#define STATUS_SUCCESS 0
#define STATUS_NOT_FOUND (-1)
#define STATUS_NOT_SUPPORTED (-2)
#define STATUS_INSUFFICIENT_RESOURCES (-3)
#define STATUS_FLT_CONTEXT_ALREADY_DEFINED (-4)
#define FLT_STREAM_CONTEXT 1
#define FLT_SET_CONTEXT_KEEP_IF_EXISTS 1
#define NonPagedPool 1
#define NotificationEvent 1
#define FALSE 0
#define NULL_EVENT 0
#define Executive 0
#define KernelMode 0
#define InterlockedIncrement(p) (++*(p))
typedef int NTSTATUS;
typedef struct TOKEN {int ReferenceCount;} *PSAFEUPLOAD_INSTANCE_TEARDOWN_TOKEN;
typedef struct INSTANCE {PSAFEUPLOAD_INSTANCE_TEARDOWN_TOKEN TeardownToken;} *PSAFEUPLOAD_INSTANCE_CONTEXT;
typedef struct CONTEXT {
 int Lock,WriterLock,WriterObjects,WriterContextUsers,WriterContextRetired,WriterContextDetached,refs,attached;
 PSAFEUPLOAD_INSTANCE_TEARDOWN_TOKEN TeardownToken;
} SAFEUPLOAD_STREAM_CONTEXT,*PSAFEUPLOAD_STREAM_CONTEXT;
typedef void *PFLT_CONTEXT,*PFILE_OBJECT;
typedef struct {void *Filter,*Instance;} OBJECTS,*PCFLT_RELATED_OBJECTS;
static int association,SafeUploadStreamContextAssociationLock,allocations,frees,failAllocation,failSet,rechecks;
static int getError,supports=1;
static SAFEUPLOAD_STREAM_CONTEXT *attached,*setWinner;
static void FltAcquirePushLockShared(int *p){(void)p;assert(!association);association=1;}
static void FltReleasePushLock(int *p){(void)p;assert(association);association=0;}
static int FltSupportsStreamContexts(void *p){(void)p;return supports;}
static NTSTATUS FltGetStreamContext(void *i,void *f,void **c){(void)i;(void)f;assert(association);if(getError)return getError;*c=attached;if(!*c)return STATUS_NOT_FOUND;attached->refs++;return 0;}
static NTSTATUS FltAllocateContext(void *f,int type,size_t bytes,int pool,void **c){(void)f;(void)type;(void)pool;assert(!association);if(failAllocation)return -3;*c=calloc(1,bytes);allocations++;return 0;}
#define RtlZeroMemory(p,n) do{unsigned char *z=(void*)(p);for(size_t k=0;k<(n);k++)z[k]=0;((SAFEUPLOAD_STREAM_CONTEXT*)(p))->refs=1;}while(0)
static void FltInitializePushLock(int *p){*p=0;}
static void KeInitializeSpinLock(int *p){*p=0;}
static void InitializeListHead(int *p){*p=0;}
static NTSTATUS FltGetInstanceContext(void *i,void **p){(void)i;(void)p;assert(!association);return STATUS_NOT_FOUND;}
static void FltReleaseContext(void *p){assert(!association);SAFEUPLOAD_STREAM_CONTEXT *c=p;assert(c->refs>0);if(--c->refs==0){assert(!c->WriterContextUsers&&!c->attached);frees++;free(c);}}
static NTSTATUS FltSetStreamContext(void *i,void *f,int flags,void *c,void **old){(void)i;(void)f;(void)flags;assert(association);if(failSet)return -3;if(setWinner){attached=setWinner;setWinner=NULL;}if(attached){*old=attached;attached->refs++;return -4;}attached=c;attached->attached=1;attached->refs++;*old=NULL;return 0;}
static int SafeUploadStageWritersAcquireContextLease(SAFEUPLOAD_STREAM_CONTEXT *c){assert(association&&!c->WriterContextRetired);c->WriterContextUsers++;return 1;}
static int SafeUploadStageWritersContextRetired(SAFEUPLOAD_STREAM_CONTEXT *c){return c->WriterContextRetired;}
static void SafeUploadStageWritersReleaseContextLease(SAFEUPLOAD_STREAM_CONTEXT *c){assert(!association&&c->WriterContextUsers>0);if(--c->WriterContextUsers==0)rechecks++;}
static void KeInitializeEvent(int *p,int t,int state){(void)t;*p=state;}
static int KeWaitForSingleObject(int *e,int a,int b,int c,void *d){(void)e;(void)a;(void)b;(void)c;(void)d;assert(0);return 0;}
'''
MAIN = r'''
static void detach(void){SAFEUPLOAD_STREAM_CONTEXT *c=attached;assert(c&&!c->WriterContextUsers);attached=NULL;c->attached=0;FltReleaseContext(c);}
int main(void){
 (void)&SafeUploadStageWritersAcquireContextLease;(void)&SafeUploadStageWritersContextRetired;(void)&KeInitializeEvent;(void)&KeWaitForSingleObject;
 OBJECTS o={0};SAFEUPLOAD_STREAM_CONTEXT *c=(void*)1;
 supports=0;assert(SafeUploadGetOrCreateStreamContext(&o,NULL,&c)==-2&&!c);supports=1;
 getError=-5;assert(SafeUploadGetOrCreateStreamContext(&o,NULL,&c)==-5&&!c);getError=0;
 failAllocation=1;assert(SafeUploadGetOrCreateStreamContext(&o,NULL,&c)==-3&&!c);failAllocation=0;
 failSet=1;assert(SafeUploadGetOrCreateStreamContext(&o,NULL,&c)==-3&&!c);assert(allocations==frees);failSet=0;
 assert(SafeUploadGetOrCreateStreamContext(&o,NULL,&c)==0&&c==attached&&c->WriterContextUsers==1&&c->refs==2);
 SafeUploadReleaseStreamContext(c);assert(!c->WriterContextUsers&&rechecks==1&&c->refs==1);
 assert(SafeUploadGetOrCreateStreamContext(&o,NULL,&c)==0&&c->WriterContextUsers==1);
 SafeUploadReleaseStreamContext(c);detach();assert(allocations==frees);
 /* Competing setter wins while allocation/token work runs outside the lock.
  * The losing allocation must be destroyed after unlocking, winner leased. */
 setWinner=calloc(1,sizeof(*setWinner));allocations++;setWinner->attached=1;setWinner->refs=1;
 assert(SafeUploadGetOrCreateStreamContext(&o,NULL,&c)==0&&c==attached&&c->WriterContextUsers==1);
 SafeUploadReleaseStreamContext(c);detach();assert(allocations==frees&&!association);
 puts("lookup/create/set-race/failed allocation and final-release lock placement PASS");return 0;
}
'''


def program(source):
    body = r.w.body(source, 'SafeUploadGetOrCreateStreamContext')
    release = r.w.body(source, 'SafeUploadReleaseStreamContext')
    return SHIM + 'NTSTATUS SafeUploadGetOrCreateStreamContext(PCFLT_RELATED_OBJECTS FltObjects,PFILE_OBJECT FileObject,PSAFEUPLOAD_STREAM_CONTEXT *StreamContext)' + body + '\nvoid SafeUploadReleaseStreamContext(PSAFEUPLOAD_STREAM_CONTEXT StreamContext)' + release + MAIN


class LookupControl(unittest.TestCase):
    def run_control(self, source, expected=0):
        scratch = ROOT / '.scratch/ux-leak2/tmp'; scratch.mkdir(parents=True, exist_ok=True)
        for compiler in dict.fromkeys(filter(None, (shutil.which('cc'), shutil.which('clang')))):
            with tempfile.TemporaryDirectory(dir=scratch, prefix='context-lookup-') as temp:
                path=Path(temp); (path/'test.c').write_text(program(source))
                build=subprocess.run([compiler,'-std=c11','-Wall','-Wextra','-Werror','-fsanitize=undefined',str(path/'test.c'),'-o',str(path/'test')],capture_output=True,text=True)
                self.assertEqual(build.returncode,0,build.stderr)
                run=subprocess.run([str(path/'test')],capture_output=True,text=True,timeout=15)
                self.assertEqual(run.returncode,expected,run.stdout+run.stderr)

    def test_production_lookup_paths(self):
        self.run_control(PATH.read_text())

    def test_missing_lease_mutation_compiles_and_fails(self):
        self.run_control(PATH.read_text().replace('!SafeUploadStageWritersAcquireContextLease(existing)', 'existing == NULL'),97)

    def test_final_release_inside_association_mutation_compiles_and_fails(self):
        source=PATH.read_text().replace('    if (created != NULL && created != existing) FltReleaseContext(created);\n    *StreamContext', '    FltAcquirePushLockShared(&SafeUploadStreamContextAssociationLock);\n    if (created != NULL && created != existing) FltReleaseContext(created);\n    FltReleasePushLock(&SafeUploadStreamContextAssociationLock);\n    *StreamContext')
        self.run_control(source,97)

if __name__=='__main__': unittest.main()
