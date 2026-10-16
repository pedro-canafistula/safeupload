#!/usr/bin/env python3
"""Production bind/prune-cache/fence controls; no Windows/MM qualification."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('witness', ROOT / 'driver/scripts/t5/sop-witness-detach-selfcheck.py')
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)
PATH = ROOT / 'driver/SafeUpload.Minifilter/StageWriters.c'

EXTRA = r'''
#undef assert
#define assert(x) do { if(!(x)){fprintf(stderr,"assertion line %d: %s\n",__LINE__,#x);exit(97);} } while(0)
typedef void *PFLT_CONTEXT;
#define SAFEUPLOAD_INSTANCE_STATE_ACTIVE 1
#define IO_NO_INCREMENT 0
#define InterlockedIncrement64(p) (++*(p))
static long long RegistryChangeSequence;
static LONG SafeUploadStageWritersGlobalUnknown(void){return globalUnknown;}
static void SafeUploadStageAdmissionCoverageBegin(void){}
static void SafeUploadStageAdmissionCoverageEnd(void){}
static int contexts,deleted;
static void FltDeleteContext(PFLT_CONTEXT p){CONTEXT *c=p;assert(!registry&&!writer);
 assert(c->attached&&c->WriterContextRetired&&!c->WriterRegistryEntry&&!c->WriterSopLifetime);
 assert(!c->WriterObjects&&!c->WritersUntracked&&!c->WriterContextDetached);
 c->attached=0;contexts--;deleted++;}
static void KeSetEvent(int *p,int increment,int wait){(void)increment;(void)wait;
 assert(!registry&&!writer&&!*p);*p=1;}
typedef int NTSTATUS;
typedef void *PCFLT_RELATED_OBJECTS;
typedef struct { void *SectionObjectPointer; } FILE_OBJECT,*PFILE_OBJECT;
#define PAGED_CODE() ((void)0)
#define STATUS_SUCCESS 0
#define STATUS_INSUFFICIENT_RESOURCES (-1)
#define NT_SUCCESS(s) ((s)>=0)
static CONTEXT *lookupContext;
static void (*onLookup)(void);
static int lookupReleases;
static NTSTATUS SafeUploadGetOrCreateStreamContext(PCFLT_RELATED_OBJECTS o,PFILE_OBJECT f,CONTEXT **c){
 (void)o;(void)f;assert(!registry&&!writer);*c=lookupContext;
 if(onLookup){void(*hook)(void)=onLookup;onLookup=NULL;hook();}return 0;}
static void FltReleaseContext(void *p){assert(p&&!registry&&!writer);lookupReleases++;}
'''

MAIN = r'''
static TOKEN active={1};
static CONTEXT context(void){CONTEXT c={0};c.TeardownToken=&active;c.attached=1;contexts++;return c;}
static STAGE_REGISTRY_ENTRY *entry(void){STAGE_REGISTRY_ENTRY *e=calloc(1,sizeof(*e));allocations++;e->References=1;e->Listed=1;return e;}
static void retire(STAGE_REGISTRY_ENTRY *e){assert(!e->Retired);FltAcquirePushLockExclusive(&RegistryLock);
 e->Retired=1;e->Listed=0;StageRegistryRetireLifetimeLocked(e);FltReleasePushLock(&RegistryLock);}
static void finish(CONTEXT *c,STAGE_REGISTRY_ENTRY *e){retire(e);StageWritersReleasePrunedCache(c,e);StageWritersRetirePrunedContext(c,e);}
static CONTEXT *oldLookup,*nextLookup;
static STAGE_REGISTRY_ENTRY *lookupEntry;
static void retireDuringLookup(void){finish(oldLookup,lookupEntry);lookupContext=nextLookup;}
int main(void){
 (void)&FltDeleteContext;
 void *sop=(void*)123;
 /* Few public names, many distinct NTFS incarnations/hand-backs. Model NTFS
  * retaining every attachment forever: only production retirement bounds it. */
 for(int cycle=0;cycle<10000;cycle++){
  CONTEXT c=context();STAGE_REGISTRY_ENTRY *e=entry();
  assert(StageRegistryBindLifetime(e,&c,sop));finish(&c,e);
  assert(contexts==0&&c.WriterContextDetached&&c.WriterContextRetired&&!c.WriterRegistryCachePruned);
  assert(SafeUploadStageWritersContextRetired(&c));
  /* Repeat worker visits cannot delete an already unset context. */
  int before=deleted;StageWritersRetirePrunedContext(&c,e);assert(deleted==before);
  StageRegistryDereference(e);assert(allocations==frees);
 }
 assert(deleted==10000);
 /* Execute the production Get+Bind retry, including the pin obtained before
  * retirement. A real binding failure returns failure without retry/authority. */
 {CONTEXT old=context(),fresh=context();STAGE_REGISTRY_ENTRY *a=entry(),*b=entry();
 assert(StageRegistryBindLifetime(a,&old,sop));oldLookup=&old;nextLookup=&fresh;lookupEntry=a;
 lookupContext=&old;onLookup=retireDuringLookup;FILE_OBJECT file={sop};CONTEXT *result=NULL;
 int before=lookupReleases;assert(StageRegistryGetBoundContext(b,NULL,&file,&result)==0);
 assert(result==&fresh&&lookupReleases==before+1&&fresh.WriterSopLifetime&&!old.WriterSopLifetime);
 FltReleaseContext(result);finish(&fresh,b);StageRegistryDereference(a);StageRegistryDereference(b);}
 {CONTEXT c=context();STAGE_REGISTRY_ENTRY *e=entry();lookupContext=&c;
 FILE_OBJECT file={sop};CONTEXT *result=(void*)1;failAllocation=1;
 assert(StageRegistryGetBoundContext(e,NULL,&file,&result)==STATUS_INSUFFICIENT_RESOURCES&&!result);
 assert(!c.WriterSopLifetime&&!c.WriterContextRetired);c.WriterRegistryCachePruned=1;
 retire(e);StageWritersRetirePrunedContext(&c,e);StageRegistryDereference(e);}
 /* A new lookup may still hold the old pin: it cannot rebind or install a
  * witness after fencing. Fresh context binds instead; old worker is inert. */
 {CONTEXT old=context(),fresh=context();STAGE_REGISTRY_ENTRY *a=entry(),*b=entry();
 assert(StageRegistryBindLifetime(a,&old,sop));finish(&old,a);
 assert(!StageRegistryBindLifetime(b,&old,sop));assert(!b->SopLifetime);
 assert(StageRegistryBindLifetime(b,&fresh,sop));int before=deleted;
 StageWritersRetirePrunedContext(&old,a);assert(deleted==before&&fresh.attached);
 finish(&fresh,b);StageRegistryDereference(a);StageRegistryDereference(b);}
 /* Bind first wins under the same locks: a sibling owns the witness and
  * prevents both witness detach and context fencing. */
 {CONTEXT c=context();STAGE_REGISTRY_ENTRY *a=entry(),*b=entry();
 assert(StageRegistryBindLifetime(a,&c,sop));assert(StageRegistryBindLifetime(b,&c,sop));
 finish(&c,a);assert(c.attached&&!c.WriterContextRetired&&c.WriterSopLifetime);
 finish(&c,b);assert(!c.attached);StageRegistryDereference(a);StageRegistryDereference(b);}
 /* Each final fence veto stays held; no Unknown/invalid/teardown repair. */
 for(int which=0;which<10;which++){
  CONTEXT c=context();STAGE_REGISTRY_ENTRY *e=entry();assert(StageRegistryBindLifetime(e,&c,sop));
  retire(e);StageWritersReleasePrunedCache(&c,e);
  switch(which){case 0:c.WritersUntracked=1;break;case 1:c.WriterObjects=1;break;
   case 2:c.WriterSopLifetimeInvalid=1;break;case 3:c.WriterRegistryCachePruned=0;break;
   case 4:globalUnknown=1;break;case 5:teardown=1;break;case 6:c.TeardownToken=NULL;break;
   case 7:active.State=2;break;case 8:c.WriterRegistryEntry=e;break;case 9:e->UnknownReasons=1;break;}
  int before=deleted;StageWritersRetirePrunedContext(&c,e);
  assert(c.attached&&!c.WriterContextRetired&&deleted==before);
  /* Test teardown resets the injected veto only to reclaim fixture memory. */
  c.WritersUntracked=c.WriterObjects=c.WriterSopLifetimeInvalid=0;c.WriterRegistryCachePruned=1;
  c.TeardownToken=&active;active.State=1;c.WriterRegistryEntry=NULL;e->UnknownReasons=0;globalUnknown=teardown=0;
  StageWritersRetirePrunedContext(&c,e);assert(!c.attached);StageRegistryDereference(e);
 }
 /* Diagnostic and ordinary detach have one driver deletion owner in either
  * order; an invalidating diagnostic never fabricates a natural receipt. */
 {CONTEXT c=context();STAGE_REGISTRY_ENTRY *e=entry();
 assert(StageRegistryBindLifetime(e,&c,sop));finish(&c,e);int before=deleted;
 assert(!SafeUploadStageWritersInvalidateLifetime(&c));assert(globalUnknown);
 StageWritersRetirePrunedContext(&c,e);assert(deleted==before);globalUnknown=0;StageRegistryDereference(e);}
 {CONTEXT c=context();STAGE_REGISTRY_ENTRY *e=entry();retire(e);c.WriterRegistryCachePruned=1;
 assert(SafeUploadStageWritersInvalidateLifetime(&c));assert(!SafeUploadStageWritersInvalidateLifetime(&c));
 StageWritersRetirePrunedContext(&c,e);assert(c.attached&&!c.WriterContextRetired&&globalUnknown);
 /* The diagnostic owner would detach this invalid cache, not the worker. */
 c.attached=0;contexts--;globalUnknown=0;StageRegistryDereference(e);}
 assert(contexts==0&&allocations==frees&&!asserts);
 puts("10000 contexts retired; sibling/race/Unknown vetoes PASS");return 0;
}
'''


def program(source):
    sop = source[source.index('typedef struct _STAGE_SOP_LIFETIME'):source.index('} STAGE_SOP_LIFETIME, *PSTAGE_SOP_LIFETIME;') + len('} STAGE_SOP_LIFETIME, *PSTAGE_SOP_LIFETIME;')]
    types = w.TYPES.replace('typedef struct CONTEXT {', 'typedef struct { LONG State; } TOKEN;\ntypedef struct CONTEXT {')
    types = types.replace('LONG WritersUntracked; int WriterObjects;',
                          'LONG WritersUntracked; int WriterObjects,WriterContextDetached,attached; TOKEN *TeardownToken;')
    # Public definition: the old helper's extractor starts at the last static
    # prefix. Select the public accessor explicitly instead.
    def public(name):
        body = w.body(source, name)
        at = w.t.strip_code(source).index(body)
        start = source.rfind('BOOLEAN ' + name, 0, at)
        return source[start:at + len(body)].replace('_In_', '').replace('_Inout_', '')
    definitions = '\n'.join(w.definition(source, name) for name in w.NAMES + ('StageWritersRetirePrunedContext',))
    definitions += public('SafeUploadStageWritersContextRetired') + public('SafeUploadStageWritersInvalidateLifetime')
    definitions += w.definition(source, 'StageRegistryGetBoundContext').replace('_Outptr_result_nullonfailure_', '')
    return w.SHIM + sop + types + EXTRA + definitions + MAIN


class ContextRetirement(unittest.TestCase):
    def run_control(self, source, expected):
        scratch = ROOT / '.scratch/ux-leak/tmp'
        scratch.mkdir(parents=True, exist_ok=True)
        for compiler in dict.fromkeys(filter(None, (shutil.which('cc'), shutil.which('clang')))):
            with tempfile.TemporaryDirectory(dir=scratch, prefix='context-retire-') as temp:
                path = Path(temp); (path/'test.c').write_text(program(source))
                result = subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror',
                                         '-fsanitize=undefined', str(path/'test.c'), '-o', str(path/'test')], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                result = subprocess.run([str(path/'test')], capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)

    def test_ten_thousand_and_races(self):
        self.run_control(PATH.read_text(), 0)

    def test_pre_fix_context_retention_fails(self):
        source = PATH.read_text().replace('FltDeleteContext((PFLT_CONTEXT)Context);', '(void)Context;')
        self.run_control(source, 97)

    def test_rebinding_retired_context_fails(self):
        source = PATH.read_text()
        body = w.body(source, 'StageRegistryBindLifetime')
        at = w.t.strip_code(source).index(body)
        region = source[at:at + len(body)]
        self.assertIn('&& !Context->WriterContextRetired &&', region)
        self.run_control(source[:at] + region.replace('&& !Context->WriterContextRetired &&', '&&') +
                         source[at + len(body):], 97)

    def test_product_wiring(self):
        source = PATH.read_text()
        fence = w.body(source, 'StageWritersRetirePrunedContext')
        self.assertLess(fence.index('FltReleasePushLock'), fence.index('FltDeleteContext'))
        self.assertLess(fence.index('FltDeleteContext'), fence.index('KeSetEvent'))
        self.assertNotIn('Ended', fence)
        self.assertNotIn('PAGED_CODE', fence)
        self.assertIn('if (StreamContext->WriterContextRetired)', w.body(source, 'StageWritersInsertNode'))
        self.assertIn('if (!streamContext->WriterContextRetired)', w.body(source, 'StageRegistryTrackUnknownWriter'))
        self.assertIn('streamContext->WriterContextRetired', w.body(source, 'SafeUploadStageWritersSnapshot'))
        self.assertIn('!StreamContext->WriterContextRetired', w.body(source, 'SafeUploadStageWritersFreeContext'))
        context = (PATH.parent/'Context.c').read_text()
        lookup = context[context.index('SafeUploadGetOrCreateStreamContext (', context.index('Stream context.')):]
        self.assertIn('KeInitializeEvent(&created->WriterContextDetached', lookup)
        self.assertIn('KeWaitForSingleObject(&existing->WriterContextDetached', lookup)
        self.assertNotIn('FltDeleteContext', lookup)
        bound = w.body(source, 'StageRegistryGetBoundContext')
        self.assertIn('SafeUploadStageWritersContextRetired(context)', bound)
        self.assertIn('PAGED_CODE()', bound)
        self.assertLess(source.index('#pragma alloc_text(PAGE, StageRegistryGetBoundContext)'),
                        w.t.strip_code(source).index(bound))


if __name__ == '__main__':
    unittest.main()
