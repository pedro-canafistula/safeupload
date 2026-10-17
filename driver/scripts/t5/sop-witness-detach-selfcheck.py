#!/usr/bin/env python3
"""Execute production SOP bind/detach/retirement bodies with deterministic owners.
Host shims do not qualify Filter Manager, spin hold time, IRQL or native races.
"""
import importlib.util
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
PATH = ROOT / 'driver/SafeUpload.Minifilter/StageWriters.c'
spec = importlib.util.spec_from_file_location('teardown', Path(__file__).with_name('teardown-participation-selfcheck.py'))
t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)

NAMES = ('StageRegistryLifetime', 'StageRegistryReleaseLifetime', 'StageRegistryLifetimeViolation',
         'StageRegistryRetireLifetimeLocked', 'StageRegistryDereference',
         'StageWritersReleasePrunedCache', 'StageRegistryBindLifetime')


def body(s, name): return t.body('StageWriters.c', name, {'StageWriters.c': s})


def definition(s, name):
    b = body(s, name)
    # Bodies have the same positions after comment/string stripping.
    at = t.strip_code(s).index(b)
    start = s.rfind('\n', 0, s.rfind('\n', 0, at)) + 1
    # Multi-line signatures: find the actual static definition prefix.
    start = s.rfind('static ', 0, at)
    prefix = s[start:at].replace('__declspec(noinline)', '')
    prefix = re.sub(r'_In_opt_|_In_', '', prefix)
    return prefix + s[at:at + len(b)]


def contract(s):
    bind = body(s, 'StageRegistryBindLifetime'); detach = body(s, 'StageWritersReleasePrunedCache')
    retire = body(s, 'StageRegistryRetireLifetimeLocked'); destroy = body(s, 'StageRegistryDereference')
    violation = body(s, 'StageRegistryLifetimeViolation')
    assert 'LONG NonRetiredBindings;' in s
    assert 'C_ASSERT(sizeof(STAGE_SOP_LIFETIME) == 24)' in s
    assert 'SAFEUPLOAD_WRITER_REGISTRY_ALL_LIMIT' in bind and 'SAFEUPLOAD_WRITER_REGISTRY_ALL_LIMIT' in retire
    assert 'InterlockedExchange(&Lifetime->Invalid, 1)' in violation
    assert 'StageRegistryPublishGlobalUnknown(SAFEUPLOAD_REGISTRY_UNKNOWN_CLEANUP)' in violation
    assert 'NT_ASSERT(lifetime == NULL || Entry->Retired)' in destroy
    assert 'if (lifetime != NULL && !Entry->Retired) StageRegistryLifetimeViolation(lifetime)' in destroy
    # Only initialization, CAS winner and the guarded retirement helper mutate the count.
    writes = re.findall(r'(?:\+\+|--)\w+->NonRetiredBindings|\w+->NonRetiredBindings\s*=(?!=)\s*[^;]+;', t.strip_code(s))
    assert writes == ['--lifetime->NonRetiredBindings', 'fresh->NonRetiredBindings = 0;', '++lifetime->NonRetiredBindings'], writes
    assert 'if (existing == NULL) ++lifetime->NonRetiredBindings;' in bind
    for part in ('Entry->Listed && !Entry->Retired && !Entry->Transient',
                 'retry = lifetime == NULL && fresh == NULL && allocationSkipped',
                 'if (!retry) return valid;', '!Context->WriterSopLifetimeInvalid',
                 '!SafeUploadStageMandatoryTeardownActive()', 'lifetime->Sop == Sop',
                 '&lifetime->Invalid, 0, 0) == 0', '&lifetime->Ended, 0, 0) == 0'):
        assert part in bind, part
    assert bind.index('FltAcquirePushLockExclusive(&RegistryLock)') < bind.index('lifetime = (PSTAGE_SOP_LIFETIME)Context->WriterSopLifetime')
    for region in (bind[bind.index('FltAcquirePushLockExclusive'):], detach):
        a = region.index('FltAcquirePushLockExclusive(&RegistryLock)')
        b = region.index('StageAcquireSpinLock', a)
        c = region.index('StageReleaseSpinLock', b)
        d = region.index('FltReleasePushLock(&RegistryLock)', c)
        assert a < b < c < d
        critical = region[b:c]
        assert not re.search(r'\b(?:for|while)\s*\(', critical)
        for forbidden in ('for (', 'while (', 'RegistryEntries', 'ExAllocatePool', 'FltObject', 'KeDelay', 'SectionLock', 'StateLock'):
            assert forbidden not in critical, forbidden
    for part in ('Entry->Retired && !Entry->Listed', 'lifetime == StageRegistryLifetime(Entry)',
                 'lifetime->NonRetiredBindings == 0', '!StreamContext->WriterSopLifetimeInvalid',
                 '&lifetime->Invalid, 0, 0) == 0', 'IsListEmpty(&StreamContext->WriterObjects)',
                 '&StreamContext->WritersUntracked, 0, 0) == 0'):
        assert part in detach, part
    assert detach.index('FltReleasePushLock') < detach.index('StageRegistryReleaseLifetime(detached)') < detach.index('StageRegistryDereference(released)')
    # Preserve the exact preexisting cache proof, including Unknown/H/W/T, independently of detach.
    cache = detach[detach.index('if (StreamContext->WriterRegistryEntry == Entry'):detach.index('lifetime = (PSTAGE_SOP_LIFETIME)')]
    for part in ('Entry->Retired', 'IsListEmpty', '&StreamContext->WritersUntracked', '&Entry->UnknownReasons', '&Entry->H', '&Entry->W', '&Entry->T', 'WriterRegistryCachePruned = TRUE'):
        assert part in cache
    for part in ('lifetime->NonRetiredBindings <= 0', 'StageRegistryLifetimeViolation(lifetime)', 'else --lifetime->NonRetiredBindings'):
        assert part in retire
    # Exactly two live retirement writes; decrement adjacent to each and under RegistryLock.
    assert len(re.findall(r'->Retired\s*=\s*TRUE', s)) == 2
    assert not re.search(r'->Retired\s*=\s*FALSE', s)
    assert len(re.findall(r'RtlZeroMemory\((?:entry|Entry),', s)) == 3
    assert len(re.findall(r'StageRegistryRetireLifetimeLocked\((?:entry|Entry)\);', s)) == 2
    for name, entry in (('StageRegistryPruneLocked', 'Entry'), ('StageRegistryRetireInstance', 'entry')):
        region = body(s, name)
        assert f'{entry}->Retired = TRUE;\n' in region
        a = region.index(f'{entry}->Retired = TRUE;')
        assert f'StageRegistryRetireLifetimeLocked({entry});' in region[a:a+110]
    worker = body(s, 'StageRegistryReclaimWorker')
    assert worker.index('if (pruned)') < worker.index('StageWritersReleasePrunedCache(streamContext, entry)')
    prune = body(s, 'StageRegistryPruneLocked')
    for part in ('!Entry->Listed || Entry->Retired', 'SAFEUPLOAD_REGISTRY_STATE_UNKNOWN',
                 'SafeUploadStageWritersOwnerCount() != 0', '&Entry->H', '&Entry->W', '&Entry->T',
                 '&Entry->RenameInFlight', 'StageRegistryDirectoryRenameInFlightLocked', 'InterlockedCompareExchange(&Entry->UnknownReasons, 0, 0) != 0)', 'RegistryReservations',
                 'TransactionAssociations', 'EvidenceSequence !=', '&lifetime->Invalid',
                 'SafeUploadStageWritersGlobalUnknown() != 0', 'StageRegistryOldIncarnationResolvedLocked',
                 'SectionSlots[index].FileObject != NULL', 'map->UnknownWriterCount', 'map->SpilledMutatingIoCount'):
        assert part in prune, part
    # End only at context cleanup; detach never publishes End or clears sticky state.
    assert 'for (' not in detach and 'while (' not in detach
    assert 'Ended' not in detach and 'InterlockedExchange(&lifetime->Invalid, 0)' not in s
    assert 'StageRegistryRetireLifetimeLocked' not in body(s, 'SafeUploadStageWritersFreeContext')
    assert 'StageRegistryRetireLifetimeLocked' not in destroy


SHIM = r'''
#include <assert.h>
#include <stdlib.h>
/* Negative controls exit without generating host core dumps. */
#undef assert
#define assert(condition) ((condition) ? (void)0 : exit(97))
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
typedef int32_t LONG; typedef void VOID,*PVOID; typedef int BOOLEAN,KIRQL;
#define TRUE 1
#define FALSE 0
#define PASSIVE_LEVEL 0
#define POOL_FLAG_NON_PAGED 1
#define STAGE_SOP_LIFETIME_TAG 1
#define SAFEUPLOAD_REGISTRY_POOL_TAG 2
#define SAFEUPLOAD_WRITER_REGISTRY_ALL_LIMIT 20480U
#define SAFEUPLOAD_REGISTRY_UNKNOWN_CLEANUP 64
static int registry, writer, globalUnknown, teardown, allocations, frees, failAllocation, asserts;
static void (*afterWriterRelease)(void), (*beforeRegistryAcquire)(void), (*duringAllocation)(void);
#define NT_ASSERT(c) do { if(!(c)) asserts++; } while(0)
#define InterlockedCompareExchange(p,v,c) (*(p))
#define InterlockedIncrement(p) (++*(p))
#define InterlockedDecrement(p) (--*(p))
#define InterlockedExchange(p,v) (*(p)=(v))
static PVOID InterlockedCompareExchangePointer(PVOID volatile *p,PVOID value,PVOID expected) {
 PVOID old=*p;if(old==expected)*p=value;return old;
}
static PVOID InterlockedExchangePointer(PVOID volatile *p,PVOID value) {PVOID old=*p;*p=value;return old;}
static int RegistryLock;
static void FltAcquirePushLockExclusive(int *p) {
 (void)p;assert(!registry && !writer);
 if(beforeRegistryAcquire){void(*h)(void)=beforeRegistryAcquire;beforeRegistryAcquire=NULL;h();}
 registry=1;
}
static void FltReleasePushLock(int *p){(void)p;assert(registry&&!writer);registry=0;}
static void StageAcquireSpinLock(int *p,KIRQL *irql){(void)p;assert(!writer);writer=1;*irql=0;}
static void StageReleaseSpinLock(int *p,KIRQL irql){(void)p;(void)irql;assert(writer);writer=0;
 if(afterWriterRelease){void(*h)(void)=afterWriterRelease;afterWriterRelease=NULL;h();}}
static void *ExAllocatePool2(int flags,size_t bytes,int tag){(void)flags;(void)tag;assert(!writer&&!registry);
 if(duringAllocation){void(*h)(void)=duringAllocation;duringAllocation=NULL;h();}
 if(failAllocation){failAllocation=0;return NULL;}allocations++;return calloc(1,bytes);}
static void ExFreePoolWithTag(void *p,int tag){(void)tag;assert(!writer&&!registry);assert(p);frees++;free(p);}
static BOOLEAN SafeUploadStageMandatoryTeardownActive(void){return teardown;}
static void StageRegistryPublishGlobalUnknown(int reason){assert(reason==64);globalUnknown=1;}
'''

TYPES = r'''
typedef struct ENTRY {
 LONG References,H,W,T,UnknownReasons; BOOLEAN Listed,Retired,Transient,StaticPool;
 PVOID volatile SopLifetime; PVOID Volume,Instance;
} STAGE_REGISTRY_ENTRY,*PSTAGE_REGISTRY_ENTRY;
typedef struct CONTEXT {
 int WriterLock; PVOID volatile WriterSopLifetime,WriterRegistryEntry;
 BOOLEAN WriterSopLifetimeInvalid,WriterRegistryCachePruned,WriterContextRetired;
 LONG WritersUntracked; int WriterObjects;
} CONTEXT,*PSAFEUPLOAD_STREAM_CONTEXT;
#define IsListEmpty(p) (*(p)==0)
static void StageRegistryReference(PSTAGE_REGISTRY_ENTRY e){++e->References;}
static void FltObjectDereference(void *p){(void)p;assert(!registry&&!writer);}
static void StageRegistryCompactPoolPush(PSTAGE_REGISTRY_ENTRY e){(void)e;assert(0);}
'''

MAIN = r'''
static STAGE_REGISTRY_ENTRY *entry(void){
 STAGE_REGISTRY_ENTRY *e=calloc(1,sizeof(*e));e->References=1;e->Listed=TRUE;return e;
}
static void retire(STAGE_REGISTRY_ENTRY *e){assert(!e->Retired);FltAcquirePushLockExclusive(&RegistryLock);
 e->Retired=TRUE;e->Listed=FALSE;StageRegistryRetireLifetimeLocked(e);FltReleasePushLock(&RegistryLock);}
static void drop(STAGE_REGISTRY_ENTRY *e){StageRegistryDereference(e);}
static void finish(CONTEXT *c, STAGE_REGISTRY_ENTRY *e){retire(e);StageWritersReleasePrunedCache(c,e);drop(e);}
static CONTEXT *hookContext; static STAGE_REGISTRY_ENTRY *hookEntry,*competitor;static void *sop=(void*)123;
static void pruneHook(void){retire(hookEntry);StageWritersReleasePrunedCache(hookContext,hookEntry);}
static void retirementHook(void){retire(hookEntry);}
static void competitorHook(void){assert(StageRegistryBindLifetime(competitor,hookContext,sop));}
static void invalidateHook(void){hookContext->WriterSopLifetimeInvalid=TRUE;}
static void teardownHook(void){teardown=TRUE;}
static void initHook(CONTEXT *c,STAGE_REGISTRY_ENTRY *e){hookContext=c;hookEntry=e;}
int main(void){
 _Static_assert(sizeof(STAGE_SOP_LIFETIME)==24,"x64 SOP witness size");
 /* Repeated binding and shared metadata-only successors: cache may remain the old entry. */
 for(int reverse=0;reverse<2;reverse++){
 CONTEXT c={0};STAGE_REGISTRY_ENTRY *a=entry(),*b=entry();
 assert(StageRegistryBindLifetime(a,&c,sop));STAGE_SOP_LIFETIME *l=c.WriterSopLifetime;
 assert(l->NonRetiredBindings==1&&l->References==2);
 assert(StageRegistryBindLifetime(a,&c,sop));assert(l->NonRetiredBindings==1&&l->References==2);
 assert(StageRegistryBindLifetime(b,&c,sop));assert(l->NonRetiredBindings==2&&l->References==3);
 retire(reverse?b:a);StageWritersReleasePrunedCache(&c,reverse?b:a);
 assert(c.WriterSopLifetime==l&&l->NonRetiredBindings==1);
 retire(reverse?a:b);StageWritersReleasePrunedCache(&c,reverse?a:b);
 assert(!c.WriterSopLifetime&&!c.WriterRegistryEntry&&l->References==2&&l->NonRetiredBindings==0&&!l->Ended);
 /* Retired entry references preserve their original witness after a fresh bind. */
 STAGE_REGISTRY_ENTRY *n=entry();assert(StageRegistryBindLifetime(n,&c,sop));assert(c.WriterSopLifetime!=l);
 retire(n);PVOID newer=c.WriterSopLifetime;StageWritersReleasePrunedCache(&c,a);
 assert(c.WriterSopLifetime==newer);StageWritersReleasePrunedCache(&c,n);drop(n);drop(a);drop(b);
 }
 /* Detach between hint and locked check retries with a fresh allocation. */
 {CONTEXT c={0};STAGE_REGISTRY_ENTRY *a=entry(),*b=entry();assert(StageRegistryBindLifetime(a,&c,sop));
 initHook(&c,a);afterWriterRelease=pruneHook;int before=allocations;
 assert(StageRegistryBindLifetime(b,&c,sop));assert(allocations==before+1);drop(a);finish(&c,b);}
 /* Detach before hint and after winning binder: no lost owner. */
 {CONTEXT c={0};STAGE_REGISTRY_ENTRY *a=entry(),*b=entry();assert(StageRegistryBindLifetime(a,&c,sop));
 retire(a);StageWritersReleasePrunedCache(&c,a);assert(StageRegistryBindLifetime(b,&c,sop));drop(a);finish(&c,b);}
 /* Competing allocations: exactly one context allocation survives; loser freed outside locks. */
 {CONTEXT c={0};STAGE_REGISTRY_ENTRY *a=entry(),*b=entry();initHook(&c,a);competitor=b;duringAllocation=competitorHook;
 int before=allocations,oldFrees=frees;assert(StageRegistryBindLifetime(a,&c,sop));
 assert(allocations==before+2&&frees==oldFrees+1);STAGE_SOP_LIFETIME *l=c.WriterSopLifetime;
 assert(l->NonRetiredBindings==2&&l->References==3);finish(&c,a);finish(&c,b);}
 /* Retirement, invalidation and teardown between checks forbid late binding. */
 for(int which=0;which<3;which++){
 CONTEXT c={0};STAGE_REGISTRY_ENTRY *a=entry();initHook(&c,a);
 beforeRegistryAcquire=which==0?retirementHook:which==1?invalidateHook:teardownHook;
 assert(!StageRegistryBindLifetime(a,&c,sop));assert(!c.WriterSopLifetime&&!a->SopLifetime);
 teardown=0;if(!a->Retired)retire(a);drop(a);
 }
 {CONTEXT c={0};STAGE_REGISTRY_ENTRY *a=entry();failAllocation=1;int before=allocations;
 assert(!StageRegistryBindLifetime(a,&c,sop));assert(allocations==before);retire(a);drop(a);}
 /* Transient classifiers and already retired history never bind. */
 {CONTEXT c={0};STAGE_REGISTRY_ENTRY *a=entry();a->Transient=TRUE;
 assert(!StageRegistryBindLifetime(a,&c,sop));assert(!c.WriterSopLifetime);retire(a);
 assert(!StageRegistryBindLifetime(a,&c,sop));drop(a);}
 /* Unchanged blockers: successful prune alone doesn't override a new writer or invalid context. */
 for(int which=0;which<4;which++){
 CONTEXT c={0};STAGE_REGISTRY_ENTRY *a=entry();assert(StageRegistryBindLifetime(a,&c,sop));
 STAGE_SOP_LIFETIME *l=c.WriterSopLifetime;retire(a);
 if(which==0)c.WriterObjects=1;
 if(which==1)c.WritersUntracked=1;
 if(which==2)c.WriterSopLifetimeInvalid=TRUE;
 if(which==3)l->Invalid=1;
 StageWritersReleasePrunedCache(&c,a);assert(c.WriterSopLifetime==l);
 c.WriterObjects=0;c.WritersUntracked=0;c.WriterSopLifetimeInvalid=FALSE;l->Invalid=0;
 StageWritersReleasePrunedCache(&c,a);assert(!c.WriterSopLifetime);drop(a);
 }
 /* Count underflow/overflow invalidates, sticks global loss and never clamps. */
 for(int which=0;which<3;which++){
 CONTEXT c={0};STAGE_REGISTRY_ENTRY *a=entry();assert(StageRegistryBindLifetime(a,&c,sop));
 STAGE_SOP_LIFETIME *l=c.WriterSopLifetime;LONG corrupt=which==0?0:which==1?-1:20481;
 l->NonRetiredBindings=corrupt;globalUnknown=0;retire(a);assert(l->Invalid&&globalUnknown);
 assert(l->NonRetiredBindings==corrupt);StageWritersReleasePrunedCache(&c,a);assert(c.WriterSopLifetime==l);
 /* Test-owned cleanup consumes the attached context reference; never repairs production evidence. */
 c.WriterSopLifetime=NULL;StageRegistryReleaseLifetime(l);
 if(c.WriterRegistryEntry){c.WriterRegistryEntry=NULL;drop(a);}drop(a);
 }
 /* Incompatible existing binding undoes its tentative reference exactly once. */
 {CONTEXT c={0},other={0};STAGE_REGISTRY_ENTRY *a=entry(),*b=entry();
 assert(StageRegistryBindLifetime(a,&c,sop));assert(StageRegistryBindLifetime(b,&other,sop));
 STAGE_SOP_LIFETIME *l=other.WriterSopLifetime;assert(!StageRegistryBindLifetime(a,&other,sop));
 assert(l->References==2&&l->NonRetiredBindings==1);finish(&c,a);finish(&other,b);}
 /* Destruction asserts the history-owner invariant and fails closed in release builds too. */
 {STAGE_REGISTRY_ENTRY *a=entry();STAGE_SOP_LIFETIME *l=ExAllocatePool2(1,sizeof(*l),1);
 l->References=2;l->NonRetiredBindings=1;a->SopLifetime=l;globalUnknown=0;int before=asserts;
 drop(a);assert(asserts==before+1&&l->Invalid&&globalUnknown&&l->NonRetiredBindings==1);StageRegistryReleaseLifetime(l);}
 assert(!registry&&!writer);assert(allocations==frees);return 0;
}
'''


def run(s):
    sop = s[s.index('typedef struct _STAGE_SOP_LIFETIME'):s.index('} STAGE_SOP_LIFETIME, *PSTAGE_SOP_LIFETIME;') + len('} STAGE_SOP_LIFETIME, *PSTAGE_SOP_LIFETIME;')]
    program = SHIM + sop + TYPES + '\n'.join(definition(s, name) for name in NAMES) + MAIN
    # malloc for entry fixtures is separate from driver witness pool accounting.
    program = program.replace('else ExFreePoolWithTag(Entry, SAFEUPLOAD_REGISTRY_POOL_TAG);', 'else free(Entry);')
    with tempfile.TemporaryDirectory(prefix='t5-sop-detach-') as temp:
        path = Path(temp); (path/'test.c').write_text(program)
        build = subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror',str(path/'test.c'),'-o',str(path/'test')],capture_output=True,text=True)
        assert build.returncode == 0, build.stderr
        return subprocess.run([str(path/'test')],capture_output=True,text=True,cwd=path,timeout=15).returncode


class SopWitnessDetach(unittest.TestCase):
    def test_production_bodies_interleaving_ownership_and_violation(self): self.assertEqual(0,run(PATH.read_text()))
    def test_source_lock_transition_inventory_and_unchanged_blockers(self): contract(PATH.read_text())
    def test_semantic_mutations_must_compile_and_fail_execution(self):
        s = PATH.read_text()
        mutations = [
            ('if (existing == NULL) ++lifetime->NonRetiredBindings;', 'if (existing == NULL) lifetime->NonRetiredBindings += 2;'),
            ('if (existing == NULL) ++lifetime->NonRetiredBindings;', 'if (existing == NULL || existing == lifetime) ++lifetime->NonRetiredBindings;'),
            ('if (existing == NULL) ++lifetime->NonRetiredBindings;', 'if (existing == NULL) (void)lifetime;'),
            ('else --lifetime->NonRetiredBindings;', 'else lifetime->NonRetiredBindings -= 2;'),
            ('else --lifetime->NonRetiredBindings;', 'else (void)lifetime;'),
            ('Entry->Listed && !Entry->Retired && !Entry->Transient', '!Entry->Transient'),
            ('Entry->Listed && !Entry->Retired && !Entry->Transient', 'Entry->Listed && !Entry->Retired'),
            ('if (!retry) return valid;', 'if (retry || !retry) return valid;'),
            ('retry = lifetime == NULL && fresh == NULL && allocationSkipped;', 'retry = lifetime == NULL && fresh == NULL;'),
            ('else StageRegistryReleaseLifetime(lifetime);', 'else (void)lifetime;'),
            ('StageRegistryReleaseLifetime(fresh);', '(void)fresh;'),
            ('lifetime->NonRetiredBindings == 0 &&', 'lifetime->NonRetiredBindings >= 0 &&'),
            ('lifetime == StageRegistryLifetime(Entry) &&', 'lifetime != NULL &&'),
            ('StageRegistryReleaseLifetime(detached);', '(void)detached;'),
            ('StageRegistryDereference(released);', '(void)released;'),
            ('InterlockedExchange(&Lifetime->Invalid, 1);', '(void)Lifetime;'),
            ('StageRegistryPublishGlobalUnknown(SAFEUPLOAD_REGISTRY_UNKNOWN_CLEANUP);', '(void)&StageRegistryPublishGlobalUnknown;'),
            ('StageRegistryLifetimeViolation(lifetime);\n        else --lifetime', 'lifetime->NonRetiredBindings = 0;\n        else --lifetime'),
            ('if (lifetime != NULL && !Entry->Retired) StageRegistryLifetimeViolation(lifetime);', 'if (lifetime != NULL && !Entry->Retired) (void)lifetime;'),
        ]
        for old,new in mutations:
            with self.subTest(mutation=old):
                self.assertIn(old,s); self.assertNotEqual(0,run(s.replace(old,new)))
    def test_source_mutations_caught(self):
        s = PATH.read_text()
        mutations = [
            ('C_ASSERT(sizeof(STAGE_SOP_LIFETIME) == 24)', 'C_ASSERT(sizeof(STAGE_SOP_LIFETIME) == 32)'),
            ('entry->Retired = TRUE;\n                StageRegistryRetireLifetimeLocked(entry);', 'entry->Retired = TRUE;'),
            ('Entry->Retired = TRUE;\n        StageRegistryRetireLifetimeLocked(Entry);', 'Entry->Retired = TRUE;'),
            ('FltAcquirePushLockExclusive(&RegistryLock);', '/* no registry lock */'),
            ('StageAcquireSpinLock(&Context->WriterLock, &irql);', '/* no writer lock */'),
            ('NT_ASSERT(lifetime == NULL || Entry->Retired);', 'NT_ASSERT(TRUE);'),
            ('Entry->Retired = TRUE;', 'Entry->Retired = FALSE;'),
            ('StageRegistryReleaseLifetime(detached);', 'StageRegistryRetireLifetimeLocked(Entry); StageRegistryReleaseLifetime(detached);'),
            ('StageRegistryReleaseLifetime(fresh);', 'StageRegistryRetireLifetimeLocked(Entry); StageRegistryReleaseLifetime(fresh);'),
            ('if (lifetime != NULL && !Entry->Retired) StageRegistryLifetimeViolation(lifetime);', 'StageRegistryRetireLifetimeLocked(Entry);'),
            ('StreamContext->WriterSopLifetime = NULL;\n        detached', 'RtlZeroMemory(Entry, sizeof(*Entry));\n        StreamContext->WriterSopLifetime = NULL;\n        detached'),
            ('InterlockedCompareExchange(&Entry->W, 0, 0) != 0 ||', 'FALSE ||'),
            ('InterlockedCompareExchange(&Entry->UnknownReasons, 0, 0) != 0)', 'FALSE)'),
            ('lifetime == StageRegistryLifetime(Entry) &&', 'TRUE &&'),
            ('!StreamContext->WriterSopLifetimeInvalid &&', 'TRUE &&'),
            ('if (existing == NULL) ++lifetime->NonRetiredBindings;', 'if (existing == NULL || existing == lifetime) ++lifetime->NonRetiredBindings;'),
            ('lifetime->NonRetiredBindings == 0 &&', 'TRUE &&'),
            ('StreamContext->WriterSopLifetime = NULL;\n        detached', 'InterlockedExchange(&lifetime->Ended, 1);\n        StreamContext->WriterSopLifetime = NULL;\n        detached'),
            ('StageRegistryReleaseLifetime(detached);', 'for (;;) {} StageRegistryReleaseLifetime(detached);'),
            ('StageAcquireSpinLock(&Context->WriterLock, &irql);\n        lifetime', 'StageAcquireSpinLock(&Context->WriterLock, &irql);\n        for (;;) {}\n        lifetime'),
        ]
        for old,new in mutations:
            with self.subTest(mutation=old):
                self.assertIn(old,s)
                with self.assertRaises((AssertionError,ValueError)): contract(s.replace(old,new))


if __name__ == '__main__': unittest.main()
