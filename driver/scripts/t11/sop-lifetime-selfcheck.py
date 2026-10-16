#!/usr/bin/env python3
"""Execute production startup SOP and ended-incarnation retirement with host DDIs.
Ownership/order diagnostics only; Windows MM/FltMgr/IRQL qualification is separate.
"""
from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('contracts', ROOT / 'driver/scripts/t5/teardown-participation-selfcheck.py')
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)


def body(file, name):
    return t.body(file, name)


def run(code, compiler):
    path = Path(tempfile.mkdtemp(prefix='t11-sop-', dir=os.environ.get('TMPDIR', ROOT / '.scratch')))
    (path / 'control.c').write_text(code)
    result = subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-fsanitize=undefined',
                             str(path / 'control.c'), '-o', str(path / 'control')], capture_output=True, text=True)
    if result.returncode == 0:
        result = subprocess.run([str(path / 'control')], capture_output=True, text=True)
    return result


class Controls(unittest.TestCase):
    def test_startup_owned_objects_and_section_only_reopen(self):
        code = STARTUP
        code += '\nstatic NTSTATUS StageCanaryCheckSharedSop(PFLT_INSTANCE Instance, PUNICODE_STRING Name, PSECTION_OBJECT_POINTERS Expected, PHANDLE Handle, PFILE_OBJECT *Object)\n' + body('StageAdmission.c', 'StageCanaryCheckSharedSop')
        code += '\nstatic NTSTATUS StageCanaryCheckSopLifetime(PFLT_INSTANCE Instance, PUNICODE_STRING Name, const FILE_ID_INFORMATION *ExpectedIdentity, PHANDLE Handle, PFILE_OBJECT *Object)\n' + body('StageAdmission.c', 'StageCanaryCheckSopLifetime')
        code += STARTUP_MAIN
        for compiler in ('cc', 'clang'):
            with self.subTest(compiler=compiler):
                result = run(code, shutil.which(compiler))
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        # Demonstrate this control rejects an implementation retaining a driver
        # FILE_OBJECT reference across the supposedly section-only interval.
        mutation = code.replace('ObDereferenceObject(*Object); *Object = NULL;', '*Object = NULL;')
        self.assertNotEqual(0, run(mutation, shutil.which('cc')).returncode)

    def test_ended_incarnation_retirement_keeps_every_obligation(self):
        code = RETIRE
        signatures = {
            'StageRegistryLifetime': 'static PSTAGE_SOP_LIFETIME StageRegistryLifetime(PSTAGE_REGISTRY_ENTRY Entry)',
            'StageRegistryLifetimeEnded': 'static BOOLEAN StageRegistryLifetimeEnded(PSTAGE_REGISTRY_ENTRY Entry)',
            'StageRegistryRetireLifetimeLocked': 'static VOID StageRegistryRetireLifetimeLocked(PSTAGE_REGISTRY_ENTRY Entry)',
            'StageRegistryOldIncarnationResolvedLocked': 'static BOOLEAN StageRegistryOldIncarnationResolvedLocked(PSTAGE_REGISTRY_ENTRY Entry)',
            'StageRegistryPruneLocked': 'static BOOLEAN StageRegistryPruneLocked(PSTAGE_REGISTRY_ENTRY Entry, ULONGLONG EvidenceSequence, PSTAGE_REGISTRY_ENTRY *MapReference, PFLT_INSTANCE *InstanceReference, PFLT_VOLUME *VolumeReference)',
        }
        for name, signature in signatures.items():
            code += '\n' + signature + '\n' + body('StageWriters.c', name)
        code += RETIRE_MAIN
        for compiler in ('cc', 'clang'):
            with self.subTest(compiler=compiler):
                result = run(code, shutil.which(compiler))
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        mutation = code.replace('InterlockedCompareExchange(&lifetime->Ended, 0, 0) != 0', '1')
        self.assertNotEqual(0, run(mutation, shutil.which('cc')).returncode)

    def test_startup_and_worker_wiring(self):
        source = (ROOT / 'driver/SafeUpload.Minifilter/StageAdmission.c').read_text()
        for name in ('StageCanaryCheckSharedSop', 'StageCanaryCheckSopLifetime', 'StageCanarySetDeleteDisposition'):
            self.assertIn('#pragma alloc_text(PAGE, ' + name + ')', source)
            self.assertEqual(2, source.count('_IRQL_requires_(PASSIVE_LEVEL)\nstatic NTSTATUS ' + name + '('))
            self.assertIn('PAGED_CODE();', body('StageAdmission.c', name))
        canary = body('StageAdmission.c', 'StageCanaryRun')
        create = canary[canary.index('status = FltCreateFileEx2'):canary.index('if (status != STATUS_SUCCESS) goto Exit;', canary.index('status = FltCreateFileEx2'))]
        self.assertNotIn('FILE_DELETE_ON_CLOSE', create)
        self.assertLess(canary.index('StageCanaryVerifySecurity'), canary.index('StageCanaryCheckSopLifetime'))
        self.assertLess(canary.index('StageCanaryCheckSopLifetime'), canary.index('StageCanaryHoldAfterSecurity'))
        self.assertLess(canary.index('StageCanaryCheckSopLifetime'), canary.index('StageCanarySetDeleteDisposition'))
        self.assertIn('checks == SAFEUPLOAD_CANARY_CHECKS_ALL', canary)
        quiescent = body('StageWriters.c', 'StageRegistryEntryQuiescent')
        self.assertLess(quiescent.index('if (StageRegistryLifetimeEnded(Entry)) return TRUE'), quiescent.index('StageRegistryOpenIdentity'))
        self.assertLess(quiescent.index('StageRegistryOriginalContext'), quiescent.index('MmCanFileBeTruncated'))
        activation = body('StageWriters.c', 'StageRegistryActivationProcess')
        self.assertIn('status == STATUS_FILE_INVALID || StageRegistryLifetimeEnded(Entry)', activation)
        worker = body('StageWriters.c', 'StageRegistryReclaimWorker')
        self.assertIn('!promotedThisPass && (StageRegistryLifetimeEnded(entry) ||', worker)
        self.assertIn('StageRegistryPruneLocked(entry, evidenceSequence', worker)
        self.assertIn('if (StageRegistryTakeWriterReleaseWake(entry)) SafeUploadStageWritersQueueRecheck()', worker)
        cleanup = body('StageWriters.c', 'SafeUploadStageWritersFreeContext')
        self.assertIn('else InterlockedExchange(&lifetime->Ended, 1)', cleanup)
        self.assertIn('if (naturalEnd && entriesRemain', cleanup)


STARTUP = r'''
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define assert(x) do { if(!(x)) exit(97); } while(0)
typedef void VOID; typedef int32_t NTSTATUS; typedef uint32_t ULONG; typedef void *HANDLE,**unused;
typedef HANDLE *PHANDLE; typedef void *PFLT_INSTANCE; typedef void *PUNICODE_STRING;
typedef struct { int value; } SECTION_OBJECT_POINTERS,*PSECTION_OBJECT_POINTERS;
typedef struct { PSECTION_OBJECT_POINTERS SectionObjectPointer; } FILE_OBJECT,*PFILE_OBJECT;
typedef struct { uint64_t VolumeSerialNumber; struct { uint64_t id[2]; } FileId; } FILE_ID_INFORMATION;
typedef struct { int dummy; } OBJECT_ATTRIBUTES,IO_STATUS_BLOCK;
#define STATUS_SUCCESS 0
#define STATUS_UNSUCCESSFUL ((NTSTATUS)-1)
#define STATUS_DATA_ERROR ((NTSTATUS)-2)
#define STATUS_INVALID_HANDLE ((NTSTATUS)-3)
#define NT_SUCCESS(x) ((x)>=0)
#define PASSIVE_LEVEL 0
#define PAGED_CODE() ((void)0)
#define NT_ASSERT(x) assert(x)
#define OBJ_KERNEL_HANDLE 1
#define OBJ_CASE_INSENSITIVE 2
#define FILE_READ_DATA 1
#define FILE_WRITE_DATA 2
#define FILE_READ_ATTRIBUTES 4
#define READ_CONTROL 8
#define DELETE 16
#define SYNCHRONIZE 32
#define FILE_SHARE_READ 1
#define FILE_SHARE_WRITE 2
#define FILE_SHARE_DELETE 4
#define FILE_OPEN 1
#define FILE_NON_DIRECTORY_FILE 1
#define FILE_SYNCHRONOUS_IO_NONALERT 2
#define FILE_OPEN_REPARSE_POINT 4
#define FILE_COMPLETE_IF_OPLOCKED 8
#define SECTION_QUERY 1
#define SECTION_MAP_READ 2
#define SECTION_MAP_WRITE 4
#define PAGE_READWRITE 4
#define SEC_COMMIT 1
#define FileIdInformation 1
#define RtlZeroMemory(p,n) memset(p,0,n)
#define RtlEqualMemory(a,b,n) (memcmp(a,b,n)==0)
#define InitializeObjectAttributes(p,n,a,r,s) do { (void)(p); (void)(n); } while(0)
static int mode,opens,handles,objects,sections,closeFailure;
static SECTION_OBJECT_POINTERS sop,other;
static FILE_OBJECT original={&sop},second={&sop},reopened={&sop};
static int KeGetCurrentIrql(void){return 0;}
static NTSTATUS FltClose(HANDLE h){assert(h&&handles>0);
 if(!closeFailure&&((mode==10&&h==(HANDLE)2)||(mode==11&&h==(HANDLE)1))){closeFailure=1;return -10;}
 handles--;return 0;}
static void ObDereferenceObject(PFILE_OBJECT p){assert(p&&objects>0);objects--;}
static void ZwClose(HANDLE h){assert(h&&sections==1);sections--;}
static NTSTATUS create(PHANDLE h,PFILE_OBJECT *p,int options){
 assert(options==(FILE_NON_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT|FILE_OPEN_REPARSE_POINT|FILE_COMPLETE_IF_OPLOCKED));
 ++opens;
 if(opens==2)assert(!handles&&!objects&&sections==1);
 if(mode==1&&opens==1)return -7;
 if(mode==4&&opens==2)return -8;
 *h=(HANDLE)(uintptr_t)(opens+1);handles++;
 *p=opens==1?&second:&reopened;objects++;
 (*p)->SectionObjectPointer=(mode==2&&opens==1)||(mode==5&&opens==2)?&other:&sop;
 if(mode==8&&opens==2){*p=NULL;objects--;}
 return mode==9&&opens==2?1:0;
}
#define FltCreateFileEx2(f,i,h,p,a,o,io,al,at,sh,d,op,e,el,fl,c) ((void)(i),(void)(io),create(h,p,op))
static NTSTATUS make_section(PHANDLE h){assert(handles==1&&objects==1);if(mode==3)return -9;*h=(HANDLE)7;sections++;return 0;}
#define ZwCreateSection(h,a,o,m,p,s,f) ((void)(o),make_section(h))
static NTSTATUS query(PFILE_OBJECT p,FILE_ID_INFORMATION *id,ULONG *returned){assert(p==&reopened&&sections==1);id->VolumeSerialNumber=7;id->FileId.id[0]=8;id->FileId.id[1]=mode==6?99:9;*returned=mode==7?1:sizeof(*id);return 0;}
#define FltQueryInformationFile(i,o,a,n,c,r) query(o,a,r)
'''
STARTUP_MAIN = r'''
int main(void){for(mode=0;mode<12;mode++){
 opens=sections=closeFailure=0;handles=objects=1;HANDLE h=(HANDLE)1;PFILE_OBJECT object=&original;
 FILE_ID_INFORMATION id={7,{{8,9}}};
 NTSTATUS status=StageCanaryCheckSopLifetime((void*)1,(void*)2,&id,&h,&object);
 assert((status==0)==(mode==0));assert(!sections);
 if(mode<=3||mode>=10){assert(h&&object);assert(handles==1&&objects==1);}
 else assert(!h&&!object&&!handles&&!objects);
 if(mode==0){assert(h&&object==&reopened);FltClose(h);ObDereferenceObject(object);}
 else if(h){FltClose(h);ObDereferenceObject(object);}
 assert(!handles&&!objects);
}return 0;}
'''
RETIRE = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#define assert(x) do { if(!(x)) exit(98); } while(0)
typedef void VOID,*PVOID,*PFLT_INSTANCE,*PFLT_VOLUME;typedef int32_t LONG;typedef uint64_t ULONGLONG;
typedef unsigned ULONG;typedef int BOOLEAN,KIRQL;typedef unsigned short USHORT,WCHAR;typedef unsigned short *PWCH;
#define TRUE 1
#define FALSE 0
#define SAFEUPLOAD_WRITER_REGISTRY_ALL_LIMIT 20480
#define SAFEUPLOAD_REGISTRY_STATE_ACTIVATING 1
#define SAFEUPLOAD_REGISTRY_STATE_UNKNOWN 2
#define SAFEUPLOAD_REGISTRY_UNKNOWN_CLEANUP 64
#define CONTAINING_RECORD(p,t,f) ((t*)((char*)(p)-offsetof(t,f)))
#define InterlockedCompareExchange(p,a,b) (*(p))
#define InterlockedCompareExchange64(p,a,b) (*(p))
#define InterlockedCompareExchangePointer(p,a,b) (*(p))
#define InterlockedIncrement64(p) (++*(p))
typedef struct LIST { struct LIST *Flink,*Blink; } LIST_ENTRY,*PLIST_ENTRY;
static void init(LIST_ENTRY *p){p->Flink=p->Blink=p;}
static void add(LIST_ENTRY *h,LIST_ENTRY *p){p->Flink=h;p->Blink=h->Blink;h->Blink->Flink=p;h->Blink=p;}
static void RemoveEntryList(LIST_ENTRY *p){p->Blink->Flink=p->Flink;p->Flink->Blink=p->Blink;}
typedef struct {LONG References,Ended,Invalid,NonRetiredBindings;PVOID Sop;} STAGE_SOP_LIFETIME,*PSTAGE_SOP_LIFETIME;
typedef struct ENTRY {LIST_ENTRY Link;LONG H,W,T,RenameInFlight,UnknownReasons,State;
 PVOID SectionObjectPointer,SopLifetime;PWCH Name;USHORT NameChars;BOOLEAN Listed,Retired,Compact;
 PFLT_INSTANCE Instance;PFLT_VOLUME Volume;} STAGE_REGISTRY_ENTRY,*PSTAGE_REGISTRY_ENTRY;
typedef struct {LIST_ENTRY Link;PSTAGE_REGISTRY_ENTRY BoundEntry;} STAGE_WRITER_RESERVATION;
typedef struct {LIST_ENTRY Link;PSTAGE_REGISTRY_ENTRY Entry;} STAGE_TX_ASSOCIATION;
typedef struct {PVOID FileObject,SectionObjectPointer;PSTAGE_REGISTRY_ENTRY RegistryEntry;} SECTION;
typedef struct {PSTAGE_REGISTRY_ENTRY Entry;LONG Unknown,UnknownReasons,UnknownWriterCount,SpilledMutatingIoCount;} STAGE_REGISTRY_SOP_SLOT,*PSTAGE_REGISTRY_SOP_SLOT;
typedef struct {PWCH Buffer;USHORT Length,MaximumLength;} UNICODE_STRING;
#define STAGE_SECTION_SLOTS 2
static SECTION SectionSlots[STAGE_SECTION_SLOTS];static STAGE_REGISTRY_SOP_SLOT map;
static LIST_ENTRY RegistryReservations,TransactionAssociations,RegistryEntries;
static int owners,globalUnknown,directory,SectionLock,spin,violations;
static LONG RegistryDirectoryRenameCount;static ULONGLONG RegistryChangeSequence,RegistryNameBytes;
static ULONG RegistryEntryCount,RegistryCompactEntryCount;
static int SafeUploadStageWritersOwnerCount(void){return owners;}
static int SafeUploadStageWritersGlobalUnknown(void){return globalUnknown;}
static int StageRegistryDirectoryRenameInFlightLocked(PFLT_INSTANCE i,UNICODE_STRING *n){(void)i;(void)n;return directory;}
static void StageAcquireSpinLock(int *l,KIRQL *i){(void)l;assert(!spin);spin=1;*i=0;}
static void StageReleaseSpinLock(int *l,KIRQL i){(void)l;(void)i;assert(spin);spin=0;}
static PSTAGE_REGISTRY_SOP_SLOT StageRegistryFindSopSlotLocked(PVOID sop,BOOLEAN *found){assert(spin&&sop==(void*)123);*found=TRUE;return &map;}
static void StageRegistryRemoveSopSlotLocked(PSTAGE_REGISTRY_SOP_SLOT p){assert(spin);memset(p,0,sizeof(*p));}
static ULONGLONG StageRegistryEntryNameStorageBytes(PSTAGE_REGISTRY_ENTRY e){(void)e;return 4;}
static void StageRegistryLifetimeViolation(PSTAGE_SOP_LIFETIME l){l->Invalid=1;violations++;}
'''
RETIRE_MAIN = r'''
int main(void){
 for(int blocker=0;blocker<19;blocker++){
 STAGE_SOP_LIFETIME witness={2,1,0,1,(void*)123};
 STAGE_REGISTRY_ENTRY e={0};e.Listed=1;e.State=1;e.SectionObjectPointer=(void*)123;e.SopLifetime=&witness;e.Instance=(void*)1;e.Volume=(void*)2;
 init(&RegistryReservations);init(&TransactionAssociations);init(&RegistryEntries);add(&RegistryEntries,&e.Link);
 memset(SectionSlots,0,sizeof(SectionSlots));memset(&map,0,sizeof(map));map.Entry=&e;
 owners=globalUnknown=directory=RegistryDirectoryRenameCount=0;RegistryChangeSequence=11;RegistryEntryCount=1;RegistryNameBytes=4;
 STAGE_WRITER_RESERVATION r={0};STAGE_TX_ASSOCIATION tx={0};
 switch(blocker){case 1:witness.Ended=0;break;case 2:e.H=1;break;case 3:e.W=1;break;case 4:e.T=1;break;
 case 5:e.RenameInFlight=1;break;case 6:e.UnknownReasons=1;break;case 7:e.State=2;break;case 8:owners=1;break;
 case 9:globalUnknown=1;break;case 10:RegistryDirectoryRenameCount=1;directory=1;break;
 case 11:r.BoundEntry=&e;add(&RegistryReservations,&r.Link);break;case 12:tx.Entry=&e;add(&TransactionAssociations,&tx.Link);break;
 case 13:SectionSlots[0].FileObject=(void*)1;SectionSlots[0].SectionObjectPointer=(void*)123;break;
 case 14:map.Unknown=1;break;case 15:map.UnknownReasons=1;break;case 16:map.UnknownWriterCount=1;break;
 case 17:map.SpilledMutatingIoCount=1;break;case 18:witness.Invalid=1;break;}
 PSTAGE_REGISTRY_ENTRY mapref=NULL;PFLT_INSTANCE instance=NULL;PFLT_VOLUME volume=NULL;
 /* A changed-SOP reopen cannot supply evidence: only the original Ended witness
  * allows retirement despite sequence movement, never a new object's predicate. */
 assert(StageRegistryPruneLocked(&e,10,&mapref,&instance,&volume)==(blocker==0));
 assert(!spin&&!violations);
 if(!blocker){assert(e.Retired&&!e.Listed&&!map.Entry&&mapref==&e&&instance==(void*)1&&volume==(void*)2);
 assert(!e.Instance&&!e.Volume&&!witness.NonRetiredBindings&&!RegistryEntryCount&&!RegistryNameBytes&&RegistryChangeSequence==12);}
 else {assert(!e.Retired&&e.Listed&&map.Entry==&e&&!mapref&&!instance&&!volume&&witness.NonRetiredBindings==1);}
 }
 return 0;
}
'''
if __name__ == '__main__':
    unittest.main()
