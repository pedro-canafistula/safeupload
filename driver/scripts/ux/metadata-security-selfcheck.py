#!/usr/bin/env python3
"""Compile the production legacy security query; host diagnostic, not WDK/NTFS."""
from pathlib import Path
import importlib.util
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / 'driver/SafeUpload.Minifilter/StageSecurity.c'
spec = importlib.util.spec_from_file_location('metadata', Path(__file__).with_name('metadata-selfcheck.py'))
metadata = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metadata)

SHIM = r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
typedef int32_t NTSTATUS;
typedef uint32_t ULONG, *PULONG;
typedef int BOOLEAN;
typedef void *PVOID, *HANDLE, *PFILE_OBJECT, *PSECURITY_DESCRIPTOR, *PFLT_INSTANCE;
typedef struct { int dummy; } OBJECT_ATTRIBUTES;
typedef struct { uint16_t Length, MaximumLength; void *Buffer; } UNICODE_STRING, *PUNICODE_STRING;
typedef struct { NTSTATUS Status; uintptr_t Information; } IO_STATUS_BLOCK;
typedef struct { uint8_t bytes[20]; } SECURITY_DESCRIPTOR_RELATIVE;
static struct { void *Filter; } SafeUploadData;
#define _In_
#define _Outptr_result_nullonfailure_
#define PAGED_CODE() ((void)0)
#define NULL_PTR ((void*)0)
#define STATUS_SUCCESS 0
#define STATUS_BUFFER_TOO_SMALL (-1)
#define STATUS_INSUFFICIENT_RESOURCES (-2)
#define STATUS_INVALID_SECURITY_DESCR (-3)
#define STATUS_STOPPED_ON_SYMLINK (-4)
#define STATUS_NOT_SUPPORTED (-5)
#define STATUS_ACCESS_DENIED (-6)
#define NT_SUCCESS(s) ((s)>=0)
#define POOL_FLAG_PAGED 1
#define SAFEUPLOAD_POOL_TAG 123
#define OBJ_KERNEL_HANDLE 1
#define OBJ_CASE_INSENSITIVE 2
#define READ_CONTROL 0x20000
#define FILE_SHARE_READ 1
#define FILE_SHARE_WRITE 2
#define FILE_SHARE_DELETE 4
#define FILE_OPEN 1
#define FILE_OPENED 1
#define FILE_DIRECTORY_FILE 1
#define FILE_NON_DIRECTORY_FILE 2
#define IO_IGNORE_SHARE_ACCESS_CHECK 1
#define IO_STOP_ON_SYMLINK 2
#define BACKUP_SECURITY_INFORMATION 0x10000u
#define OWNER_SECURITY_INFORMATION 1
#define GROUP_SECURITY_INFORMATION 2
#define DACL_SECURITY_INFORMATION 4
#define SACL_SECURITY_INFORMATION 8
static NTSTATUS open_status, io_status, first_status, second_status;
static ULONG needed, returned;
static int allocations, frees, closes, dereferences, queries, no_memory, valid, null_object, null_handle, bad_information;
static void InitializeObjectAttributes(OBJECT_ATTRIBUTES *a, PUNICODE_STRING n, int f, void *r, void *s) {
 (void)a;(void)n;(void)f;(void)r;(void)s;
}
static NTSTATUS FltCreateFileEx2(void *f, void *i, HANDLE *h, PFILE_OBJECT *o, int a,
 OBJECT_ATTRIBUTES *oa, IO_STATUS_BLOCK *io, void *size, int attrs, int share,
 int disp, int opts, void *ea, int easz, int flags, void *ecp) {
 (void)f;(void)i;(void)oa;(void)size;(void)attrs;(void)opts;(void)ea;(void)easz;(void)ecp;
 assert(a==READ_CONTROL && share==7 && disp==FILE_OPEN && flags==3);
 *h=null_handle?NULL:(void*)1;*o=null_object?NULL:(void*)2;io->Status=io_status;io->Information=bad_information?0:FILE_OPENED;
 return open_status;
}
static NTSTATUS FltQuerySecurityObject(void *i, void *o, ULONG info, void *b, ULONG size, ULONG *count) {
 (void)i;assert(o==(void*)2 && info==7);queries++;
 if (!b) { assert(size==0);*count=needed;return first_status; }
 assert(size==needed);memset(b,0,size);*count=returned;return second_status;
}
static void *ExAllocatePool2(int flags, ULONG size, int tag) {
 assert(flags==POOL_FLAG_PAGED && size>=20 && size<=65536 && tag==SAFEUPLOAD_POOL_TAG);
 if(no_memory) { return NULL; }
 allocations++;return malloc(size);
}
static void ExFreePoolWithTag(void *p,int tag) { assert(p && tag==SAFEUPLOAD_POOL_TAG);frees++;free(p); }
static void ExFreePool(void *p) { free(p); }
static void ObDereferenceObject(void *o) { assert(o==(void*)2);dereferences++; }
static void FltClose(void *h) { assert(h==(void*)1);closes++; }
static int RtlValidRelativeSecurityDescriptor(void *b, ULONG size, ULONG required) {
 assert(b && size>=20 && size<=needed && required==0);return valid;
}
static void reset(void) {
 open_status=io_status=second_status=0;first_status=STATUS_BUFFER_TOO_SMALL;
 needed=returned=64;allocations=frees=closes=dereferences=queries=no_memory=null_object=null_handle=bad_information=0;valid=1;
}
'''
CASES = r'''
int main(void) {
 PSECURITY_DESCRIPTOR descriptor=NULL;UNICODE_STRING name={0};
 reset();assert(SafeUploadStageQuerySecurity(NULL,&name,0,&descriptor)==0 && descriptor);
 assert(queries==2 && allocations==1 && closes==1 && dereferences==1 && !frees);
 ExFreePoolWithTag(descriptor,SAFEUPLOAD_POOL_TAG);
 for(int fault=0;fault<15;fault++) {
  reset();descriptor=(void*)99;
  switch(fault) {
   case 0:needed=19;break;
   case 1:needed=65537;break;
   case 2:no_memory=1;break;
   case 3:returned=19;break;
   case 4:returned=65;break;
   case 5:valid=0;break;
   case 6:second_status=0x103;break;
   case 7:second_status=STATUS_ACCESS_DENIED;break;
   case 8:first_status=0;break;
   case 9:first_status=0x103;break;
   case 10:open_status=0x103;break;
   case 11:null_object=1;break;
   case 12:io_status=0x103;break;
   case 13:null_handle=1;break;
   case 14:bad_information=1;break;
  }
  assert(SafeUploadStageQuerySecurity(NULL,&name,0,&descriptor)!=0 && descriptor==NULL);
  assert(allocations==frees && closes==!null_handle && dereferences==!null_object);
 }
 reset();open_status=STATUS_ACCESS_DENIED;
 assert(SafeUploadStageQuerySecurity(NULL,&name,0,&descriptor)==STATUS_ACCESS_DENIED && !descriptor);
 assert(!queries && !allocations && !closes && !dereferences);
 puts("legacy security capture: bounded allocation, complete query, malformed/short/pending/open failures and balanced cleanup PASS");
}
'''

class SecurityCapture(unittest.TestCase):
    def test_production_query(self):
        scratch = ROOT / '.scratch/metadata-security-shim'
        scratch.mkdir(parents=True, exist_ok=True)
        src = scratch / 'security.c'
        src.write_text(SHIM + metadata.body('SafeUploadStageQuerySecurity', SOURCE) + CASES)
        compilers = [c for c in ('cc', 'clang') if shutil.which(c)]
        self.assertEqual(len(compilers), 2, 'GCC and Clang required for this host control')
        for compiler in compilers:
            executable = scratch / compiler
            subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-fsanitize=undefined',
                            str(src), '-o', str(executable)], check=True)
            subprocess.run([str(executable)], check=True)

    def test_annotations_and_inheritance_are_explicit(self):
        source = SOURCE.read_text()
        header = SOURCE.with_suffix('.h').read_text()
        for name in ('SafeUploadStageQueryIdentity', 'SafeUploadStageCheckAccess',
                     'SafeUploadStageCaptureSecurity', 'SafeUploadStageFreeSecurity',
                     'SafeUploadStageCheckRenameAccess', 'SafeUploadStageCheckSubjectAccess'):
            for text in (source, header):
                self.assertRegex(text, r'_IRQL_requires_\(PASSIVE_LEVEL\)\s+(?:NTSTATUS|VOID)\s+' + name)
            self.assertIn('#pragma alloc_text(PAGE, ' + name + ')', source)
        capture = metadata.body('SafeUploadStageCaptureSecurity', SOURCE)
        self.assertIn('NULL, FALSE, SEF_DACL_AUTO_INHERIT,', capture)
        self.assertNotIn('SEF_SACL_AUTO_INHERIT', capture)
        self.assertNotIn('SEF_AVOID_', capture)

if __name__ == '__main__':
    unittest.main()
