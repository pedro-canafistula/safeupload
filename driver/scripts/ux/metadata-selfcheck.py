#!/usr/bin/env python3
"""Compile production basic-metadata bodies; host controls, not Windows qualification."""
from pathlib import Path
import re
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / 'driver/SafeUpload.Minifilter/StageStream.c'


def body(name, path=SOURCE):
    text = path.read_text()
    match = re.search(r'(?m)^(?:static\s+)?(?:VOID|NTSTATUS|BOOLEAN)\s+' + name + r'\s*\([^;]*?\)\s*\{', text)
    assert match, name
    end = text.index('{', match.start()) + 1
    depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[match.start():end]


SHIM = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef int NTSTATUS;
typedef uint32_t ULONG, ACCESS_MASK;
typedef int BOOLEAN;
typedef void VOID;
typedef struct { int64_t QuadPart; } LARGE_INTEGER;
typedef struct { LARGE_INTEGER CreationTime,LastAccessTime,LastWriteTime,ChangeTime; ULONG FileAttributes; } FILE_BASIC_INFORMATION,*PFILE_BASIC_INFORMATION;
typedef struct _STAGE_STREAM { int Resource; BOOLEAN ReadOnly,Sealed,SealBasicValid; void *RenameExchange,*BackingObject,*BackingInstance; FILE_BASIC_INFORMATION BasicOverrides,SealBasic; } STAGE_STREAM,*PSTAGE_STREAM;
typedef struct { struct { struct { ULONG Length; void *InfoBuffer; } SetFileInformation; } Parameters; } IOPB;
typedef struct { IOPB *Iopb; } DATA,*PFLT_CALLBACK_DATA;
#define _In_
#define _Inout_
#define _In_opt_
#define PAGED_CODE() ((void)0)
#define TRUE 1
#define FALSE 0
#define PASSIVE_LEVEL 0
#define STATUS_SUCCESS 0
#define STATUS_ACCESS_DENIED (-1)
#define STATUS_INFO_LENGTH_MISMATCH (-2)
#define STATUS_NOT_SUPPORTED (-3)
#define STATUS_INVALID_DEVICE_STATE (-4)
#define STATUS_UNEXPECTED_IO_ERROR (-5)
#define NT_SUCCESS(s) ((s)>=0)
#define FILE_WRITE_ATTRIBUTES 0x100u
#define FILE_ATTRIBUTE_NORMAL 0x80u
#define FILE_ATTRIBUTE_ARCHIVE 0x20u
#define FILE_ATTRIBUTE_READONLY 1u
#define FILE_SUPERSEDE 0u
#define FILE_OVERWRITE 4u
#define FILE_OVERWRITE_IF 5u
#define STAGE_BASIC_ATTRIBUTES 0x21a7u
#define FileBasicInformation 4
#define FlagOn(a,b) ((a)&(b))
#define BooleanFlagOn(a,b) (!!((a)&(b)))
#define __try if(1)
#define __except(x) else
#define EXCEPTION_EXECUTE_HANDLER 1
#define GetExceptionCode() (-99)
#define RtlZeroMemory(p,n) memset(p,0,n)
static int irql,top,held,queries,short_query;
static NTSTATUS query_status;
static FILE_BASIC_INFORMATION backing;
static int KeGetCurrentIrql(void) { return irql; }
static void *IoGetTopLevelIrp(void) { return top?&top:NULL; }
static void StageAcquire(int *r) { (void)r;assert(!held);held=1; }
static void StageRelease(int *r) { (void)r;assert(held);held=0; }
static NTSTATUS FltQueryInformationFile(void *i, void *o, void *b, ULONG n, int c, ULONG *returned) {
    (void)i;assert(o && !held);assert(c==FileBasicInformation && n==sizeof(backing));++queries;
    memcpy(b,&backing,n);*returned=short_query?0:n;return query_status;
}
'''

CASES = r'''
int main(void) {
    FILE_BASIC_INFORMATION input={.CreationTime={100},.LastAccessTime={200},.LastWriteTime={300},.ChangeTime={900},.FileAttributes=0x2023};
    STAGE_STREAM s={.BackingObject=&backing}; IOPB io={0}; DATA d={&io};
    io.Parameters.SetFileInformation.Length=sizeof(input);io.Parameters.SetFileInformation.InfoBuffer=&input;
    assert(StageSetBasicInformation(&d,&s,0)==STATUS_ACCESS_DENIED);
    assert(!s.BasicOverrides.FileAttributes && !queries);
    assert(StageSetBasicInformation(&d,&s,FILE_WRITE_ATTRIBUTES)==0);
    assert(!s.ReadOnly && s.BasicOverrides.FileAttributes==0x2023 && !queries);
    assert(StageBasicReadonly(&s));
    assert(s.BasicOverrides.CreationTime.QuadPart==100 && s.BasicOverrides.ChangeTime.QuadPart==0);
    FILE_BASIC_INFORMATION b={.CreationTime={1},.LastAccessTime={2},.LastWriteTime={3},.ChangeTime={4},.FileAttributes=0x80};
    StageOverlayBasic(&s,&b);assert(b.LastWriteTime.QuadPart==300 && b.FileAttributes==0x2023 && b.ChangeTime.QuadPart==4);
    StageBasicWritten(&s);assert(s.BasicOverrides.LastWriteTime.QuadPart==0 && (s.BasicOverrides.FileAttributes&0x20));
    assert(StageSetBasicInformation(&d,&s,FILE_WRITE_ATTRIBUTES)==0);
    FILE_BASIC_INFORMATION original=s.BasicOverrides;
    uint32_t unsupported[]={0x4000,0x1000,0x800,0x200,0x400,0x10,0x40000000};
    for(unsigned x=0;x<sizeof(unsupported)/sizeof(*unsupported);++x) {
        input.FileAttributes=unsupported[x]; assert(StageSetBasicInformation(&d,&s,FILE_WRITE_ATTRIBUTES)==STATUS_NOT_SUPPORTED);
        assert(!memcmp(&original,&s.BasicOverrides,sizeof(original)));
    }
    input.FileAttributes=0;input.LastAccessTime.QuadPart=-1;
    assert(StageSetBasicInformation(&d,&s,FILE_WRITE_ATTRIBUTES)==STATUS_NOT_SUPPORTED);
    input.LastAccessTime.QuadPart=-2;assert(StageSetBasicInformation(&d,&s,FILE_WRITE_ATTRIBUTES)==STATUS_NOT_SUPPORTED);
    input.LastAccessTime.QuadPart=0;
    s.ReadOnly=1;assert(StageSetBasicInformation(&d,&s,FILE_WRITE_ATTRIBUTES)==STATUS_ACCESS_DENIED);s.ReadOnly=0;
    s.Sealed=1;assert(StageSetBasicInformation(&d,&s,FILE_WRITE_ATTRIBUTES)==STATUS_ACCESS_DENIED);s.Sealed=0;
    s.RenameExchange=&s;assert(StageSetBasicInformation(&d,&s,FILE_WRITE_ATTRIBUTES)==STATUS_ACCESS_DENIED);s.RenameExchange=NULL;
    io.Parameters.SetFileInformation.Length=1;assert(StageSetBasicInformation(&d,&s,FILE_WRITE_ATTRIBUTES)==STATUS_INFO_LENGTH_MISMATCH);
    io.Parameters.SetFileInformation.Length=sizeof(input);
    irql=2;assert(StageSetBasicInformation(&d,&s,FILE_WRITE_ATTRIBUTES)==STATUS_INVALID_DEVICE_STATE);irql=0;
    backing=(FILE_BASIC_INFORMATION){.CreationTime={10},.LastAccessTime={20},.LastWriteTime={30},.FileAttributes=0x20};
    assert(StageCaptureSealBasic(&s)==STATUS_INVALID_DEVICE_STATE && !queries);s.ReadOnly=1;
    top=1;assert(StageCaptureSealBasic(&s)==STATUS_INVALID_DEVICE_STATE && !queries);top=0;
    query_status=STATUS_ACCESS_DENIED;assert(StageCaptureSealBasic(&s)==STATUS_ACCESS_DENIED && !s.SealBasicValid);
    query_status=0x103;assert(StageCaptureSealBasic(&s)==STATUS_UNEXPECTED_IO_ERROR && !s.SealBasicValid);
    query_status=0;short_query=1;assert(StageCaptureSealBasic(&s)==STATUS_INFO_LENGTH_MISMATCH && !s.SealBasicValid);short_query=0;
    assert(StageCaptureSealBasic(&s)==0 && s.SealBasicValid && s.SealBasic.LastWriteTime.QuadPart==300 && s.SealBasic.FileAttributes==0x2023);
    int count=queries;backing.LastWriteTime.QuadPart=999;
    assert(StageCaptureSealBasic(&s)==0 && queries==count && s.SealBasic.LastWriteTime.QuadPart==300);
    STAGE_STREAM successor={0};
    StageInitializeBasic(&successor,&s,1,1,0x80);
    assert(successor.BasicOverrides.CreationTime.QuadPart==100 && successor.BasicOverrides.LastWriteTime.QuadPart==300);
    StageInitializeBasic(&successor,&s,1,FILE_OVERWRITE,0x80);
    assert(successor.BasicOverrides.CreationTime.QuadPart==100 && successor.BasicOverrides.LastWriteTime.QuadPart==0 && (successor.BasicOverrides.FileAttributes&0x20));
    memset(&successor,0,sizeof(successor));StageInitializeBasic(&successor,&s,1,FILE_SUPERSEDE,0x2081);
    assert(successor.BasicOverrides.CreationTime.QuadPart==0 && successor.BasicOverrides.FileAttributes==0x2021);
    memset(&successor,0,sizeof(successor));StageInitializeBasic(&successor,NULL,0,2,0x80);
    assert(successor.BasicOverrides.FileAttributes==0x20 && !StageBasicReadonly(&successor));
    puts("production metadata controls PASS: caller grant, ordinary bits, timestamp controls, seal freeze, lower failures and no I/O under locks");
}
'''

WIRE_SHIM = r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
typedef int NTSTATUS,BOOLEAN; typedef void *PVOID; typedef uint16_t WCHAR;
typedef uint32_t UINT32,ULONG,*PUINT32;typedef uint64_t UINT64;typedef int64_t LONGLONG;
typedef struct { uint8_t b[16]; } GUID,FILE_ID_128;
typedef struct { int64_t QuadPart; } LARGE_INTEGER;
typedef struct { LARGE_INTEGER CreationTime,LastAccessTime,LastWriteTime,ChangeTime;ULONG FileAttributes; } FILE_BASIC_INFORMATION;
typedef struct { uint16_t Length,MaximumLength;WCHAR *Buffer; } UNICODE_STRING,*PUNICODE_STRING;
typedef struct { UINT64 VolumeSerialNumber;FILE_ID_128 FileId; } SAFEUPLOAD_STAGE_IDENTITY_V19;
typedef struct { UINT32 Version,StructSize;GUID ReservationId;SAFEUPLOAD_STAGE_IDENTITY_V19 StageIdentity;UINT64 DestinationGeneration;UINT32 Kind; } SAFEUPLOAD_STAGE_VERSION_V19;
typedef struct { UINT32 Version,StructSize;SAFEUPLOAD_STAGE_IDENTITY_V19 StageIdentity;UINT64 DestinationGeneration; } SAFEUPLOAD_STAGE_SEAL_V19;
typedef struct { SAFEUPLOAD_STAGE_SEAL_V19 Seal;UINT32 Failure,Reserved; } SAFEUPLOAD_STAGE_RESOURCE_SEAL_V31;
#define SAFEUPLOAD_STAGE_RESOURCE_SEAL_VERSION 31u
typedef struct { SAFEUPLOAD_STAGE_SEAL_V19 Seal;LONGLONG CreationTime,LastAccessTime,LastWriteTime;UINT32 FileAttributes,Reserved; } SAFEUPLOAD_STAGE_SEAL_METADATA;
typedef struct { UINT32 Version,StructSize;UINT64 RequestId;UINT32 Operation,RequestorProcessId,Reserved,PathLength,ImageNameLength;WCHAR Path[512],ImageName[64]; } SAFEUPLOAD_REQUEST;
typedef struct { SAFEUPLOAD_REQUEST Request;struct { UINT32 StageNameLength; } Response; } SAFEUPLOAD_EXCHANGE,*PSAFEUPLOAD_EXCHANGE;
static struct { int64_t NextRequestId; } SafeUploadData;
#define _In_
#define _In_opt_
#define _Out_opt_
#define PAGED_CODE() ((void)0)
#define TRUE 1
#define FALSE 0
#define NT_SUCCESS(s) ((s)>=0)
#define STATUS_INVALID_PARAMETER (-1)
#define STATUS_INSUFFICIENT_RESOURCES (-2)
#define STATUS_INVALID_BUFFER_SIZE (-3)
#define SAFEUPLOAD_PROTOCOL_VERSION 18u
#define SAFEUPLOAD_STAGE_EXTENSION_VERSION 20u
#define SAFEUPLOAD_VERDICT_DENY 0u
#define SAFEUPLOAD_OPERATION_STAGE_DISCARD 5u
#define SAFEUPLOAD_OPERATION_STAGE_SEAL 4u
#define SAFEUPLOAD_STAGE_DISCARD_KIND_PRIVATE_VERSION 1u
#define SAFEUPLOAD_STAGE_DISCARD_KIND_UNATTACHED_ALLOCATION 5u
#define SAFEUPLOAD_STAGE_REPLY_DISCARD_PENDING 1u
#define SAFEUPLOAD_STAGE_REPLY_DISCARD_ACKNOWLEDGED 2u
#define SAFEUPLOAD_STAGE_REPLY_SEALED 3u
#define SAFEUPLOAD_MAX_PATH_BYTES 1022u
#define POOL_FLAG_NON_PAGED 1u
#define SAFEUPLOAD_POOL_TAG 1u
#define RtlZeroMemory(p,n) memset(p,0,n)
#define RtlCopyMemory(p,s,n) memcpy(p,s,n)
static SAFEUPLOAD_REQUEST sent;
static uint32_t reply=3;static int send_status,allocations;
static void *ExAllocatePool2(ULONG f,size_t n,ULONG t) { (void)f;(void)t;++allocations;return calloc(1,n); }
static void ExFreePoolWithTag(void *p,ULONG t) { (void)t;--allocations;free(p); }
static int64_t InterlockedIncrement64(int64_t *p) { return ++*p; }
static NTSTATUS StageSendV19Exchange(PSAFEUPLOAD_EXCHANGE e,BOOLEAN alloc,UINT32 *verdict,BOOLEAN *answered) {
 (void)alloc;sent=e->Request;e->Response.StageNameLength=reply;*answered=TRUE;*verdict=1;return send_status;
}
static NTSTATUS SafeUploadStageExchangeResult(NTSTATUS s,BOOLEAN a,UINT32 v) { assert(a && v==1);return s; }
'''

WIRE_CASES = r'''
int main(void) {
 assert(sizeof(SAFEUPLOAD_STAGE_SEAL_V19)==40 && sizeof(SAFEUPLOAD_STAGE_SEAL_METADATA)==72);
 WCHAR path[]={1,2};UNICODE_STRING name={4,4,path};SAFEUPLOAD_STAGE_IDENTITY_V19 id={.VolumeSerialNumber=9};
 FILE_BASIC_INFORMATION basic={.CreationTime={100},.LastAccessTime={200},.LastWriteTime={300},.FileAttributes=0x2023};
 assert(SafeUploadStageSealVersionV19(42,&name,&id,7,&basic,FALSE)==0 && !allocations);
 assert(sent.ImageNameLength==72 && sent.PathLength==4 && sent.Operation==4 && sent.Reserved==20);
 SAFEUPLOAD_STAGE_SEAL_METADATA seal;memcpy(&seal,sent.ImageName,sizeof(seal));
 assert(seal.Seal.StructSize==72 && seal.Seal.Version==20 && seal.Seal.DestinationGeneration==7 && seal.Seal.StageIdentity.VolumeSerialNumber==9);
 assert(seal.CreationTime==100 && seal.LastAccessTime==200 && seal.LastWriteTime==300 && seal.FileAttributes==0x2023 && !seal.Reserved);
 for(size_t i=72;i<sizeof(sent.ImageName);++i)assert(!((uint8_t*)sent.ImageName)[i]);
 assert(SafeUploadStageSealVersionV19(42,&name,&id,7,&basic,TRUE)==0 && !allocations);
 assert(sent.ImageNameLength==48 && sent.Reserved==31);
 SAFEUPLOAD_STAGE_RESOURCE_SEAL_V31 failed;memcpy(&failed,sent.ImageName,sizeof(failed));
 assert(sizeof(failed)==48 && failed.Seal.Version==31 && failed.Seal.StructSize==48 && failed.Failure==1 && !failed.Reserved);
 assert(failed.Seal.DestinationGeneration==7 && failed.Seal.StageIdentity.VolumeSerialNumber==9);
 for(size_t i=48;i<sizeof(sent.ImageName);++i)assert(!((uint8_t*)sent.ImageName)[i]);
 reply=99;assert(SafeUploadStageSealVersionV19(42,&name,&id,7,&basic,FALSE)==STATUS_INVALID_BUFFER_SIZE && !allocations);
 reply=3;send_status=-9;assert(SafeUploadStageSealVersionV19(42,&name,&id,7,&basic,FALSE)==-9 && !allocations);send_status=0;
 assert(SafeUploadStageSealVersionV19(42,&name,&id,7,NULL,FALSE)==STATUS_INVALID_PARAMETER && !allocations);
 puts("production metadata seal wire PASS: 72-byte payload, exact tuple/dates/flags, zero tail, failures and balanced ownership");
}
'''


class Metadata(unittest.TestCase):
    def test_production_seal_protocol_and_forward_declarations(self):
        protocol = ROOT / 'driver/SafeUpload.Minifilter/StageProtocol.c'
        text = protocol.read_text()
        declaration = re.search(r'static NTSTATUS StageSendVersionRequestV19\([^;]+;', text)[0]
        header = (ROOT / 'driver/SafeUpload.Minifilter/Stage.h').read_text()
        public_declaration = re.search(r'NTSTATUS SafeUploadStageSealVersionV19\([^;]+;', header)[0]
        program = WIRE_SHIM + declaration + public_declaration + body('StageSendVersionRequestV19', protocol) + body('SafeUploadStageSealVersionV19', protocol) + WIRE_CASES
        out = ROOT / '.scratch/checks/metadata'
        out.mkdir(parents=True, exist_ok=True)
        (out / 'wire.c').write_text(program)
        for cc in ('gcc', 'clang'):
            subprocess.run([cc, '-std=c11', '-Wall', '-Wextra', '-Werror', '-fsanitize=undefined',
                            str(out / 'wire.c'), '-o', str(out / ('wire-' + cc))], check=True)
            subprocess.run([str(out / ('wire-' + cc))], check=True)

    def test_production_bodies_with_both_compilers(self):
        out = ROOT / '.scratch/checks/metadata'
        out.mkdir(parents=True, exist_ok=True)
        source = SHIM + '\n'.join(body(n) for n in ('StageBasicWritten', 'StageBasicReadonly', 'StageInitializeBasic', 'StageOverlayBasic', 'StageSetBasicInformation', 'StageCaptureSealBasic')) + CASES
        (out / 'fixture.c').write_text(source)
        for cc in ('gcc', 'clang'):
            self.assertIsNotNone(shutil.which(cc), cc)
            subprocess.run([cc, '-std=c11', '-Wall', '-Wextra', '-Werror', '-fsanitize=undefined',
                            str(out / 'fixture.c'), '-o', str(out / cc)], check=True)
            subprocess.run([str(out / cc)], check=True)

    def test_seal_query_and_rpc_run_outside_namespace_resource(self):
        source = SOURCE.read_text()
        perform = source[source.index('static VOID StagePerformSealRpcs('):]
        perform = perform[:perform.index('static VOID StagePerformRenameRpcs(')]
        self.assertLess(perform.index('StageCaptureSealBasic(stream)'), perform.index('StageAcquire(&StageNamespaceResource)'))
        self.assertLess(perform.index('SafeUploadStageSealVersionV19('), perform.index('StageAcquire(&StageNamespaceResource)'))
        for name in ('StageSetBasicInformation', 'StageCaptureSealBasic'):
            self.assertIn('#pragma alloc_text(PAGE, ' + name + ')', source)
            self.assertIn('PAGED_CODE()', body(name))
        self.assertNotIn('FltSetInformationFile', body('StageSetBasicInformation'))
        self.assertIn('StageOverlayBasic(Stream, &all->BasicInformation)', source)
        self.assertIn('StageOverlayBasic(Stream, (PFILE_BASIC_INFORMATION)output)', source)
        disposition = source[source.index('static NTSTATUS StageSetDisposition('):source.index('static NTSTATUS StageRename(')]
        self.assertLess(disposition.index('StageBasicReadonly(Stream)'), disposition.index('StageCancelSealedPrivate(Stream'))
        rename = source[source.index('static NTSTATUS StageRename('):]
        self.assertLess(rename.index('StageBasicReadonly(targetStream)'), rename.index('StageCancelSealedPrivate(targetStream'))


if __name__ == '__main__':
    unittest.main()
