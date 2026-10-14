/* Actual production bodies are inserted by the runner. Mock only the OS/map
 * boundaries; poison allocations so missing reply initialization is visible. */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
typedef void VOID, *PVOID, *PEPROCESS, *PSECURITY_DESCRIPTOR;
typedef int32_t NTSTATUS, INT32;
typedef int64_t LONG64, INT64;
typedef uint32_t ULONG, UINT32, *PULONG;
typedef uint16_t WCHAR, USHORT, UINT16, SECURITY_DESCRIPTOR_CONTROL;
typedef uint64_t UINT64;
typedef uint8_t UCHAR, BOOLEAN, KIRQL;
typedef size_t SIZE_T;
typedef struct { UCHAR Bytes[16]; } GUID;
typedef struct { UINT64 VolumeSerialNumber; UCHAR FileId[16]; } SAFEUPLOAD_STAGE_IDENTITY_V19;
typedef struct { UINT32 Version, StructSize, Command, Reserved; } SAFEUPLOAD_CONTROL;
typedef struct _LIST_ENTRY { struct _LIST_ENTRY *Flink, *Blink; } LIST_ENTRY, *PLIST_ENTRY;
typedef struct { UCHAR Revision, Reserved; USHORT Control; ULONG Offsets[4]; } SECURITY_DESCRIPTOR_RELATIVE;
#define TRUE 1
#define FALSE 0
#define PASSIVE_LEVEL 0
#define DISPATCH_LEVEL 2
#define STATUS_SUCCESS 0
#define STATUS_INVALID_BUFFER_SIZE -1
#define STATUS_INVALID_PARAMETER -2
#define STATUS_DEVICE_NOT_READY -3
#define STATUS_ACCESS_DENIED -4
#define STATUS_INSUFFICIENT_RESOURCES -5
#define STATUS_INTEGER_OVERFLOW -6
#define STATUS_RETRY -7
#define STATUS_NOT_FOUND -8
#define STATUS_ACCESS_VIOLATION -9
#define STATUS_INVALID_SECURITY_DESCR -10
#define STATUS_BUFFER_TOO_SMALL -11
#define NT_SUCCESS(s) ((s) >= 0)
#define SAFEUPLOAD_PROTOCOL_VERSION 18
#define SAFEUPLOAD_STAGE_CREATE_SECURITY_LIMIT 65536
#define SE_SELF_RELATIVE 0x8000
#define OWNER_SECURITY_INFORMATION 1
#define GROUP_SECURITY_INFORMATION 2
#define DACL_SECURITY_INFORMATION 4
#define SACL_SECURITY_INFORMATION 8
#define BP_TAG 0
#define BP_REJECTED 6
#define BP_ACKNOWLEDGED 4
#define POOL_FLAG_NON_PAGED 1
#define _In_
#define _Out_
#define _Outptr_result_nullonfailure_
#define NT_ASSERT assert
#define PAGED_CODE() assert(CurrentIrql == PASSIVE_LEVEL)
#define C_ASSERT(e) _Static_assert((e), #e)
#define FIELD_OFFSET(t, f) offsetof(t, f)
#define CONTAINING_RECORD(p, t, f) ((t *)((char *)(p) - offsetof(t, f)))
#define RtlEqualMemory(a, b, n) (memcmp((a), (b), (n)) == 0)
#define RtlCopyMemory memcpy
#define RtlZeroMemory(p, n) memset((p), 0, (n))
/* Probe faults only; this adapter does not model Windows SEH semantics. */
static jmp_buf Exception;
#define try if (setjmp(Exception) == 0) for (int once = 1; once; once = 0)
#define except(x) else
#define leave break
#define GetExceptionCode() STATUS_ACCESS_VIOLATION
/* PRODUCTION_WIRE */
typedef struct { LIST_ENTRY Link; SAFEUPLOAD_BOUND_PUBLICATION_FACTS_ROW Facts; int Uses; } BP_RECORD, *PBP_RECORD;
static LIST_ENTRY BpRecords;
static BP_RECORD Record;
static GUID BpDriver = {{1}};
static ULONG BpBoot = 1, BpCount;
static UINT64 BpRevision;
static BOOLEAN BpReplayUsable;
static int BpCalls, Allocations, AllocationAttempt, FailAllocation, ProcessPins, MutationCalls, Destroyed, WriteProbes;
static int Fault, IdentityCalls, ValidDescriptor, ValidRelative;
static NTSTATUS ConvertResult;
static ULONG DescriptorBytes;
static KIRQL CurrentIrql;
static UCHAR *UserOutput;
static ULONG UserOutputLength;
enum { NoFault, ReadProbe, WriteProbe, Enter, Auth, Pin, IdentityRecheck, Mutation };
static int KeGetCurrentIrql(void) { return CurrentIrql; }
static PVOID ExAllocatePool2(int flags, size_t bytes, int tag)
{
    assert(CurrentIrql == PASSIVE_LEVEL && flags == POOL_FLAG_NON_PAGED && tag == BP_TAG);
    if (++AllocationAttempt == FailAllocation) return NULL;
    PVOID p = malloc(bytes); assert(p != NULL); memset(p, 0xa5, bytes); ++Allocations; return p;
}
static void ExFreePoolWithTag(PVOID p, int tag)
{ assert(CurrentIrql == PASSIVE_LEVEL && tag == BP_TAG && p != NULL && Allocations > 0); --Allocations; free(p); }
static void BpAcquire(KIRQL *irql) { assert(CurrentIrql == PASSIVE_LEVEL); *irql = CurrentIrql; CurrentIrql = DISPATCH_LEVEL; }
static void BpRelease(KIRQL irql) { assert(CurrentIrql == DISPATCH_LEVEL); CurrentIrql = irql; }
static BOOLEAN BpEnter(void) { if (Fault == Enter) return FALSE; ++BpCalls; return TRUE; }
static void ExReleaseRundownProtection(int *p) { assert(*p > 0); --*p; }
static BOOLEAN SafeUploadConnectionGetAuthenticatedIdentity(PVOID given, PVOID *cookie, LONG64 *epoch, PULONG pid)
{ if (Fault == Auth) return FALSE; *cookie = given; *epoch = 1; *pid = 1; return TRUE; }
static BOOLEAN SafeUploadConnectionPinAuthenticatedProcess(PVOID cookie, LONG64 epoch, PEPROCESS *process)
{ (void)cookie; assert(epoch == 1); if (Fault == Pin) return FALSE; ++ProcessPins; *process = &Record; return TRUE; }
static void SafeUploadConnectionReleaseAuthenticatedProcess(PVOID cookie, PEPROCESS process)
{ (void)cookie; assert(process == &Record && ProcessPins == 1); --ProcessPins; }
static PEPROCESS PsGetCurrentProcess(void) { return &Record; }
static UINT64 SafeUploadStageProtocolNativeAuthority(void) { return 1; }
static BOOLEAN SafeUploadConnectionIsAuthenticatedIdentity(PVOID cookie, LONG64 epoch)
{ (void)cookie; assert(epoch == 1); ++IdentityCalls; return Fault != IdentityRecheck; }
static void ProbeForRead(PVOID p, ULONG bytes, ULONG alignment)
{ assert(p && bytes > 0 && alignment == 4 && CurrentIrql == PASSIVE_LEVEL); if (Fault == ReadProbe) longjmp(Exception, 1); }
static void ProbeForWrite(PVOID p, ULONG bytes, ULONG alignment)
{
    assert(p == UserOutput && bytes <= UserOutputLength && alignment == 4 && CurrentIrql == PASSIVE_LEVEL);
    ++WriteProbes; if (Fault == WriteProbe) longjmp(Exception, 1);
}
/* PRODUCTION_HELPERS */
static NTSTATUS BpMutation(const SAFEUPLOAD_BOUND_PUBLICATION_REQUEST *request, PVOID cookie,
    PEPROCESS process, UINT64 epoch, UINT64 authority, PSAFEUPLOAD_BOUND_PUBLICATION_REPLY reply)
{
    (void)cookie; assert(process == &Record); ++MutationCalls;
    if (Fault == Mutation) return STATUS_ACCESS_DENIED;
    BpReply(request, epoch, authority, BP_REJECTED, reply); return STATUS_SUCCESS;
}
static PBP_RECORD BpFind(const GUID *nonce)
{ assert(CurrentIrql == DISPATCH_LEVEL); return BpCount && BpEqual(nonce, &Record.Facts.Create.CreateNonce, sizeof(*nonce)) ? &Record : NULL; }
static BOOLEAN BpTerminal(PBP_RECORD r) { return r->Uses == 1; }
static void RemoveEntryList(PLIST_ENTRY link) { link->Blink->Flink = link->Flink; link->Flink->Blink = link->Blink; }
static void BpChangedLocked(void) { assert(CurrentIrql == DISPATCH_LEVEL); ++BpRevision; }
static void BpDestroy(PBP_RECORD r) { assert(CurrentIrql == PASSIVE_LEVEL && r == &Record && r->Uses == 0); ++Destroyed; }
static BOOLEAN RtlValidSecurityDescriptor(PSECURITY_DESCRIPTOR p) { return p != NULL && ValidDescriptor; }
static ULONG RtlLengthSecurityDescriptor(PSECURITY_DESCRIPTOR p) { (void)p; return DescriptorBytes; }
static NTSTATUS RtlAbsoluteToSelfRelativeSD(PSECURITY_DESCRIPTOR input, PSECURITY_DESCRIPTOR output, PULONG bytes)
{
    if (output == NULL) { *bytes = DescriptorBytes; return STATUS_BUFFER_TOO_SMALL; }
    if (ConvertResult != STATUS_SUCCESS) return ConvertResult;
    memcpy(output, input, *bytes); ((SECURITY_DESCRIPTOR_RELATIVE *)output)->Control |= SE_SELF_RELATIVE;
    return STATUS_SUCCESS;
}
static BOOLEAN RtlValidRelativeSecurityDescriptor(PSECURITY_DESCRIPTOR p, ULONG bytes, ULONG mask)
{ assert(p && bytes == DescriptorBytes && mask == 15); return ValidRelative; }
/* PRODUCTION_BODIES */

static void reset(void)
{
    assert(Allocations == 0 && BpCalls == 0 && ProcessPins == 0 && CurrentIrql == PASSIVE_LEVEL);
    AllocationAttempt = FailAllocation = Fault = MutationCalls = Destroyed = WriteProbes = IdentityCalls = 0;
    BpRevision = 1; BpCount = 0; BpReplayUsable = TRUE;
    BpRecords.Flink = BpRecords.Blink = &BpRecords;
    memset(&Record, 0, sizeof(Record));
    ValidDescriptor = ValidRelative = TRUE; ConvertResult = STATUS_SUCCESS;
    DescriptorBytes = sizeof(SECURITY_DESCRIPTOR_RELATIVE);
}
static BP_INPUT input(ULONG phase)
{
    BP_INPUT q = {0};
    q.Mutation.Control = (SAFEUPLOAD_CONTROL){SAFEUPLOAD_PROTOCOL_VERSION,
        phase <= 3 ? sizeof(q.Mutation) : sizeof(q.Facts), SAFEUPLOAD_CONTROL_BOUND_PUBLICATION, 0};
    q.Mutation.ExtensionVersion = SAFEUPLOAD_BOUND_PUBLICATION_VERSION; q.Mutation.Phase = phase;
    if (phase == SAFEUPLOAD_BOUND_PUBLICATION_ACK) {
        q.Ack.DriverInstanceId = BpDriver; q.Ack.CreateNonce.Bytes[0] = 2; q.Ack.ExpectedRevision = BpRevision;
    }
    return q;
}
static void install_record(void)
{
    Record.Link.Flink = Record.Link.Blink = &BpRecords;
    BpRecords.Flink = BpRecords.Blink = &Record.Link; BpCount = 1; Record.Uses = 1;
    Record.Facts.Create.CreateNonce.Bytes[0] = 2;
}
static void control(ULONG phase, ULONG outputBytes, NTSTATUS expected)
{
    BP_INPUT q = input(phase);
    /* Extra canaries catch writes even if the mock probe failed to reject one. */
    UCHAR *storage = malloc(sizeof(SAFEUPLOAD_BOUND_PUBLICATION_FACTS_PAGE) + 32);
    assert(storage); memset(storage, 0xcd, sizeof(SAFEUPLOAD_BOUND_PUBLICATION_FACTS_PAGE) + 32);
    UserOutput = storage + 8; UserOutputLength = outputBytes;
    ULONG returned = 123;
    NTSTATUS status = SafeUploadBoundPublicationControl(&Record, &q, q.Mutation.Control.StructSize,
        UserOutput, outputBytes, &returned);
    assert(status == expected);
    if (status == STATUS_SUCCESS) {
        assert(returned == outputBytes && WriteProbes == 1);
        if (phase == SAFEUPLOAD_BOUND_PUBLICATION_FACTS) {
            PSAFEUPLOAD_BOUND_PUBLICATION_FACTS_PAGE page = (PVOID)UserOutput;
            assert(page->StructSize == outputBytes && page->Count == BpCount && page->Complete == 1 && page->Reserved == 0);
            for (ULONG i = page->Count; i < SAFEUPLOAD_BOUND_PUBLICATION_PAGE_ROWS; ++i)
                assert(BpZero(&page->Rows[i], sizeof(page->Rows[i])));
        } else {
            PSAFEUPLOAD_BOUND_PUBLICATION_REPLY reply = (PVOID)UserOutput;
            assert(reply->Phase == phase && reply->Reserved == 0 && reply->ReservedEnd == 0);
        }
    } else { assert(returned == 0); for (size_t i = 0; i < outputBytes; ++i) assert(UserOutput[i] == 0xcd); }
    for (size_t i = 0; i < 8; ++i) assert(storage[i] == 0xcd);
    for (size_t i = 8 + outputBytes; i < sizeof(SAFEUPLOAD_BOUND_PUBLICATION_FACTS_PAGE) + 32; ++i) assert(storage[i] == 0xcd);
    free(storage);
    assert(Allocations == 0 && BpCalls == 0 && ProcessPins == 0 && CurrentIrql == PASSIVE_LEVEL);
}
static void security(BOOLEAN relative, NTSTATUS expected)
{
    SECURITY_DESCRIPTOR_RELATIVE source = {1, 0, relative ? SE_SELF_RELATIVE : 0, {0}};
    PSECURITY_DESCRIPTOR captured = (PVOID)(uintptr_t)1;
    ULONG bytes = 123;
    NTSTATUS status = BpCaptureSecurity(&source, &captured, &bytes);
    assert(status == expected);
    if (status == STATUS_SUCCESS) { assert(captured && bytes == sizeof(source)); ExFreePoolWithTag(captured, BP_TAG); }
    else assert(captured == NULL && bytes == 0);
    assert(Allocations == 0);
}
int main(void)
{
    const ULONG page = sizeof(SAFEUPLOAD_BOUND_PUBLICATION_FACTS_PAGE), reply = sizeof(SAFEUPLOAD_BOUND_PUBLICATION_REPLY);
    for (ULONG phase = 1; phase <= 5; ++phase) {
        ULONG exact = phase == SAFEUPLOAD_BOUND_PUBLICATION_FACTS ? page : reply;
        const ULONG invalid[] = {0, 1, exact - 1, exact + 1, phase == SAFEUPLOAD_BOUND_PUBLICATION_FACTS ? reply : page};
        for (size_t i = 0; i < sizeof(invalid) / sizeof(*invalid); ++i) {
            reset(); if (phase == 5) install_record();
            control(phase, invalid[i], STATUS_INVALID_PARAMETER);
            assert(MutationCalls == 0 && Destroyed == 0 && WriteProbes == 0);
        }
        reset(); if (phase == 5) install_record(); control(phase, exact, STATUS_SUCCESS);
        if (phase == 5) assert(Destroyed == 1 && BpCount == 0);
        const NTSTATUS errors[] = {0, STATUS_ACCESS_VIOLATION, STATUS_ACCESS_VIOLATION, STATUS_DEVICE_NOT_READY,
            STATUS_ACCESS_DENIED, STATUS_ACCESS_DENIED, STATUS_ACCESS_DENIED};
        for (int fault = ReadProbe; fault <= IdentityRecheck; ++fault) {
            reset(); if (phase == 5) install_record(); Fault = fault; control(phase, exact, errors[fault]);
            /* Losing ACK's reply must not replay or undo the completed retirement. */
            if (phase == 5 && (fault == WriteProbe || fault == IdentityRecheck)) assert(Destroyed == 1);
        }
        reset(); FailAllocation = 1; control(phase, exact, STATUS_INSUFFICIENT_RESOURCES);
    }
    reset(); FailAllocation = 2; control(4, page, STATUS_INSUFFICIENT_RESOURCES);
    reset(); install_record(); control(4, page, STATUS_SUCCESS);
    reset(); BpReplayUsable = FALSE; control(4, page, STATUS_INTEGER_OVERFLOW);
    reset(); control(5, reply, STATUS_NOT_FOUND);
    reset(); Fault = Mutation; control(1, reply, STATUS_ACCESS_DENIED);
    reset(); security(TRUE, STATUS_SUCCESS);
    reset(); security(FALSE, STATUS_SUCCESS);
    reset(); FailAllocation = 1; security(TRUE, STATUS_INSUFFICIENT_RESOURCES);
    reset(); ValidDescriptor = FALSE; security(TRUE, STATUS_INVALID_SECURITY_DESCR);
    reset(); ValidRelative = FALSE; security(FALSE, STATUS_INVALID_SECURITY_DESCR);
    reset(); ConvertResult = 1; security(FALSE, STATUS_INVALID_SECURITY_DESCR);
    reset(); ConvertResult = STATUS_ACCESS_DENIED; security(FALSE, STATUS_ACCESS_DENIED);
    reset(); DescriptorBytes = SAFEUPLOAD_STAGE_CREATE_SECURITY_LIMIT + 1; security(TRUE, STATUS_INVALID_BUFFER_SIZE);
    puts("PASS: V26 fixed-buffer canaries, zeroed replies, allocation/auth/probe failures, ACK retirement and security ownership");
    return 0;
}
