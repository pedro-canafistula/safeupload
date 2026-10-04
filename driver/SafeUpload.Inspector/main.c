/*++

Module Name:

    main.c

Abstract:

    SafeUpload.Inspector - the v1 user-mode client of the SafeUpload
    minifilter's communication port.

    This program is deliberately stupid. It connects to the port, reads one
    request at a time, applies a single hard-coded test rule, and answers.
    Its only job is to prove the kernel/user round trip end to end: message
    layout, request/response correlation, allow and deny both reaching the
    file system.

    There is no detection logic here either. Business rules RN-001..RN-004
    (CPF, CNPJ, Luhn, password heuristics) belong to the WPF agent that
    will replace this program; the contract it has to speak is Protocol.h.

    Test rule: deny any path containing "BLOQUEAR_TESTE", allow everything
    else.

Environment:

    User mode

--*/

#include <windows.h>
#include <fltUser.h>
#include <aclapi.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <strsafe.h>

#include "..\SafeUpload.Minifilter\Protocol.h"

//
//  The string whose presence in a path makes this test client answer DENY.
//

#define SAFEUPLOAD_TEST_BLOCK_TOKEN L"BLOQUEAR_TESTE"

//
//  Signalled once the port is connected, so that a script driving this
//  program can tell when it is ready.
//
//  An event rather than a marker in the output, because the obvious
//  alternative - watching the log file for a line - is file I/O, and file
//  I/O on this machine goes through the very filter this program answers
//  for. A watcher polling the log makes the inspector wait on the watcher
//  that is waiting on the inspector.
//

#define SAFEUPLOAD_READY_EVENT_NAME L"Global\\SafeUploadInspectorReady"

//
//  What FilterGetMessage delivers: the filter manager's header followed by
//  our payload. Natural alignment is kept - FILTER_MESSAGE_HEADER is 16
//  bytes, so the request lands 8-byte aligned exactly as the kernel laid
//  it out.
//

typedef struct _SAFEUPLOAD_MESSAGE {

    FILTER_MESSAGE_HEADER Header;
    SAFEUPLOAD_REQUEST Request;

} SAFEUPLOAD_MESSAGE;

//
//  What FilterReplyMessage sends back.
//

typedef struct _SAFEUPLOAD_REPLY {

    FILTER_REPLY_HEADER Header;
    SAFEUPLOAD_RESPONSE Response;

} SAFEUPLOAD_REPLY;


//
//  The scope this test client pushes to the driver on connect.
//
//  Mirrors the defaults in LocalPolicyStore so that kernel and user mode
//  agree, plus the smoke test directory.
//

static const WCHAR *SafeUploadTestExtensions[] = {
    L".txt", L".csv", L".docx", L".xlsx"
};

static const WCHAR *SafeUploadTestPrefixes[] = {
    L"C:\\safeupload-teste"
};

//
//  Where a file is worth reading to find out whether it is sensitive.
//
//  A different question from the destination list above, and normally much
//  broader in production: user document folders, rather than the handful of
//  places a file must not reach.
//

static const WCHAR *SafeUploadTestSourcePrefixes[] = {
    L"C:\\safeupload-origem"
};


static
BOOL
DosPathToNtPath (
    _In_z_ const WCHAR *DosPath,
    _Out_writes_z_(NtPathChars) WCHAR *NtPath,
    _In_ size_t NtPathChars
    )
    /*
        NtPath is terminated on every path out of this routine: the two
        early failures write the terminator before returning FALSE, and
        StringCchPrintfW terminates even when it truncates.
    */
/*++

Routine Description:

    Turns C:\folder into \Device\HarddiskVolumeN\folder.

    This conversion belongs here, in user mode, and happens once when the
    policy is built. The kernel only ever sees NT paths, because a drive
    letter is a per-logon-session symbolic link that means nothing to a
    filter - and converting on every operation would put a lookup in the
    hot path.

Arguments:

    DosPath - Path beginning with a drive letter and a colon.

    NtPath - Receives the NT form.

    NtPathChars - Capacity of NtPath, in characters.

Return Value:

    TRUE on success. FALSE when the path has no drive letter or the drive
    has no device mapping.

--*/
{
    WCHAR drive[3];
    WCHAR device[MAX_PATH];

    NtPath[0] = L'\0';

    if (DosPath[0] == L'\0' || DosPath[1] != L':') {

        return FALSE;
    }

    drive[0] = DosPath[0];
    drive[1] = L':';
    drive[2] = L'\0';

    if (QueryDosDeviceW( drive, device, ARRAYSIZE( device ) ) == 0) {

        return FALSE;
    }

    return SUCCEEDED( StringCchPrintfW( NtPath, NtPathChars, L"%s%s", device, DosPath + 2 ) );
}


static
HRESULT
SendPolicy (
    _In_ HANDLE Port
    )
/*++

Routine Description:

    Pushes the scope policy down to the driver.

    Until this arrives the driver considers nothing to be in scope, which is
    the correct default: without a policy there is no monitored destination
    and no monitored extension. So this has to happen right after connecting,
    before any traffic is expected.

Arguments:

    Port - The connected communication port.

Return Value:

    The result of FilterSendMessage.

--*/
{
    //
    //  From the heap, not the stack: the message is close to 20 KB and a
    //  local of that size is a habit that stops being harmless the moment
    //  the same code is reused somewhere with a smaller stack.
    //

    SAFEUPLOAD_POLICY_MESSAGE *policy;
    WCHAR ntPath[SAFEUPLOAD_MAX_PREFIX_CHARS];
    DWORD returned = 0;
    UINT32 index;
    HRESULT hr;

    policy = (SAFEUPLOAD_POLICY_MESSAGE *) calloc( 1, sizeof( SAFEUPLOAD_POLICY_MESSAGE ) );

    if (policy == NULL) {

        return E_OUTOFMEMORY;
    }

    policy->Control.Version = SAFEUPLOAD_PROTOCOL_VERSION;
    policy->Control.StructSize = sizeof( SAFEUPLOAD_POLICY_MESSAGE );
    policy->Control.Command = SAFEUPLOAD_CONTROL_SET_POLICY;

    //
    //  Removable media and network shares are destinations in their own
    //  right, with no prefix needed: every path on them leaves the machine.
    //

    policy->Flags = SAFEUPLOAD_POLICY_FLAG_REMOVABLE | SAFEUPLOAD_POLICY_FLAG_NETWORK;

    for (index = 0; index < ARRAYSIZE( SafeUploadTestExtensions ); index += 1) {

        StringCchCopyW( policy->Extensions[index],
                        SAFEUPLOAD_MAX_EXTENSION_CHARS,
                        SafeUploadTestExtensions[index] );
    }

    policy->ExtensionCount = ARRAYSIZE( SafeUploadTestExtensions );

    for (index = 0; index < ARRAYSIZE( SafeUploadTestPrefixes ); index += 1) {

        if (!DosPathToNtPath( SafeUploadTestPrefixes[index], ntPath, ARRAYSIZE( ntPath ) )) {

            wprintf( L"AVISO: nao foi possivel converter %s para forma NT.\n",
                     SafeUploadTestPrefixes[index] );
            continue;
        }

        StringCchCopyW( policy->Prefixes[policy->PrefixCount],
                        SAFEUPLOAD_MAX_PREFIX_CHARS,
                        ntPath );

        wprintf( L"Destino: %s  ->  %s\n", SafeUploadTestPrefixes[index], ntPath );

        policy->PrefixCount += 1;
    }

    for (index = 0; index < ARRAYSIZE( SafeUploadTestSourcePrefixes ); index += 1) {

        if (!DosPathToNtPath( SafeUploadTestSourcePrefixes[index], ntPath, ARRAYSIZE( ntPath ) )) {

            wprintf( L"AVISO: nao foi possivel converter %s para forma NT.\n",
                     SafeUploadTestSourcePrefixes[index] );
            continue;
        }

        StringCchCopyW( policy->SourcePrefixes[policy->SourcePrefixCount],
                        SAFEUPLOAD_MAX_PREFIX_CHARS,
                        ntPath );

        wprintf( L"Origem : %s  ->  %s\n", SafeUploadTestSourcePrefixes[index], ntPath );

        policy->SourcePrefixCount += 1;
    }

    hr = FilterSendMessage( Port,
                            policy,
                            sizeof( SAFEUPLOAD_POLICY_MESSAGE ),
                            NULL,
                            0,
                            &returned );

    free( policy );

    return hr;
}


static
BOOL
ContainsTokenNoCase (
    _In_z_ const WCHAR *Text,
    _In_z_ const WCHAR *Token
    )
/*++

Routine Description:

    Case-insensitive substring test, written out rather than pulled from
    shlwapi to keep this program free of extra dependencies.

Arguments:

    Text - String to search. NUL-terminated.

    Token - String to look for. NUL-terminated, must not be empty.

Return Value:

    TRUE if Token occurs in Text, ignoring case.

--*/
{
    size_t textLength = wcslen( Text );
    size_t tokenLength = wcslen( Token );
    size_t start;
    size_t offset;

    if (tokenLength == 0 || textLength < tokenLength) {

        return FALSE;
    }

    for (start = 0; start + tokenLength <= textLength; start += 1) {

        for (offset = 0; offset < tokenLength; offset += 1) {

            if (towupper( Text[start + offset] ) != towupper( Token[offset] )) {

                break;
            }
        }

        if (offset == tokenLength) {

            return TRUE;
        }
    }

    return FALSE;
}


static
const WCHAR *
OperationName (
    _In_ UINT32 Operation
    )
{
    switch (Operation) {

        case SAFEUPLOAD_OPERATION_CREATE:
            return L"CREATE";

        case SAFEUPLOAD_OPERATION_READ:
            return L"READ";

        case SAFEUPLOAD_OPERATION_STAGE_ALLOCATE:
            return L"STAGE";

        default:
            return L"?";
    }
}


static
int
PrintCounters (
    VOID
    )
/*++

Routine Description:

    Connects to the port, asks the driver for its counters, prints them and
    leaves.

    Run after the main inspector has stopped: the port accepts one client at
    a time, and the counters live in the driver, so they outlive whoever was
    connected.

Return Value:

    0 on success, non-zero on failure.

--*/
{
    SAFEUPLOAD_CONTROL control;
    SAFEUPLOAD_COUNTERS counters;
    HANDLE port = INVALID_HANDLE_VALUE;
    DWORD returned = 0;
    HRESULT hr;

    hr = FilterConnectCommunicationPort( SAFEUPLOAD_PORT_NAME,
                                         0,
                                         NULL,
                                         0,
                                         NULL,
                                         &port );

    if (FAILED( hr )) {

        wprintf( L"ERRO: nao foi possivel conectar na porta (hr = 0x%08X).\n", hr );
        return 2;
    }

    ZeroMemory( &control, sizeof( control ) );
    ZeroMemory( &counters, sizeof( counters ) );

    control.Version = SAFEUPLOAD_PROTOCOL_VERSION;
    control.StructSize = sizeof( SAFEUPLOAD_CONTROL );
    control.Command = SAFEUPLOAD_CONTROL_GET_COUNTERS;

    hr = FilterSendMessage( port,
                            &control,
                            sizeof( control ),
                            &counters,
                            sizeof( counters ),
                            &returned );

    CloseHandle( port );

    if (FAILED( hr ) || returned < sizeof( counters )) {

        wprintf( L"ERRO: o driver nao devolveu os contadores (hr = 0x%08X).\n", hr );
        return 3;
    }

    wprintf( L"CreatesSeen             : %llu\n", counters.CreatesSeen );
    wprintf( L"CreatesPastCheapGates   : %llu\n", counters.CreatesPastCheapGates );
    wprintf( L"ScopeEvaluations        : %llu\n", counters.ScopeEvaluations );
    wprintf( L"UserModeRoundTrips      : %llu\n", counters.UserModeRoundTrips );
    wprintf( L"CacheHits               : %llu\n", counters.CacheHits );
    wprintf( L"DeniedPreCreate         : %llu\n", counters.DeniedPreCreate );
    wprintf( L"DeniedPostCreate        : %llu\n", counters.DeniedPostCreate );
    wprintf( L"DeniedRename            : %llu\n", counters.DeniedRename );
    wprintf( L"AllowedWithoutInspection: %llu\n", counters.AllowedWithoutInspection );
    wprintf( L"TaintsRecorded          : %llu\n", counters.TaintsRecorded );
    wprintf( L"TaintLookups            : %llu\n", counters.TaintLookups );
    wprintf( L"TaintHits               : %llu\n", counters.TaintHits );
    wprintf( L"SetInformationSeen      : %llu\n", counters.SetInformationSeen );
    wprintf( L"RenamesSeen             : %llu\n", counters.RenamesSeen );
    wprintf( L"RenamesFromTainted      : %llu\n", counters.RenamesFromTainted );

    //
    //  Decode the class bitmap. Printing the raw words as well as the
    //  names keeps the output useful when a class shows up that this
    //  table does not know about.
    //

    wprintf( L"ClassesSeen             : %016llX %016llX\n",
             counters.ClassesSeenHigh, counters.ClassesSeenLow );

    {
        static const struct { ULONG Class; PCWSTR Name; } known[] = {
            {  4, L"FileBasicInformation" },
            { 10, L"FileRenameInformation" },
            { 11, L"FileLinkInformation" },
            { 13, L"FileDispositionInformation" },
            { 14, L"FilePositionInformation" },
            { 19, L"FileEndOfFileInformation" },
            { 20, L"FileAllocationInformation" },
            { 64, L"FileDispositionInformationEx" },
            { 65, L"FileRenameInformationEx" },
            { 72, L"FileLinkInformationEx" },
        };

        ULONG index;

        wprintf( L"  classes vistas        :" );

        for (index = 0; index < RTL_NUMBER_OF( known ); index += 1) {

            ULONG bit = known[ index ].Class;
            UINT64 word = (bit < 64) ? counters.ClassesSeenLow : counters.ClassesSeenHigh;
            ULONG shift = (bit < 64) ? bit : bit - 64;

            if ((word >> shift) & 1) {
                wprintf( L" %u=%s", bit, known[ index ].Name );
            }
        }

        wprintf( L"\n" );
    }


    //
    //  The ratio the whole design is judged by: how little of what the
    //  filter sees ever costs anything.
    //

    if (counters.CreatesSeen != 0) {

        wprintf( L"\nPassaram das portas baratas: %.4f%% dos creates\n",
                 (double) counters.CreatesPastCheapGates * 100.0 /
                 (double) counters.CreatesSeen );
    }

    if ((counters.CacheHits + counters.ScopeEvaluations) != 0) {

        wprintf( L"Acerto de cache            : %.1f%%\n",
                 (double) counters.CacheHits * 100.0 /
                 (double) (counters.CacheHits + counters.ScopeEvaluations) );
    }

    return 0;
}


#if defined(SAFEUPLOAD_STAGING_PROTOTYPE) && SAFEUPLOAD_STAGING_PROTOTYPE
static PCWSTR AdmissionEventName(_In_ UINT32 EventKind)
{
    switch (EventKind) {
        case SAFEUPLOAD_ADMISSION_TRACE_EVENT_PAGING_WRITE: return L"paging_write";
        case SAFEUPLOAD_ADMISSION_TRACE_EVENT_UNOWNED_NONPAGING_WRITE: return L"unowned_nonpaging_write";
        case SAFEUPLOAD_ADMISSION_TRACE_EVENT_SECTION_ACQUIRE: return L"section_acquire";
        case SAFEUPLOAD_ADMISSION_TRACE_EVENT_SECTION_RELEASE: return L"section_release";
        case SAFEUPLOAD_ADMISSION_TRACE_EVENT_INSTANCE_SETUP: return L"instance_setup";
        case SAFEUPLOAD_ADMISSION_TRACE_EVENT_EXPLICIT_PROBE: return L"explicit_probe";
        case SAFEUPLOAD_ADMISSION_TRACE_EVENT_FILE_CLEANUP: return L"file_cleanup";
        case SAFEUPLOAD_ADMISSION_TRACE_EVENT_FILE_CLOSE: return L"file_close";
        default: return L"unknown";
    }
}

static PCWSTR AdmissionMmDoesName(_In_ UINT32 Result)
{
    switch (Result) {
        case SAFEUPLOAD_ADMISSION_TRACE_MMDOES_NOT_APPLICABLE: return L"not_applicable";
        case SAFEUPLOAD_ADMISSION_TRACE_MMDOES_SKIPPED: return L"skipped";
        case SAFEUPLOAD_ADMISSION_TRACE_MMDOES_NO: return L"no";
        case SAFEUPLOAD_ADMISSION_TRACE_MMDOES_YES: return L"yes";
        default: return L"unknown";
    }
}

static PCWSTR AdmissionContextName(_In_ UINT32 State)
{
    switch (State) {
        case SAFEUPLOAD_ADMISSION_TRACE_CONTEXT_NOT_APPLICABLE: return L"not_applicable";
        case SAFEUPLOAD_ADMISSION_TRACE_CONTEXT_UNKNOWN: return L"unknown";
        case SAFEUPLOAD_ADMISSION_TRACE_CONTEXT_ABSENT: return L"absent";
        case SAFEUPLOAD_ADMISSION_TRACE_CONTEXT_PRESENT: return L"present";
        case SAFEUPLOAD_ADMISSION_TRACE_CONTEXT_NOT_QUERIED: return L"not_queried";
        default: return L"unknown";
    }
}

static PCWSTR AdmissionAttachClassName(_In_ UINT32 AttachClass)
{
    switch (AttachClass) {
        case SAFEUPLOAD_ADMISSION_TRACE_ATTACH_AUTOMATIC: return L"automatic";
        case SAFEUPLOAD_ADMISSION_TRACE_ATTACH_MANUAL: return L"manual";
        case SAFEUPLOAD_ADMISSION_TRACE_ATTACH_AUTOMATIC | SAFEUPLOAD_ADMISSION_TRACE_ATTACH_MANUAL:
            return L"automatic|manual";
        case SAFEUPLOAD_ADMISSION_TRACE_ATTACH_NEWLY_MOUNTED: return L"newly_mounted";
        case SAFEUPLOAD_ADMISSION_TRACE_ATTACH_AUTOMATIC | SAFEUPLOAD_ADMISSION_TRACE_ATTACH_NEWLY_MOUNTED:
            return L"automatic|newly_mounted";
        case SAFEUPLOAD_ADMISSION_TRACE_ATTACH_MANUAL | SAFEUPLOAD_ADMISSION_TRACE_ATTACH_NEWLY_MOUNTED:
            return L"manual|newly_mounted";
        case SAFEUPLOAD_ADMISSION_TRACE_ATTACH_AUTOMATIC | SAFEUPLOAD_ADMISSION_TRACE_ATTACH_MANUAL |
             SAFEUPLOAD_ADMISSION_TRACE_ATTACH_NEWLY_MOUNTED:
            return L"automatic|manual|newly_mounted";
        default: return L"unknown";
    }
}

static VOID PrintAdmissionTraceEntry(_In_ const SAFEUPLOAD_ADMISSION_TRACE_ENTRY *Entry)
{
    wprintf(L"{\"sequence\":%llu,\"timestamp\":%llu,\"event\":\"%s\","
            L"\"pid\":%u,\"irql\":%u,\"instance\":\"0x%016llX\","
            L"\"targetFileObject\":\"0x%016llX\",\"sectionObjectPointer\":\"0x%016llX\","
            L"\"major\":%u,\"minor\":%u,\"irpFlags\":\"0x%08X\","
            L"\"mmDoes\":\"%s\",\"streamContext\":\"%s\",\"ownedStream\":%s,"
            L"\"admissionRecordState\":\"not_tracked\",\"setupFlags\":%u,"
            L"\"volumeKind\":%u,\"attachClass\":\"%s\",\"syncType\":%u,"
            L"\"pageProtection\":\"0x%08X\",\"syncParametersValid\":%s,"
            L"\"probeStatus\":\"0x%08X\",\"probeStage\":%u,"
            L"\"writeObjects\":%u,\"writersUntracked\":%s,\"inFlightSections\":%u,"
            L"\"canaryState\":%u,\"canaryStatus\":\"0x%08X\",\"canaryChecks\":%u,"
            L"\"canaryCleanupStatus\":\"0x%08X\"}\n",
            Entry->Sequence, Entry->Timestamp, AdmissionEventName(Entry->EventKind),
            Entry->ProcessId, Entry->Irql, Entry->Instance, Entry->TargetFileObject,
            Entry->SectionObjectPointer, Entry->MajorFunction, Entry->MinorFunction,
            Entry->IrpFlags, AdmissionMmDoesName(Entry->MmDoesResult),
            AdmissionContextName(Entry->StreamContextState),
            Entry->OwnedStream != 0 ? L"true" : L"false", Entry->SetupFlags,
            Entry->VolumeKind, AdmissionAttachClassName(Entry->AttachClass),
            Entry->SyncType, Entry->PageProtection,
            Entry->SyncParametersValid != 0 ? L"true" : L"false",
            Entry->ProbeStatus, Entry->ProbeStage,
            Entry->AdmissionRecordState & ~SAFEUPLOAD_WRITERS_UNTRACKED_BIT,
            (Entry->AdmissionRecordState & SAFEUPLOAD_WRITERS_UNTRACKED_BIT) != 0 ? L"true" : L"false",
            Entry->EventKind == SAFEUPLOAD_ADMISSION_TRACE_EVENT_EXPLICIT_PROBE ? Entry->SetupFlags : 0,
            Entry->CanaryState, Entry->CanaryStatus, Entry->CanaryChecks, Entry->CanaryCleanupStatus);
}

static int SendAdmissionProbe(_In_z_ PCWSTR DosPath)
{
    static const WCHAR volumePrefix[] = L"\\Device\\HarddiskVolume";
    WCHAR drive[3];
    PWCHAR deviceName = NULL;
    PSAFEUPLOAD_ADMISSION_PROBE_REQUEST request = NULL;
    HANDLE port = INVALID_HANDLE_VALUE;
    PCWSTR relativePath;
    SIZE_T dosPathChars;
    SIZE_T deviceNameChars;
    SIZE_T prefixChars = ARRAYSIZE(volumePrefix) - 1;
    SIZE_T index;
    ULONG relativeChars;
    ULONG requestBytes;
    const DWORD deviceNameCapacity = 4096;
    DWORD returned = 0;
    HRESULT hr;
    int exitCode = 2;

    dosPathChars = wcslen(DosPath);
    if (dosPathChars < 4 || dosPathChars > SAFEUPLOAD_ADMISSION_PROBE_MAX_STRING_CHARS ||
        !((DosPath[0] >= L'A' && DosPath[0] <= L'Z') ||
          (DosPath[0] >= L'a' && DosPath[0] <= L'z')) ||
        DosPath[1] != L':' || DosPath[2] != L'\\' ||
        DosPath[dosPathChars - 1] == L'\\') {
        fwprintf(stderr, L"Uso: SafeUpload.Inspector --admission-probe X:\\dir\\file\n");
        return 2;
    }
    for (index = 0; index < dosPathChars; index += 1) {
        if (DosPath[index] == L'/') {
            fwprintf(stderr, L"ERRO: use uma barra invertida no caminho.\n");
            return 2;
        }
        if (index >= 2 && DosPath[index] == L':') {
            fwprintf(stderr, L"ERRO: fluxos alternativos (:) nao sao aceitos.\n");
            return 2;
        }
    }

    drive[0] = DosPath[0];
    drive[1] = L':';
    drive[2] = L'\0';
    deviceName = (PWCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
        (SIZE_T)deviceNameCapacity * sizeof(WCHAR));
    if (deviceName == NULL) return 2;

    if (QueryDosDeviceW(drive, deviceName, deviceNameCapacity) == 0) {
        fwprintf(stderr, L"ERRO: nao foi possivel resolver a unidade %s.\n", drive);
        goto Cleanup;
    }

    deviceNameChars = wcslen(deviceName);
    if (deviceNameChars == 0 ||
        deviceNameChars > SAFEUPLOAD_ADMISSION_PROBE_MAX_STRING_CHARS ||
        deviceNameChars < prefixChars ||
        _wcsnicmp(deviceName, volumePrefix, prefixChars) != 0) {
        fwprintf(stderr, L"ERRO: a unidade nao aponta para um volume local suportado.\n");
        goto Cleanup;
    }

    relativePath = DosPath + 2;
    relativeChars = (ULONG)(dosPathChars - 2);
    if (relativeChars > SAFEUPLOAD_ADMISSION_PROBE_MAX_STRING_CHARS) {
        fwprintf(stderr, L"ERRO: o caminho excede o limite do protocolo.\n");
        goto Cleanup;
    }

    requestBytes = (ULONG)FIELD_OFFSET(SAFEUPLOAD_ADMISSION_PROBE_REQUEST, Strings) +
        ((ULONG)deviceNameChars + relativeChars) * (ULONG)sizeof(WCHAR);
    request = (PSAFEUPLOAD_ADMISSION_PROBE_REQUEST)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, requestBytes);
    if (request == NULL) goto Cleanup;

    request->Control.Version = SAFEUPLOAD_PROTOCOL_VERSION;
    request->Control.StructSize = requestBytes;
    request->Control.Command = SAFEUPLOAD_CONTROL_ADMISSION_PROBE;
    request->VolumeNameChars = (UINT16)deviceNameChars;
    request->RelativePathChars = (UINT16)relativeChars;
    CopyMemory(request->Strings, deviceName, deviceNameChars * sizeof(WCHAR));
    CopyMemory(request->Strings + deviceNameChars,
               relativePath,
               relativeChars * sizeof(WCHAR));

    hr = FilterConnectCommunicationPort(SAFEUPLOAD_PORT_NAME, 0, NULL, 0, NULL, &port);
    if (FAILED(hr)) {
        fwprintf(stderr, L"ERRO: nao foi possivel conectar na porta (hr = 0x%08X).\n", hr);
        goto Cleanup;
    }

    hr = FilterSendMessage(port, request, requestBytes, NULL, 0, &returned);
    wprintf(L"{\"admissionProbe\":\"sent\",\"status\":\"0x%08X\"}\n", hr);
    exitCode = SUCCEEDED(hr) && returned == 0 ? 0 : 3;

Cleanup:
    if (port != INVALID_HANDLE_VALUE) CloseHandle(port);
    if (request != NULL) HeapFree(GetProcessHeap(), 0, request);
    if (deviceName != NULL) HeapFree(GetProcessHeap(), 0, deviceName);
    return exitCode;
}

static int SendAdmissionDeleteStreamContext(_In_z_ PCWSTR DosPath)
{
    static const WCHAR volumePrefix[] = L"\\Device\\HarddiskVolume";
    WCHAR drive[] = L"C:";
    PWCHAR deviceName = NULL;
    PSAFEUPLOAD_ADMISSION_DELETE_STREAM_CONTEXT_REQUEST request = NULL;
    HANDLE port = INVALID_HANDLE_VALUE;
    PCWSTR relativePath;
    SIZE_T dosPathChars;
    SIZE_T deviceNameChars;
    SIZE_T prefixChars = ARRAYSIZE(volumePrefix) - 1;
    SIZE_T index;
    ULONG relativeChars;
    ULONG requestBytes;
    const DWORD deviceNameCapacity = 4096;
    DWORD returned = 0;
    HRESULT hr;
    int exitCode = 2;

    dosPathChars = wcslen(DosPath);
    if (dosPathChars < 4 || dosPathChars > SAFEUPLOAD_ADMISSION_PROBE_MAX_STRING_CHARS ||
        (DosPath[0] != L'C' && DosPath[0] != L'c') ||
        DosPath[1] != L':' || DosPath[2] != L'\\' ||
        DosPath[dosPathChars - 1] == L'\\') {
        fwprintf(stderr, L"Uso: SafeUpload.Inspector --admission-delete-stream-context C:\\dir\\file.maptest\n");
        return 2;
    }
    for (index = 0; index < dosPathChars; ++index) {
        if (DosPath[index] == L'/' || (index >= 2 && DosPath[index] == L':')) {
            fwprintf(stderr, L"ERRO: caminho C: invalido ou fluxo alternativo.\n");
            return 2;
        }
    }

    deviceName = (PWCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
        (SIZE_T)deviceNameCapacity * sizeof(WCHAR));
    if (deviceName == NULL) return 2;
    if (QueryDosDeviceW(drive, deviceName, deviceNameCapacity) == 0) {
        fwprintf(stderr, L"ERRO: nao foi possivel resolver C:.\n");
        goto Cleanup;
    }
    deviceNameChars = wcslen(deviceName);
    if (deviceNameChars < prefixChars ||
        deviceNameChars > SAFEUPLOAD_ADMISSION_PROBE_MAX_STRING_CHARS ||
        _wcsnicmp(deviceName, volumePrefix, prefixChars) != 0) {
        fwprintf(stderr, L"ERRO: C: nao aponta para um volume local suportado.\n");
        goto Cleanup;
    }

    relativePath = DosPath + 2;
    relativeChars = (ULONG)(dosPathChars - 2);
    requestBytes = (ULONG)FIELD_OFFSET(SAFEUPLOAD_ADMISSION_DELETE_STREAM_CONTEXT_REQUEST, Strings) +
        ((ULONG)deviceNameChars + relativeChars) * (ULONG)sizeof(WCHAR);
    request = (PSAFEUPLOAD_ADMISSION_DELETE_STREAM_CONTEXT_REQUEST)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, requestBytes);
    if (request == NULL) goto Cleanup;

    request->Control.Version = SAFEUPLOAD_PROTOCOL_VERSION;
    request->Control.StructSize = requestBytes;
    request->Control.Command = SAFEUPLOAD_CONTROL_ADMISSION_DELETE_STREAM_CONTEXT;
    request->VolumeNameChars = (UINT16)deviceNameChars;
    request->RelativePathChars = (UINT16)relativeChars;
    request->DriveLetter = L'C';
    CopyMemory(request->Strings, deviceName, deviceNameChars * sizeof(WCHAR));
    CopyMemory(request->Strings + deviceNameChars, relativePath, relativeChars * sizeof(WCHAR));

    hr = FilterConnectCommunicationPort(SAFEUPLOAD_PORT_NAME, 0, NULL, 0, NULL, &port);
    if (FAILED(hr)) {
        fwprintf(stderr, L"ERRO: nao foi possivel conectar na porta (hr = 0x%08X).\n", hr);
        goto Cleanup;
    }
    hr = FilterSendMessage(port, request, requestBytes, NULL, 0, &returned);
    wprintf(L"{\"streamContextDeleted\":%s,\"status\":\"0x%08X\"}\n",
        SUCCEEDED(hr) && returned == 0 ? L"true" : L"false", hr);
    exitCode = SUCCEEDED(hr) && returned == 0 ? 0 : 3;

Cleanup:
    if (port != INVALID_HANDLE_VALUE) CloseHandle(port);
    if (request != NULL) HeapFree(GetProcessHeap(), 0, request);
    if (deviceName != NULL) HeapFree(GetProcessHeap(), 0, deviceName);
    return exitCode;
}

static BOOL ResolveCanaryVolumeName(_In_z_ PCWSTR Volume, _Out_writes_(SAFEUPLOAD_CANARY_VOLUME_CHARS) PWSTR NativeName,
    _Out_ PUINT16 NativeChars)
{
    WCHAR mountPoint[4];
    WCHAR volumeName[SAFEUPLOAD_CANARY_VOLUME_CHARS];
    static const WCHAR guidPrefix[] = L"\\\\?\\Volume{";
    size_t inputChars, volumeChars, nativeChars;

    inputChars = wcslen(Volume);
    if (inputChars == 2 && Volume[1] == L':') {
        mountPoint[0] = Volume[0]; mountPoint[1] = L':'; mountPoint[2] = L'\\'; mountPoint[3] = UNICODE_NULL;
    } else if (inputChars == 3 && Volume[1] == L':' && Volume[2] == L'\\') {
        CopyMemory(mountPoint, Volume, sizeof(mountPoint));
    } else {
        return FALSE;
    }
    ZeroMemory(volumeName, sizeof(volumeName));
    if (!GetVolumeNameForVolumeMountPointW(mountPoint, volumeName, ARRAYSIZE(volumeName))) return FALSE;
    volumeChars = wcslen(volumeName);
    if (volumeChars < ARRAYSIZE(guidPrefix) - 1 ||
        _wcsnicmp(volumeName, guidPrefix, ARRAYSIZE(guidPrefix) - 1) != 0 ||
        volumeName[volumeChars - 1] != L'\\') return FALSE;

    /* FltGetVolumeGuidName uses the native \\??\\Volume{GUID} form without a trailing slash. */
    if (volumeChars - 1 + 1 > SAFEUPLOAD_CANARY_VOLUME_CHARS) return FALSE;
    NativeName[0] = L'\\'; NativeName[1] = L'?'; NativeName[2] = L'?'; NativeName[3] = L'\\';
    nativeChars = volumeChars - 4 - 1;
    CopyMemory(NativeName + 4, volumeName + 4, nativeChars * sizeof(WCHAR));
    NativeName[4 + nativeChars] = UNICODE_NULL;
    *NativeChars = (UINT16)(4 + nativeChars);
    return TRUE;
}

static int SendAdmissionCanaryHold(_In_z_ PCWSTR Volume, _In_z_ PCWSTR MillisecondsText)
{
    SAFEUPLOAD_ADMISSION_CANARY_HOLD_REQUEST request;
    SAFEUPLOAD_ADMISSION_CANARY_HOLD_REPLY reply;
    WCHAR nativeVolume[SAFEUPLOAD_CANARY_VOLUME_CHARS];
    WCHAR *end = NULL;
    ULONG holdMilliseconds;
    HANDLE port = INVALID_HANDLE_VALUE;
    UINT16 volumeChars = 0;
    DWORD returned = 0;
    HRESULT hr;

    holdMilliseconds = (ULONG)wcstoul(MillisecondsText, &end, 10);
    if (end == MillisecondsText || *end != UNICODE_NULL || holdMilliseconds == 0 ||
        holdMilliseconds > SAFEUPLOAD_CANARY_MAX_HOLD_MS ||
        !ResolveCanaryVolumeName(Volume, nativeVolume, &volumeChars)) {
        fwprintf(stderr, L"Uso: SafeUpload.Inspector --admission-canary-hold X:\\ 1..30000\n");
        return 2;
    }

    ZeroMemory(&request, sizeof(request));
    ZeroMemory(&reply, sizeof(reply));
    request.Control.Version = SAFEUPLOAD_PROTOCOL_VERSION;
    request.Control.StructSize = sizeof(request);
    request.Control.Command = SAFEUPLOAD_CONTROL_ADMISSION_CANARY_HOLD;
    request.HoldMilliseconds = holdMilliseconds;
    request.VolumeNameChars = volumeChars;
    CopyMemory(request.VolumeName, nativeVolume, (volumeChars + 1) * sizeof(WCHAR));

    hr = FilterConnectCommunicationPort(SAFEUPLOAD_PORT_NAME, 0, NULL, 0, NULL, &port);
    if (FAILED(hr)) goto Exit;
    hr = FilterSendMessage(port, &request, sizeof(request), &reply, sizeof(reply), &returned);
    if (FAILED(hr) || returned != sizeof(reply) || reply.StructSize != sizeof(reply) ||
        reply.Status != 0 || reply.Reserved != 0 || reply.PathChars == 0 ||
        reply.PathChars >= ARRAYSIZE(reply.CanaryPath) ||
        reply.CanaryPath[reply.PathChars] != UNICODE_NULL ||
        wcsncmp(reply.CanaryPath, L"\\Device\\", 8) != 0) {
        fwprintf(stderr, L"ERRO: resposta do hold do canary invalida (hr = 0x%08X, bytes = %u).\n",
            hr, returned);
        if (port != INVALID_HANDLE_VALUE) CloseHandle(port);
        return 3;
    }

    wprintf(L"{\"canaryHold\":\"armed\",\"status\":\"0x%08X\",\"holdMilliseconds\":%u,\"path\":\"",
        reply.Status, holdMilliseconds);
    for (UINT32 index = 0; index < reply.PathChars; ++index) {
        WCHAR value = reply.CanaryPath[index];
        if (value == L'\\' || value == L'\"') wprintf(L"\\%lc", value);
        else if (value < 32 || value > 126) wprintf(L"\\u%04X", (unsigned)value);
        else wprintf(L"%lc", value);
    }
    wprintf(L"\"}\n");
    CloseHandle(port);
    return 0;

Exit:
    fwprintf(stderr, L"ERRO: nao foi possivel conectar na porta (hr = 0x%08X).\n", hr);
    if (port != INVALID_HANDLE_VALUE) CloseHandle(port);
    return 3;
}

static int SendAdmissionCanaryHoldCancel(VOID)
{
    SAFEUPLOAD_CONTROL control;
    HANDLE port = INVALID_HANDLE_VALUE;
    DWORD returned = 0;
    HRESULT hr;
    ZeroMemory(&control, sizeof(control));
    control.Version = SAFEUPLOAD_PROTOCOL_VERSION;
    control.StructSize = sizeof(control);
    control.Command = SAFEUPLOAD_CONTROL_ADMISSION_CANARY_HOLD_CANCEL;
    hr = FilterConnectCommunicationPort(SAFEUPLOAD_PORT_NAME, 0, NULL, 0, NULL, &port);
    if (SUCCEEDED(hr)) hr = FilterSendMessage(port, &control, sizeof(control), NULL, 0, &returned);
    if (port != INVALID_HANDLE_VALUE) CloseHandle(port);
    wprintf(L"{\"canaryHoldCancel\":true,\"status\":\"0x%08X\"}\n", hr);
    return SUCCEEDED(hr) && returned == 0 ? 0 : 3;
}

static int PrintCanarySecurity(_In_z_ PCWSTR NativePath)
{
    WCHAR win32Path[SAFEUPLOAD_MAX_PATH_CHARS + 32];
    HANDLE file = INVALID_HANDLE_VALUE;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    LPWSTR sddl = NULL;
    DWORD error, characters = 0;
    int result = 3;

    if (wcsncmp(NativePath, L"\\Device\\", 8) != 0 ||
        FAILED(StringCchPrintfW(win32Path, ARRAYSIZE(win32Path), L"\\\\?\\GLOBALROOT%s", NativePath))) {
        fwprintf(stderr, L"ERRO: caminho nativo do canary invalido.\n");
        return 2;
    }
    file = CreateFileW(win32Path, READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        error = GetLastError();
        fwprintf(stderr, L"ERRO: abertura SYSTEM do canary falhou (Win32=%lu).\n", error);
        return 3;
    }
    error = GetSecurityInfo(file, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        NULL, NULL, NULL, NULL, &descriptor);
    if (error != ERROR_SUCCESS) goto Exit;
    if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &sddl, &characters)) {
        error = GetLastError();
        goto Exit;
    }
    wprintf(L"{\"canarySecurity\":\"readback\",\"status\":\"0x%08X\",\"sddl\":\"%s\"}\n",
        ERROR_SUCCESS, sddl);
    result = 0;

Exit:
    if (result != 0) {
        fwprintf(stderr, L"ERRO: descritor de seguranca do canary falhou (Win32=%lu).\n", error);
    }
    if (sddl != NULL) LocalFree(sddl);
    if (descriptor != NULL) LocalFree(descriptor);
    CloseHandle(file);
    return result;
}

static int PrintAdmissionVolumeStatus(VOID)
{
    SAFEUPLOAD_CONTROL control;
    PSAFEUPLOAD_ADMISSION_VOLUME_STATUS status;
    HANDLE port = INVALID_HANDLE_VALUE;
    DWORD returned = 0;
    UINT32 index, character;
    PCWSTR bootPolicyProtectionStatus;
    HRESULT hr;
    int result = 3;
    status = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*status));
    if (status == NULL) return 4;
    hr = FilterConnectCommunicationPort(SAFEUPLOAD_PORT_NAME, 0, NULL, 0, NULL, &port);
    if (FAILED(hr)) goto Exit;
    ZeroMemory(&control, sizeof(control));
    control.Version = SAFEUPLOAD_PROTOCOL_VERSION;
    control.StructSize = sizeof(control);
    control.Command = SAFEUPLOAD_CONTROL_ADMISSION_VOLUME_STATUS;
    hr = FilterSendMessage(port, &control, sizeof(control), status, sizeof(*status), &returned);
    if (FAILED(hr) || returned != sizeof(*status) || status->StructSize != sizeof(*status) ||
        status->EntryCount > SAFEUPLOAD_ADMISSION_VOLUME_MAX_ENTRIES ||
        status->BootPolicyState > SAFEUPLOAD_BOOT_POLICY_STATE_PENDING_UNION) goto Exit;
    for (index = 0; index < status->EntryCount; ++index) {
        if (status->Entries[index].VolumeGuidChars >= ARRAYSIZE(status->Entries[index].VolumeGuid)) goto Exit;
    }
    switch (status->BootPolicyState) {
    case SAFEUPLOAD_BOOT_POLICY_STATE_MISSING:
        bootPolicyProtectionStatus = L"not claimed: missing";
        break;
    case SAFEUPLOAD_BOOT_POLICY_STATE_CORRUPT_EMPTY:
        bootPolicyProtectionStatus = L"not claimed: corrupt empty";
        break;
    case SAFEUPLOAD_BOOT_POLICY_STATE_ACL_REJECTED:
        bootPolicyProtectionStatus = L"not claimed: ACL_REJECTED";
        break;
    case SAFEUPLOAD_BOOT_POLICY_STATE_VALID:
        bootPolicyProtectionStatus = L"valid";
        break;
    case SAFEUPLOAD_BOOT_POLICY_STATE_PENDING_UNION:
        bootPolicyProtectionStatus = L"pending union";
        break;
    case SAFEUPLOAD_BOOT_POLICY_STATE_CORRUPT_PARTIAL:
        bootPolicyProtectionStatus = L"partial: only identified scopes enforced";
        break;
    default:
        bootPolicyProtectionStatus = L"unreadable: protection uncertain";
        break;
    }
    wprintf(L"{\"writerGlobalUnknown\":%u,\"bootPolicyState\":%u,"
        L"\"bootPolicyProtectionStatus\":\"%s\",\"admissionVolumes\":[",
        status->WriterGlobalUnknown, status->BootPolicyState, bootPolicyProtectionStatus);
    for (index = 0; index < status->EntryCount; ++index) {
        const SAFEUPLOAD_ADMISSION_VOLUME_ENTRY *entry = &status->Entries[index];
        UINT32 trustState = ((INT32)entry->ContextStatus >= 0) ?
            ((entry->SetupFlags >> SAFEUPLOAD_SETUP_TRUST_STATE_SHIFT) & 0xFFFF) :
            SAFEUPLOAD_VOLUME_TRUST_CONTEXT_UNAVAILABLE;
        UINT32 setupFlags = entry->SetupFlags & SAFEUPLOAD_SETUP_FLAGS_MASK;
        BOOLEAN trusted = trustState == SAFEUPLOAD_VOLUME_TRUST_CANARY_PASSED &&
            entry->CanaryState == SAFEUPLOAD_CANARY_PASSED;
        PCWSTR protectionStatus;
        if (trustState == SAFEUPLOAD_VOLUME_TRUST_CANARY_PASSED && !trusted)
            trustState = SAFEUPLOAD_VOLUME_TRUST_CANARY_PENDING;
        protectionStatus = trusted ? L"trusted" :
            (trustState == SAFEUPLOAD_VOLUME_TRUST_PENDING_REBOOT ? L"protection pending reboot" : L"untrusted");
        wprintf(L"%s{\"instance\":\"%016llX\",\"volumeKind\":%u,\"fileSystemType\":%u,"
            L"\"fileSystemStatus\":%u,\"setupFlags\":%u,\"trustState\":%u,\"protectionStatus\":\"%s\",\"contextStatus\":%u,"
            L"\"canaryState\":%u,\"canaryStatus\":%u,\"canaryChecks\":%u,\"canaryCleanupStatus\":%u,"
            L"\"instanceWritersUntracked\":%u,\"volumeInfoStatus\":%u,\"volumeFlags\":%u,"
            L"\"volumeGuidStatus\":%u,\"volumeGuid\":\"",
            index == 0 ? L"" : L",", entry->Instance, entry->VolumeKind, entry->FileSystemType,
            entry->FileSystemStatus, setupFlags, trustState, protectionStatus, entry->ContextStatus, entry->CanaryState,
            entry->CanaryStatus, entry->CanaryChecks, entry->CanaryCleanupStatus,
            entry->InstanceWritersUntracked, entry->VolumeInfoStatus, entry->VolumeFlags, entry->VolumeGuidStatus);
        for (character = 0; character < entry->VolumeGuidChars; ++character) {
            WCHAR value = entry->VolumeGuid[character];
            if (value == L'\\' || value == L'"') wprintf(L"\\%lc", value);
            else if (value < 32 || value > 126) wprintf(L"\\u%04X", (unsigned)value);
            else wprintf(L"%lc", value);
        }
        wprintf(L"\"}");
    }
    wprintf(L"]}\n");
    result = 0;
Exit:
    if (result != 0) wprintf(L"ERRO: resposta de admission-volume invalida (hr = 0x%08X, bytes = %u).\n", hr, returned);
    if (port != INVALID_HANDLE_VALUE) CloseHandle(port);
    HeapFree(GetProcessHeap(), 0, status);
    return result;
}

static int PrintWriterStateStatus(VOID)
{
    SAFEUPLOAD_CONTROL control;
    SAFEUPLOAD_WRITER_STATE_STATUS status;
    HANDLE port = INVALID_HANDLE_VALUE;
    DWORD returned = 0;
    HRESULT hr;

    hr = FilterConnectCommunicationPort(SAFEUPLOAD_PORT_NAME, 0, NULL, 0, NULL, &port);
    if (FAILED(hr)) {
        wprintf(L"ERRO: nao foi possivel conectar na porta (hr = 0x%08X).\n", hr);
        return 2;
    }

    ZeroMemory(&control, sizeof(control));
    ZeroMemory(&status, sizeof(status));
    control.Version = SAFEUPLOAD_PROTOCOL_VERSION;
    control.StructSize = sizeof(control);
    control.Command = SAFEUPLOAD_CONTROL_WRITER_STATE_STATUS;
    hr = FilterSendMessage(port, &control, sizeof(control), &status, sizeof(status), &returned);
    CloseHandle(port);
    if (FAILED(hr) || returned != sizeof(status) || status.StructSize != sizeof(status)) {
        wprintf(L"ERRO: resposta de writer-state invalida (hr = 0x%08X, bytes = %u).\n", hr, returned);
        return 3;
    }

    wprintf(L"{\"writerState\":true,\"postCreateRuns\":%llu,\"writeObjectsCounted\":%llu,\"writeObjectsReleased\":%llu,"
            L"\"untrackedCreates\":%llu,\"cleanupUnmatched\":%llu,\"directoryCreatesSkipped\":%llu,"
            L"\"sectionInFlightNow\":%lu,\"sectionInFlightInserted\":%llu,\"sectionInFlightReleased\":%llu,"
            L"\"sectionInFlightOverflow\":%llu,\"sectionInFlightStuck\":%llu,\"sectionInFlightRemovedOnFailure\":%llu,"
            L"\"sectionInFlightMaxDepth\":%lu,\"pagingCreatesSkipped\":%llu,\"volumeCreatesSkipped\":%llu,"
            L"\"writersDroppedAtTeardown\":%llu,\"writersDroppedWhileMounted\":%llu,"
            L"\"instanceTeardownsDismount\":%llu,\"instanceTeardownsOther\":%llu,"
            L"\"stageStreams\":%u,\"stageFileObjects\":%u,\"lastUnloadVeto\":%u,\"lastUnloadStatus\":%u}\n",
            status.PostCreateRuns, status.WriteObjectsCounted, status.WriteObjectsReleased,
            status.UntrackedCreates, status.CleanupUnmatched, status.DirectoryCreatesSkipped,
            status.SectionInFlightNow, status.SectionInFlightInserted, status.SectionInFlightReleased,
            status.SectionInFlightOverflow, status.SectionInFlightStuck, status.SectionInFlightRemovedOnFailure,
            status.SectionInFlightMaxDepth, status.PagingCreatesSkipped, status.VolumeCreatesSkipped,
            status.WritersDroppedAtTeardown, status.WritersDroppedWhileMounted,
            status.InstanceTeardownsDismount, status.InstanceTeardownsOther,
            status.StageStreams, status.StageFileObjects, status.LastUnloadVeto, status.LastUnloadStatus);
    return 0;
}

static int PrintFenceStatus(VOID)
{
    SAFEUPLOAD_CONTROL control;
    SAFEUPLOAD_FENCE_STATUS status;
    HANDLE port = INVALID_HANDLE_VALUE;
    DWORD returned = 0;
    HRESULT hr;
    BOOL complete;

    hr = FilterConnectCommunicationPort(SAFEUPLOAD_PORT_NAME, 0, NULL, 0, NULL, &port);
    if (FAILED(hr)) {
        wprintf(L"ERRO: nao foi possivel conectar na porta (hr = 0x%08X).\n", hr);
        return 2;
    }

    ZeroMemory(&control, sizeof(control));
    ZeroMemory(&status, sizeof(status));
    control.Version = SAFEUPLOAD_PROTOCOL_VERSION;
    control.StructSize = sizeof(control);
    control.Command = SAFEUPLOAD_CONTROL_ADMISSION_FENCE_STATUS;
    hr = FilterSendMessage(port, &control, sizeof(control), &status, sizeof(status), &returned);
    CloseHandle(port);
    if (FAILED(hr) || returned != sizeof(status) || status.StructSize != sizeof(status)) {
        wprintf(L"ERRO: o driver recusou o status da cerca (hr = 0x%08X, %lu bytes).\n", hr, returned);
        return 3;
    }

    // "complete" requires a successful scan with no skipped scopes or reparses, no unresolved
    // admission counters, and no refresh, unload gate, quarantine, or retry still active. This is a
    // sampled status and does not close the attach-to-scan window.
    complete = status.LastStatus == 0 && status.VolumeScopesSkipped == 0 && status.ReparseSkipped == 0 &&
        status.SectionNameUnresolved == 0 && status.FsctlUnresolved == 0 && status.StateFlags == 0;
    wprintf(L"{\"fence\":true,\"complete\":%s,\"stateFlags\":%lu,\"entries\":%lu,\"generation\":%lu,\"lastStatus\":\"0x%08X\",\"failureLine\":%lu,"
            L"\"refreshStarted\":%llu,\"refreshCompleted\":%llu,\"refreshFailed\":%llu,"
            L"\"pagingWritesDenied\":%llu,\"opensRefused\":%llu,\"directoriesScanned\":%llu,"
            L"\"filesScanned\":%llu,\"reparseSkipped\":%llu,\"volumeScopesSkipped\":%llu,"
            L"\"streamsReleased\":%llu,\"releaseRefused\":%llu,\"sectionsDenied\":%llu,\"sectionNameUnresolved\":%llu,\"fsctlUnresolved\":%llu,\"lateRefreshesQueued\":%llu}\n",
            complete ? L"true" : L"false",
            status.StateFlags, status.Entries, status.Generation, status.LastStatus, status.FailureLine,
            status.RefreshStarted, status.RefreshCompleted, status.RefreshFailed,
            status.PagingWritesDenied, status.OpensRefused, status.DirectoriesScanned,
            status.FilesScanned, status.ReparseSkipped, status.VolumeScopesSkipped,
            status.StreamsReleased, status.ReleaseRefused, status.SectionsDenied, status.SectionNameUnresolved, status.FsctlUnresolved, status.LateRefreshesQueued);
    return complete ? 0 : 4;
}

static int SendAdmissionTraceControl(_In_ UINT32 Command, _In_z_ PCWSTR Name, _In_ UINT32 Options)
{
    SAFEUPLOAD_CONTROL control;
    HANDLE port = INVALID_HANDLE_VALUE;
    DWORD returned = 0;
    HRESULT hr;

    hr = FilterConnectCommunicationPort(SAFEUPLOAD_PORT_NAME, 0, NULL, 0, NULL, &port);
    if (FAILED(hr)) {
        wprintf(L"ERRO: nao foi possivel conectar na porta (hr = 0x%08X).\n", hr);
        return 2;
    }

    ZeroMemory(&control, sizeof(control));
    control.Version = SAFEUPLOAD_PROTOCOL_VERSION;
    control.StructSize = sizeof(control);
    control.Command = Command;
    control.Reserved = Options;
    hr = FilterSendMessage(port, &control, sizeof(control), NULL, 0, &returned);
    CloseHandle(port);
    if (FAILED(hr) || returned != 0) {
        wprintf(L"ERRO: o driver recusou %s (hr = 0x%08X).\n", Name, hr);
        return 3;
    }

    wprintf(L"%s: OK\n", Name);
    return 0;
}

static int PrintAdmissionTrace(VOID)
{
    SAFEUPLOAD_ADMISSION_TRACE_REQUEST request;
    SAFEUPLOAD_ADMISSION_TRACE_BATCH batch;
    SAFEUPLOAD_ADMISSION_TRACE_COUNTERS counters;
    HANDLE port = INVALID_HANDLE_VALUE;
    DWORD returned = 0;
    UINT64 cursor = 0;
    UINT64 snapshot = 0;
    HRESULT hr;
    ULONG index;
    int exitCode = 0;

    ZeroMemory(&counters, sizeof(counters));
    hr = FilterConnectCommunicationPort(SAFEUPLOAD_PORT_NAME, 0, NULL, 0, NULL, &port);
    if (FAILED(hr)) {
        wprintf(L"ERRO: nao foi possivel conectar na porta (hr = 0x%08X).\n", hr);
        return 2;
    }

    for (;;) {
        ZeroMemory(&request, sizeof(request));
        ZeroMemory(&batch, sizeof(batch));
        request.Control.Version = SAFEUPLOAD_PROTOCOL_VERSION;
        request.Control.StructSize = sizeof(request);
        request.Control.Command = SAFEUPLOAD_CONTROL_ADMISSION_TRACE_READ_BATCH;
        request.Cursor = cursor;
        request.SnapshotSequence = snapshot;

        returned = 0;
        hr = FilterSendMessage(port, &request, sizeof(request), &batch, sizeof(batch), &returned);
        if (FAILED(hr) || returned != sizeof(batch) ||
            batch.Control.Version != SAFEUPLOAD_PROTOCOL_VERSION ||
            batch.Control.StructSize != sizeof(batch) ||
            batch.Control.Command != SAFEUPLOAD_CONTROL_ADMISSION_TRACE_READ_BATCH ||
            batch.EntryCount > SAFEUPLOAD_ADMISSION_TRACE_BATCH_ENTRIES) {
            wprintf(L"ERRO: resposta de trace invalida (hr = 0x%08X, bytes = %u).\n",
                    hr, returned);
            exitCode = 3;
            break;
        }

        if (snapshot == 0) snapshot = batch.SnapshotSequence;
        if (batch.SnapshotSequence != snapshot || batch.NextCursor < cursor) {
            wprintf(L"ERRO: cursor ou snapshot invalido devolvido pelo driver.\n");
            exitCode = 3;
            break;
        }

        for (index = 0; index < batch.EntryCount; index += 1) {
            PrintAdmissionTraceEntry(&batch.Entries[index]);
        }
        counters = batch.Counters;
        if (batch.NextCursor == cursor && cursor <= snapshot) {
            // A slot changed during this snapshot read; leave the cursor for
            // a later invocation to retry from a fresh snapshot.
            break;
        }

        cursor = batch.NextCursor;
        if (cursor > snapshot) break;
    }

    CloseHandle(port);
    if (exitCode != 0) return exitCode;

    wprintf(L"{\"summary\":true,\"totalEvents\":%llu,\"pagingWrites\":%llu,"
            L"\"nonPagingWrites\":%llu,\"sectionAcquires\":%llu,\"sectionReleases\":%llu,"
            L"\"instanceSetups\":%llu,"
            L"\"lostEntries\":%llu,\"cursor\":%llu,\"snapshotSequence\":%llu}\n",
            counters.TotalEvents, counters.PagingWrites, counters.NonPagingWrites,
            counters.SectionAcquires, counters.SectionReleases, counters.InstanceSetups,
            counters.LostEntries, cursor, snapshot);
    return 0;
}
#endif

int __cdecl
wmain (
    int argc,
    wchar_t *argv[]
    )
/*++

Routine Description:

    Connects to the minifilter port and answers requests until the port is
    torn down or the process is stopped.

    The loop is synchronous and single threaded: one request in flight at a
    time. That is enough to prove the path works, and it keeps the failure
    modes obvious. A production client wants overlapped I/O and a pool of
    threads, the way the WDK scanner sample does it.

Arguments:

    argc, argv - Unused.

Return Value:

    0 on a clean exit, non-zero on a connection or protocol failure.

--*/
{
    HANDLE port = INVALID_HANDLE_VALUE;
    HANDLE readyEvent = NULL;
    SAFEUPLOAD_MESSAGE message;
    SAFEUPLOAD_REPLY reply;
    HRESULT hr;
    int exitCode = 0;

    //
    //  A second, short-lived mode: connect, read the driver counters, print
    //  and leave. Meant to run after the main inspector has stopped, since
    //  the port takes one client at a time and the counters live in the
    //  driver rather than in whoever was connected.
    //

    if (argc > 1 && _wcsicmp( argv[1], L"--counters" ) == 0) {

        return PrintCounters();
    }

#if defined(SAFEUPLOAD_STAGING_PROTOTYPE) && SAFEUPLOAD_STAGING_PROTOTYPE
    if (argc > 1 && _wcsicmp(argv[1], L"--admission-trace-enable") == 0) {
        return SendAdmissionTraceControl(SAFEUPLOAD_CONTROL_ADMISSION_TRACE_ENABLE,
                                         L"admission trace enable", 0);
    }

    if (argc > 1 && _wcsicmp(argv[1], L"--admission-trace-enable-sections") == 0) {
        return SendAdmissionTraceControl(SAFEUPLOAD_CONTROL_ADMISSION_TRACE_ENABLE,
                                         L"admission trace enable with section events",
                                         SAFEUPLOAD_ADMISSION_TRACE_OPTION_SECTION_EVENTS);
    }

    if (argc > 1 && _wcsicmp(argv[1], L"--admission-trace-enable-lifetime") == 0) {
        return SendAdmissionTraceControl(SAFEUPLOAD_CONTROL_ADMISSION_TRACE_ENABLE,
                                         L"admission trace enable with file lifetime events",
                                         SAFEUPLOAD_ADMISSION_TRACE_OPTION_FILE_LIFETIME);
    }

    if (argc > 1 && _wcsicmp(argv[1], L"--admission-trace-enable-sections-lifetime") == 0) {
        return SendAdmissionTraceControl(SAFEUPLOAD_CONTROL_ADMISSION_TRACE_ENABLE,
                                         L"admission trace enable with section and file lifetime events",
                                         SAFEUPLOAD_ADMISSION_TRACE_OPTION_SECTION_EVENTS |
                                         SAFEUPLOAD_ADMISSION_TRACE_OPTION_FILE_LIFETIME);
    }

    if (argc > 1 && _wcsicmp(argv[1], L"--admission-trace-disable") == 0) {
        return SendAdmissionTraceControl(SAFEUPLOAD_CONTROL_ADMISSION_TRACE_DISABLE,
                                         L"admission trace disable", 0);
    }

    if (argc > 1 && _wcsicmp(argv[1], L"--admission-trace-clear") == 0) {
        return SendAdmissionTraceControl(SAFEUPLOAD_CONTROL_ADMISSION_TRACE_CLEAR,
                                         L"admission trace clear", 0);
    }

    if (argc > 1 && _wcsicmp(argv[1], L"--admission-trace") == 0) {
        return PrintAdmissionTrace();
    }

    if (argc > 1 && _wcsicmp(argv[1], L"--writer-state-status") == 0) {
        return PrintWriterStateStatus();
    }
    if (argc > 1 && _wcsicmp(argv[1], L"--admission-volume-status") == 0) {
        return PrintAdmissionVolumeStatus();
    }

    if (argc > 1 && _wcsicmp(argv[1], L"--admission-fence-status") == 0) {
        return PrintFenceStatus();
    }

    if (argc > 1 && _wcsicmp(argv[1], L"--admission-fence-refresh") == 0) {
        return SendAdmissionTraceControl(SAFEUPLOAD_CONTROL_ADMISSION_FENCE_REFRESH,
                                         L"admission fence refresh", 0);
    }

    if (argc > 1 && _wcsicmp(argv[1], L"--admission-probe") == 0) {
        if (argc != 3) {
            fwprintf(stderr, L"Uso: SafeUpload.Inspector --admission-probe X:\\dir\\file\n");
            return 2;
        }
        return SendAdmissionProbe(argv[2]);
    }

    if (argc > 1 && _wcsicmp(argv[1], L"--admission-delete-stream-context") == 0) {
        if (argc != 3) {
            fwprintf(stderr, L"Uso: SafeUpload.Inspector --admission-delete-stream-context C:\\dir\\file.maptest\n");
            return 2;
        }
        return SendAdmissionDeleteStreamContext(argv[2]);
    }

    if (argc > 1 && _wcsicmp(argv[1], L"--admission-canary-hold") == 0) {
        if (argc != 4) {
            fwprintf(stderr, L"Uso: SafeUpload.Inspector --admission-canary-hold X:\\ 1..30000\n");
            return 2;
        }
        return SendAdmissionCanaryHold(argv[2], argv[3]);
    }

    if (argc > 1 && _wcsicmp(argv[1], L"--admission-canary-hold-cancel") == 0) {
        if (argc != 2) return 2;
        return SendAdmissionCanaryHoldCancel();
    }

    if (argc > 1 && _wcsicmp(argv[1], L"--admission-canary-security") == 0) {
        if (argc != 3) {
            fwprintf(stderr, L"Uso: SafeUpload.Inspector --admission-canary-security \\Device\\HarddiskVolumeN\\file\n");
            return 2;
        }
        return PrintCanarySecurity(argv[2]);
    }
#endif

    UNREFERENCED_PARAMETER( argc );
    UNREFERENCED_PARAMETER( argv );

    //
    //  Unbuffered output.
    //
    //  When stdout is a console the CRT flushes line by line and everything
    //  appears as it happens. When it is redirected to a file - which is how
    //  the test script runs this program - the CRT switches to full
    //  buffering, and nothing reaches the file until the buffer fills or the
    //  process exits. A watcher waiting for "Conectado" to show up in the
    //  log would wait forever while the program sat there working fine.
    //

    setvbuf( stdout, NULL, _IONBF, 0 );

    wprintf( L"SafeUpload.Inspector - cliente de teste da porta %s\n",
             SAFEUPLOAD_PORT_NAME );
    wprintf( L"Regra de teste: bloqueia caminhos contendo \"%s\"\n\n",
             SAFEUPLOAD_TEST_BLOCK_TOKEN );

    hr = FilterConnectCommunicationPort( SAFEUPLOAD_PORT_NAME,
                                         0,
                                         NULL,
                                         0,
                                         NULL,
                                         &port );

    if (FAILED( hr )) {

        wprintf( L"ERRO: nao foi possivel conectar na porta (hr = 0x%08X).\n", hr );
        wprintf( L"      Verifique se o filtro esta carregado (fltmc filters)\n" );
        wprintf( L"      e se este processo esta elevado.\n" );
        return 2;
    }

    //
    //  Before anything else. Until a policy arrives the driver considers
    //  nothing to be in scope, so an inspector that connects and never
    //  pushes one would see no traffic at all and look broken.
    //

    hr = SendPolicy( port );

    if (FAILED( hr )) {

        wprintf( L"ERRO: o driver recusou a politica (hr = 0x%08X).\n", hr );
        wprintf( L"      0x8007051B e incompatibilidade de versao do protocolo:\n" );
        wprintf( L"      o driver carregado e de outra compilacao.\n" );
        CloseHandle( port );
        return 4;
    }

    wprintf( L"Politica enviada ao driver.\n" );
    wprintf( L"Conectado. Aguardando requisicoes (Ctrl+C para sair).\n\n" );

    //
    //  CreateEvent opens the existing event when a driving script created it
    //  first, and creates it otherwise. Either way, failing to signal is not
    //  worth aborting over: nobody may be listening.
    //

    readyEvent = CreateEventW( NULL, TRUE, FALSE, SAFEUPLOAD_READY_EVENT_NAME );

    if (readyEvent != NULL) {

        SetEvent( readyEvent );
    }

    for (;;) {

        UINT32 verdict = SAFEUPLOAD_VERDICT_ALLOW;

        ZeroMemory( &message, sizeof( message ) );

        //
        //  Synchronous receive: no OVERLAPPED, so this blocks until the
        //  driver has something to ask.
        //

        hr = FilterGetMessage( port,
                               &message.Header,
                               sizeof( message ),
                               NULL );

        if (FAILED( hr )) {

            if (hr == HRESULT_FROM_WIN32( ERROR_INVALID_HANDLE )) {

                wprintf( L"\nPorta desconectada (o filtro foi descarregado).\n" );

            } else {

                wprintf( L"\nERRO ao receber mensagem: 0x%08X\n", hr );
                exitCode = 3;
            }

            break;
        }

        //
        //  Validate before trusting. A version we do not know is answered
        //  with ALLOW: refusing to decide must never turn into a block.
        //

        if (message.Request.Version != SAFEUPLOAD_PROTOCOL_VERSION ||
            message.Request.StructSize != sizeof( SAFEUPLOAD_REQUEST )) {

            wprintf( L"AVISO: versao de protocolo incompativel "
                     L"(recebida %u/%u, esperada %u/%u). Permitindo.\n",
                     message.Request.Version,
                     message.Request.StructSize,
                     SAFEUPLOAD_PROTOCOL_VERSION,
                     (UINT32) sizeof( SAFEUPLOAD_REQUEST ) );

        } else {

            //
            //  The kernel zero-fills the buffer and never fills the last
            //  WCHAR, so these are already terminated. Forcing it anyway
            //  costs nothing and removes the assumption.
            //

            message.Request.Path[SAFEUPLOAD_MAX_PATH_CHARS - 1] = L'\0';
            message.Request.ImageName[SAFEUPLOAD_MAX_IMAGE_NAME_CHARS - 1] = L'\0';

            // This legacy probe has no durable transfer journal. Explicitly
            // refuse a staged allocation instead of answering ALLOW without
            // a basename and relying on the driver to reject it.
            if (message.Request.Operation == SAFEUPLOAD_OPERATION_STAGE_ALLOCATE ||
                ContainsTokenNoCase( message.Request.Path,
                                     SAFEUPLOAD_TEST_BLOCK_TOKEN )) {

                verdict = SAFEUPLOAD_VERDICT_DENY;
            }

            wprintf( L"[%llu] %-6s pid=%-6u %-16s %s%s\n",
                     message.Request.RequestId,
                     OperationName( message.Request.Operation ),
                     message.Request.RequestorProcessId,
                     message.Request.ImageName[0] != L'\0'
                         ? message.Request.ImageName
                         : L"(desconhecido)",
                     message.Request.Path,
                     verdict == SAFEUPLOAD_VERDICT_DENY
                         ? L"  => BLOQUEADO"
                         : L"" );

            wprintf( L"       escopo:%s%s\n",
                     (message.Request.Flags & SAFEUPLOAD_REQUEST_FLAG_SCOPE_DESTINATION) != 0
                         ? L" destino" : L"",
                     (message.Request.Flags & SAFEUPLOAD_REQUEST_FLAG_SCOPE_SOURCE) != 0
                         ? L" origem" : L"" );

            if ((message.Request.Flags &
                 SAFEUPLOAD_REQUEST_FLAG_PATH_NOT_NORMALIZED) != 0) {

                wprintf( L"       (caminho nao normalizado)\n" );
            }

            if ((message.Request.Flags &
                 SAFEUPLOAD_REQUEST_FLAG_PATH_TRUNCATED) != 0) {

                wprintf( L"       (caminho truncado)\n" );
            }
        }

        ZeroMemory( &reply, sizeof( reply ) );

        //
        //  Status is the status of the reply itself, not the verdict. The
        //  verdict travels in the payload.
        //

        reply.Header.Status = 0;
        reply.Header.MessageId = message.Header.MessageId;

        reply.Response.Version = SAFEUPLOAD_PROTOCOL_VERSION;
        reply.Response.StructSize = sizeof( SAFEUPLOAD_RESPONSE );
        reply.Response.RequestId = message.Request.RequestId;
        reply.Response.Verdict = verdict;

        hr = FilterReplyMessage( port,
                                 &reply.Header,
                                 sizeof( reply ) );

        if (FAILED( hr )) {

            //
            //  The most common cause is that the driver already gave up on
            //  this request and timed out. That is not fatal for us: the
            //  operation was allowed and the next request is still coming.
            //

            wprintf( L"AVISO: resposta a requisicao %llu nao foi aceita "
                     L"(hr = 0x%08X).\n",
                     message.Request.RequestId,
                     hr );
        }

        fflush( stdout );
    }

    if (readyEvent != NULL) {

        CloseHandle( readyEvent );
    }

    CloseHandle( port );

    return exitCode;
}
