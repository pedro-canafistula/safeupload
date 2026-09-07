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

            if (ContainsTokenNoCase( message.Request.Path,
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
