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
#include <wchar.h>

#include "..\SafeUpload.Minifilter\Protocol.h"

//
//  The string whose presence in a path makes this test client answer DENY.
//

#define SAFEUPLOAD_TEST_BLOCK_TOKEN L"BLOQUEAR_TESTE"

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
    SAFEUPLOAD_MESSAGE message;
    SAFEUPLOAD_REPLY reply;
    HRESULT hr;
    int exitCode = 0;

    UNREFERENCED_PARAMETER( argc );
    UNREFERENCED_PARAMETER( argv );

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

    wprintf( L"Conectado. Aguardando requisicoes (Ctrl+C para sair).\n\n" );

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

    CloseHandle( port );

    return exitCode;
}
