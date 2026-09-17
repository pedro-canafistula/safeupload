/*++

Module Name:

    Override.c

Abstract:

    Excecoes concedidas pelo modo usuario para operacoes que seriam negadas.

    Existe para o "bloqueio com justificativa": o usuario recebe a recusa,
    informa um motivo de negocio, e a operacao seguinte passa - com o motivo
    registrado na auditoria. E o que impede um DLP de ser desinstalado por
    atrapalhar trabalho legitimo, e e o comportamento padrao dos produtos de
    mercado, que oferecem "block with override" ao lado de "block".

    Duas propriedades definem a seguranca disto, e ambas sao do desenho e nao
    da disciplina de quem chama:

    A concessao e ESTREITA. Vale para um processo, um caminho de destino
    exato e um prazo curto, e some depois de um uso. A alternativa obvia -
    limpar a marca do processo - seria um martelo grande demais: liberaria
    qualquer escrita para qualquer destino vigiado ate o processo ler algo
    sensivel de novo.

    A concessao e CONCEDIDA, nao pedida. O kernel nunca pergunta se ha
    excecao; ele apenas consulta uma tabela que o modo usuario preencheu.
    Nada que o processo interceptado faca pode criar uma entrada aqui.

Environment:

    Kernel mode.

--*/

#include "Filter.h"

//
//  RtlCompareMemory e nao RtlEqualMemory: a segunda e macro para memcmp, que
//  em Release vira importacao de CRT e reprova no ApiValidator - "aitstatic
//  returned exit code 193", uma mensagem que nao nomeia nem a API nem o
//  arquivo. A primeira e funcao exportada do kernel e esta na lista de DDI
//  universal.
//

//
//  Tabela pequena e linear, sem hash: excecao e evento raro, criado por
//  intervencao humana. Uma lista de dezesseis entradas percorrida na negacao
//  custa menos que a estrutura para evita-la, e a negacao ja e o caminho
//  frio.
//

#define SAFEUPLOAD_MAX_OVERRIDES 16

typedef struct _SAFEUPLOAD_OVERRIDE_ENTRY {

    BOOLEAN InUse;

    ULONG ProcessId;

    //
    //  Caminho de destino exato, em forma de dispositivo, como o filtro os
    //  entrega. Nao e prefixo: uma excecao para uma pasta valeria para tudo
    //  que fosse escrito nela depois.
    //

    WCHAR Path[SAFEUPLOAD_MAX_PATH_CHARS];
    USHORT PathLengthBytes;

    //
    //  KeQueryInterruptTime, monotonico: um usuario mexendo no relogio do
    //  sistema nao estende nem cancela uma excecao.
    //

    ULONGLONG ExpiresAt;

} SAFEUPLOAD_OVERRIDE_ENTRY, *PSAFEUPLOAD_OVERRIDE_ENTRY;

static EX_PUSH_LOCK SafeUploadOverrideLock;
static SAFEUPLOAD_OVERRIDE_ENTRY SafeUploadOverrides[SAFEUPLOAD_MAX_OVERRIDES];

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(PAGE, SafeUploadInitializeOverrides)
    #pragma alloc_text(PAGE, SafeUploadFreeOverrides)
#endif


VOID
SafeUploadInitializeOverrides (
    VOID
    )
/*++

Routine Description:

    Prepares the override table.

    IRQL: PASSIVE_LEVEL.

--*/
{
    PAGED_CODE();

    FltInitializePushLock( &SafeUploadOverrideLock );
    RtlZeroMemory( SafeUploadOverrides, sizeof( SafeUploadOverrides ) );
}


VOID
SafeUploadFreeOverrides (
    VOID
    )
/*++

Routine Description:

    Releases the override table.

    Nothing is allocated per entry - the table is a fixed array - so this
    only has the lock to give back.

    IRQL: PASSIVE_LEVEL.

--*/
{
    PAGED_CODE();

    FltDeletePushLock( &SafeUploadOverrideLock );
}


NTSTATUS
SafeUploadGrantOverride (
    _In_ ULONG ProcessId,
    _In_ PCWSTR Path,
    _In_ USHORT PathLengthBytes,
    _In_ ULONG DurationSeconds
    )
/*++

Routine Description:

    Records an exception for one process, one exact destination path, for a
    bounded time.

    The duration is clamped rather than trusted. An exception is a hole in
    the protection, and one that lasts an hour is a hole with a name; the
    ceiling keeps a mistake in user mode from becoming a permanent bypass.

    IRQL: <= APC_LEVEL, for the push lock.

Arguments:

    ProcessId - Process the exception applies to.

    Path - Destination path, in device form.

    PathLengthBytes - Length of Path in bytes, without the terminator.

    DurationSeconds - Requested lifetime; clamped to the bounds below.

Return Value:

    STATUS_SUCCESS, or STATUS_INSUFFICIENT_RESOURCES when the table is full.

--*/
{
    ULONG index;
    ULONG slot = SAFEUPLOAD_MAX_OVERRIDES;
    ULONGLONG now;
    ULONG seconds;

    //
    //  O modo esta na politica, e a verificacao mora aqui e nao em quem
    //  chama: com ela aqui, nao existe caminho que conceda excecao com o
    //  modo desligado, por mais que alguem se engane la em cima.
    //

    if (!SafeUploadPolicyAllowsOverride()) {

        SafeUploadTrace( "excecao recusada: politica nao permite justificativa\n" );

        return STATUS_ACCESS_DENIED;
    }

    if (PathLengthBytes == 0 ||
        PathLengthBytes > (SAFEUPLOAD_MAX_PATH_CHARS - 1) * sizeof( WCHAR )) {

        return STATUS_INVALID_PARAMETER;
    }

    seconds = DurationSeconds;

    if (seconds < SAFEUPLOAD_OVERRIDE_MIN_SECONDS) {

        seconds = SAFEUPLOAD_OVERRIDE_MIN_SECONDS;

    } else if (seconds > SAFEUPLOAD_OVERRIDE_MAX_SECONDS) {

        seconds = SAFEUPLOAD_OVERRIDE_MAX_SECONDS;
    }

    now = KeQueryInterruptTime();

    FltAcquirePushLockExclusive( &SafeUploadOverrideLock );

    //
    //  Uma varredura so: aproveita para reciclar entradas vencidas e para
    //  substituir uma concessao anterior do mesmo processo para o mesmo
    //  caminho, em vez de acumular duas.
    //

    for (index = 0; index < SAFEUPLOAD_MAX_OVERRIDES; index += 1) {

        PSAFEUPLOAD_OVERRIDE_ENTRY entry = &SafeUploadOverrides[index];

        if (entry->InUse && entry->ExpiresAt <= now) {

            entry->InUse = FALSE;
        }

        if (!entry->InUse) {

            if (slot == SAFEUPLOAD_MAX_OVERRIDES) {

                slot = index;
            }

            continue;
        }

        if (entry->ProcessId == ProcessId &&
            entry->PathLengthBytes == PathLengthBytes &&
            RtlCompareMemory( entry->Path, Path, PathLengthBytes ) == PathLengthBytes) {

            slot = index;
            break;
        }
    }

    if (slot == SAFEUPLOAD_MAX_OVERRIDES) {

        FltReleasePushLock( &SafeUploadOverrideLock );

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    SafeUploadOverrides[slot].InUse = TRUE;
    SafeUploadOverrides[slot].ProcessId = ProcessId;
    SafeUploadOverrides[slot].PathLengthBytes = PathLengthBytes;
    SafeUploadOverrides[slot].ExpiresAt =
        now + ((ULONGLONG) seconds * 10ULL * 1000ULL * 1000ULL);

    RtlCopyMemory( SafeUploadOverrides[slot].Path, Path, PathLengthBytes );
    SafeUploadOverrides[slot].Path[PathLengthBytes / sizeof( WCHAR )] = L'\0';

    FltReleasePushLock( &SafeUploadOverrideLock );

    SafeUploadCount( OverridesGranted );

    SafeUploadTrace( "excecao concedida: processo %lu, %u s\n", ProcessId, seconds );

    return STATUS_SUCCESS;
}


BOOLEAN
SafeUploadConsumeOverride (
    _In_ ULONG ProcessId,
    _In_ PCUNICODE_STRING Path
    )
/*++

Routine Description:

    Whether an exception covers this operation, consuming it if so.

    Consuming is the point: an exception answers one operation, not a
    period of freedom. A copy that the user justified once does not become a
    licence to copy again, and the expiry is a backstop for the exception
    that is never used rather than the mechanism that limits it.

    IRQL: <= APC_LEVEL, for the push lock.

Return Value:

    TRUE when the operation was covered, and the exception is now gone.

--*/
{
    ULONG index;
    BOOLEAN allowed = FALSE;
    ULONGLONG now;

    if (Path == NULL || Path->Length == 0) {

        return FALSE;
    }

    now = KeQueryInterruptTime();

    FltAcquirePushLockExclusive( &SafeUploadOverrideLock );

    for (index = 0; index < SAFEUPLOAD_MAX_OVERRIDES; index += 1) {

        PSAFEUPLOAD_OVERRIDE_ENTRY entry = &SafeUploadOverrides[index];

        if (!entry->InUse) {

            continue;
        }

        if (entry->ExpiresAt <= now) {

            entry->InUse = FALSE;
            continue;
        }

        if (entry->ProcessId == ProcessId &&
            entry->PathLengthBytes == Path->Length &&
            RtlCompareMemory( entry->Path, Path->Buffer, Path->Length ) == Path->Length) {

            entry->InUse = FALSE;
            allowed = TRUE;
            break;
        }
    }

    FltReleasePushLock( &SafeUploadOverrideLock );

    if (allowed) {

        SafeUploadCount( OverridesUsed );

        SafeUploadTrace( "excecao usada: processo %lu\n", ProcessId );
    }

    return allowed;
}
