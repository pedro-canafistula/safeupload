/*++

Module Name:

    Protocol.h

Abstract:

    Wire contract between the SafeUpload minifilter (kernel mode) and the
    inspector that arbitrates its operations (user mode).

    This header is compiled by BOTH sides and is the single source of truth
    for the message layout. The WPF/C# agent that will replace
    SafeUpload.Inspector has to marshal exactly these structures; see the
    "Contrato de mensagens" section of DEPLOY.md.

    Rules this contract follows, and that any change to it must keep:

    - Messages use fixed-width structures and no pointers or heap ownership
      crossing the boundary. The feature-only admission probe has a bounded
      variable string tail whose exact byte length is declared and validated.
    - Every field has an explicit width (UINT32/UINT64/WCHAR). No enums,
      no BOOLEAN, no ULONG_PTR: nothing whose size depends on the compiler
      or on the bitness of the process.
    - Fields are ordered so that every one of them lands on its natural
      alignment with no implicit padding. The C_ASSERTs at the bottom of
      this file fail the build if that ever stops being true.
    - Both structures carry Version and StructSize so that a mismatched
      kernel/user pair is detected instead of misparsed.

Environment:

    Kernel and user mode

--*/

#ifndef _SAFEUPLOAD_PROTOCOL_H_
#define _SAFEUPLOAD_PROTOCOL_H_

//
//  Name of the filter communication port. User mode passes this string to
//  FilterConnectCommunicationPort.
//

#define SAFEUPLOAD_PORT_NAME L"\\SafeUploadPort"

//
//  Version of this contract. Bump it on ANY layout change. Both sides
//  reject a message whose Version they do not recognise. Ordinary verdicts
//  fail open under RN-013; experimental staged allocations fail closed.
//

/* Unchanged by the test-only writer-state counters: that reply is size-checked by StructSize, and the agent
 * (agente/.../Protocol.cs, Version = 18) never reads it. */
#define SAFEUPLOAD_PROTOCOL_VERSION ((UINT32) 18)

//
//  Capacity of the inline string fields, in WCHARs, terminator included.
//  The *_BYTES macros give the largest payload that may be copied in, so
//  that the last WCHAR always stays zero and both sides can treat the
//  fields as NUL-terminated.
//

#define SAFEUPLOAD_MAX_PATH_CHARS       ((UINT32) 512)
#define SAFEUPLOAD_MAX_IMAGE_NAME_CHARS ((UINT32) 64)

#define SAFEUPLOAD_MAX_PATH_BYTES \
    ((UINT32) ((SAFEUPLOAD_MAX_PATH_CHARS - 1) * sizeof( WCHAR )))

#define SAFEUPLOAD_MAX_IMAGE_NAME_BYTES \
    ((UINT32) ((SAFEUPLOAD_MAX_IMAGE_NAME_CHARS - 1) * sizeof( WCHAR )))

//
//  Which operation the kernel is asking about.
//

#define SAFEUPLOAD_OPERATION_CREATE ((UINT32) 1)
#define SAFEUPLOAD_OPERATION_READ   ((UINT32) 2)
#define SAFEUPLOAD_OPERATION_STAGE_ALLOCATE ((UINT32) 3)
#define SAFEUPLOAD_OPERATION_STAGE_SEAL ((UINT32) 4)
#define SAFEUPLOAD_OPERATION_STAGE_RENAME ((UINT32) 5)
#define SAFEUPLOAD_OPERATION_STAGE_DIAGNOSTIC ((UINT32) 6)
#define SAFEUPLOAD_OPERATION_STAGE_RENAME_COMMIT ((UINT32) 7)
#define SAFEUPLOAD_OPERATION_STAGE_RENAME_ABORT ((UINT32) 8)
#define SAFEUPLOAD_REQUEST_FLAG_STAGE_REMOVABLE ((UINT32) 0x00000040)
#define SAFEUPLOAD_REQUEST_FLAG_STAGE_NETWORK ((UINT32) 0x00000080)

// The reply carries only a stage basename. The driver constructs the local
// volume path and rejects separators or a malformed suffix.
#define SAFEUPLOAD_MAX_STAGE_NAME_CHARS ((UINT32) 64)

//
//  Verdict returned by user mode. Anything that is not an explicit DENY is
//  treated as ALLOW.
//

#define SAFEUPLOAD_VERDICT_ALLOW ((UINT32) 0)
#define SAFEUPLOAD_VERDICT_DENY  ((UINT32) 1)

//
//  SAFEUPLOAD_REQUEST.Flags
//

//
//  Path did not fit in Path[] and was cut short.
//

#define SAFEUPLOAD_REQUEST_FLAG_PATH_TRUNCATED       ((UINT32) 0x00000001)

//
//  ImageName did not fit and was cut short.
//

#define SAFEUPLOAD_REQUEST_FLAG_IMAGE_NAME_TRUNCATED ((UINT32) 0x00000002)

//
//  The normalized name could not be obtained and Path holds the opened
//  name instead: whatever the caller literally passed, which may be
//  relative, a short name, or reached through a different mount point.
//  Usable, but not safe to compare byte-for-byte against a policy list.
//

#define SAFEUPLOAD_REQUEST_FLAG_PATH_NOT_NORMALIZED  ((UINT32) 0x00000004)

//
//  Which scope brought this operation to user mode. Both can be set when a
//  path is a monitored destination and a monitored source at once.
//
//  DESTINATION means the file is heading somewhere it must not go. SOURCE
//  means the file is somewhere worth inspecting for sensitive content. The
//  agent needs to tell them apart: the first asks for a verdict, the second
//  asks what the file contains.
//

#define SAFEUPLOAD_REQUEST_FLAG_SCOPE_DESTINATION    ((UINT32) 0x00000008)
#define SAFEUPLOAD_REQUEST_FLAG_SCOPE_SOURCE         ((UINT32) 0x00000010)

// STAGE_ALLOCATE uses ImageName for the previous 32-character stage ID when
// creating a later version. Reserved carries the original create disposition.
#define SAFEUPLOAD_REQUEST_FLAG_STAGE_FOLLOWUP       ((UINT32) 0x00000020)
// Allocate an empty new private view at this writer's committed rename
// tombstone. ImageName is the tombstone-owning transfer GUID, Reserved is
// FILE_CREATE (even for other create-capable upper dispositions). Older
// allocators reject an occupied physical slot rather than seed public bytes.
#define SAFEUPLOAD_REQUEST_FLAG_STAGE_TOMBSTONE_CREATE ((UINT32) 0x00000100)


#pragma pack(push, 8)

//
//  Kernel -> user. Sent with FltSendMessage; the filter manager prepends a
//  FILTER_MESSAGE_HEADER before user mode sees it.
//

typedef struct _SAFEUPLOAD_REQUEST {

    //
    //  SAFEUPLOAD_PROTOCOL_VERSION and sizeof(SAFEUPLOAD_REQUEST). Checked
    //  by the receiver before any other field is read.
    //

    UINT32 Version;
    UINT32 StructSize;

    //
    //  Monotonic identifier of this request. The response must echo it, so
    //  that a late reply to a request the kernel already timed out cannot
    //  be mistaken for the answer to the current one.
    //

    UINT64 RequestId;

    //
    //  SAFEUPLOAD_OPERATION_*.
    //

    UINT32 Operation;

    //
    //  PID of the process that issued the operation, as reported by
    //  FltGetRequestorProcessId.
    //

    UINT32 RequestorProcessId;

    //
    //  SAFEUPLOAD_REQUEST_FLAG_*.
    //

    UINT32 Flags;

    //
    //  Lengths in BYTES, terminator excluded. Zero means "not available".
    //

    UINT32 PathLength;
    UINT32 ImageNameLength;

    UINT32 Reserved;

    //
    //  Normalized path of the target file, NUL-terminated, in NT form
    //  (\Device\HarddiskVolume3\Users\...). Truncated to fit, in which case
    //  SAFEUPLOAD_REQUEST_FLAG_PATH_TRUNCATED is set.
    //

    WCHAR Path[SAFEUPLOAD_MAX_PATH_CHARS];

    //
    //  Last component of the requesting process image, NUL-terminated
    //  (for example "notepad.exe"). Empty when it could not be resolved.
    //

    WCHAR ImageName[SAFEUPLOAD_MAX_IMAGE_NAME_CHARS];


} SAFEUPLOAD_REQUEST, *PSAFEUPLOAD_REQUEST;

//
//  User -> kernel. Sent with FilterReplyMessage after a
//  FILTER_REPLY_HEADER.
//

typedef struct _SAFEUPLOAD_RESPONSE {

    UINT32 Version;
    UINT32 StructSize;

    //
    //  Must equal the RequestId of the request being answered.
    //

    UINT64 RequestId;

    //
    //  SAFEUPLOAD_VERDICT_*.
    //

    UINT32 Verdict;

    UINT32 StageNameLength;

    // Used only for STAGE_ALLOCATE. Length is bytes without the terminator.
    WCHAR StageName[SAFEUPLOAD_MAX_STAGE_NAME_CHARS];

} SAFEUPLOAD_RESPONSE, *PSAFEUPLOAD_RESPONSE;

///////////////////////////////////////////////////////////////////////////
//
//  Control channel: user -> kernel, sent with FilterSendMessage.
//
//  This is how the policy reaches the kernel. It travels in the opposite
//  direction from the requests above and is not a reply to anything.
//
///////////////////////////////////////////////////////////////////////////

#define SAFEUPLOAD_CONTROL_SET_POLICY   ((UINT32) 1)
#define SAFEUPLOAD_CONTROL_GET_COUNTERS ((UINT32) 2)
#define SAFEUPLOAD_CONTROL_STAGE_PUBLICATION ((UINT32) 4)

#if defined(SAFEUPLOAD_STAGING_PROTOTYPE) && SAFEUPLOAD_STAGING_PROTOTYPE
#define SAFEUPLOAD_CONTROL_ADMISSION_TRACE_ENABLE       ((UINT32) 5)
/*
 *  ENABLE carries its options in SAFEUPLOAD_CONTROL.Reserved. Section
 *  synchronization events are system-wide and ~1000 per second, so they are
 *  recorded only when asked for; the default trace holds writes, probes and setup.
 *  A separate option records IRP_MJ_CLEANUP and IRP_MJ_CLOSE of file objects that were opened
 *  with write access (observe-only; they never change a status). It is cheap enough to leave on
 *  for minutes, unlike the section events.
 */
#define SAFEUPLOAD_ADMISSION_TRACE_OPTION_SECTION_EVENTS ((UINT32) 1)
#define SAFEUPLOAD_ADMISSION_TRACE_OPTION_FILE_LIFETIME  ((UINT32) 2)
#define SAFEUPLOAD_CONTROL_ADMISSION_TRACE_DISABLE      ((UINT32) 6)
#define SAFEUPLOAD_CONTROL_ADMISSION_TRACE_CLEAR        ((UINT32) 7)
#define SAFEUPLOAD_CONTROL_ADMISSION_TRACE_READ_BATCH   ((UINT32) 8)
#define SAFEUPLOAD_CONTROL_ADMISSION_PROBE              ((UINT32) 9)
#define SAFEUPLOAD_CONTROL_ADMISSION_FENCE_STATUS       ((UINT32) 10)
#define SAFEUPLOAD_CONTROL_ADMISSION_FENCE_REFRESH      ((UINT32) 11)
#define SAFEUPLOAD_CONTROL_ADMISSION_VOLUME_STATUS      ((UINT32) 13)
#define SAFEUPLOAD_CONTROL_ADMISSION_CANARY_HOLD        ((UINT32) 14)
#define SAFEUPLOAD_CONTROL_ADMISSION_CANARY_HOLD_CANCEL ((UINT32) 15)
#define SAFEUPLOAD_CONTROL_ADMISSION_DELETE_STREAM_CONTEXT ((UINT32) 16)
#define SAFEUPLOAD_ADMISSION_VOLUME_MAX_ENTRIES          ((UINT32) 32)
#define SAFEUPLOAD_CONTROL_WRITER_STATE_STATUS          ((UINT32) 12)
#define SAFEUPLOAD_CONTROL_REGISTRY_ENTRY               ((UINT32) 17)
#define SAFEUPLOAD_CONTROL_REGISTRY_SET_CAPACITY         ((UINT32) 18)
#define SAFEUPLOAD_CONTROL_ACTIVATING_STATUS             ((UINT32) 19)
#define SAFEUPLOAD_CONTROL_ADMISSION_EPOCH_STATUS        ((UINT32) 20)
#define SAFEUPLOAD_CONTROL_ADMISSION_EPOCH_FORCE_TIMEOUT ((UINT32) 21)
#define SAFEUPLOAD_CONTROL_PROMOTION_TRACE_READ_BATCH ((UINT32) 22)
/* Same status payload without the legacy canary-deadline transition. */
#define SAFEUPLOAD_CONTROL_ADMISSION_VOLUME_OBSERVE       ((UINT32) 23)
#define SAFEUPLOAD_CONTROL_ADMISSION_COVERAGE              ((UINT32) 24)
#define SAFEUPLOAD_CONTROL_ACTIVATING_DIAGNOSTIC_STATUS     ((UINT32) 25)
#define SAFEUPLOAD_CONTROL_ACTIVATING_TARGET_STATUS         ((UINT32) 26)
/* Field diagnostics: read by the agent over its own connection (the port accepts one client, so the Inspector cannot
 * read them while the service runs). Both are read-only. */
#define SAFEUPLOAD_CONTROL_DENY_RING_READ                   ((UINT32) 27)
#define SAFEUPLOAD_CONTROL_DIAG_COUNTERS                    ((UINT32) 28)
#define SAFEUPLOAD_ADMISSION_COVERAGE_MAX_SCOPES \
    ((UINT32)(SAFEUPLOAD_MAX_PREFIXES + SAFEUPLOAD_MAX_PREFIXES + SAFEUPLOAD_BOOT_SCOPE_MAX_PREFIXES + 2))
#define SAFEUPLOAD_ADMISSION_COVERAGE_MAX_INSTANCES         ((UINT32) 128)
#define SAFEUPLOAD_ADMISSION_COVERAGE_SCOPE_PREFIX          ((UINT32) 1)
#define SAFEUPLOAD_ADMISSION_COVERAGE_SCOPE_REMOVABLE       ((UINT32) 2)
#define SAFEUPLOAD_ADMISSION_COVERAGE_SCOPE_NETWORK         ((UINT32) 3)
#define SAFEUPLOAD_ADMISSION_COVERAGE_RESOLUTION_UNKNOWN    ((UINT32) 0)
#define SAFEUPLOAD_ADMISSION_COVERAGE_RESOLUTION_ABSENT     ((UINT32) 1)
#define SAFEUPLOAD_ADMISSION_COVERAGE_RESOLUTION_UNIQUE     ((UINT32) 2)
#define SAFEUPLOAD_ADMISSION_COVERAGE_RESOLUTION_AMBIGUOUS  ((UINT32) 3)
#define SAFEUPLOAD_ADMISSION_COVERAGE_RESOLUTION_NOT_APPLICABLE ((UINT32) 4)
#define SAFEUPLOAD_ADMISSION_COVERAGE_STATE_PENDING         ((UINT32) 0)
#define SAFEUPLOAD_ADMISSION_COVERAGE_STATE_READY           ((UINT32) 1)
#define SAFEUPLOAD_ADMISSION_COVERAGE_STATE_DEGRADED        ((UINT32) 2)
#define SAFEUPLOAD_ADMISSION_COVERAGE_REASON_NONE           ((UINT32) 0)
#define SAFEUPLOAD_ADMISSION_COVERAGE_REASON_NO_SCOPE       ((UINT32) 1)
#define SAFEUPLOAD_ADMISSION_COVERAGE_REASON_POLICY_CHANGE  ((UINT32) 2)
#define SAFEUPLOAD_ADMISSION_COVERAGE_REASON_TOPOLOGY       ((UINT32) 3)
#define SAFEUPLOAD_ADMISSION_COVERAGE_REASON_ABSENT         ((UINT32) 4)
#define SAFEUPLOAD_ADMISSION_COVERAGE_REASON_AMBIGUOUS      ((UINT32) 5)
#define SAFEUPLOAD_ADMISSION_COVERAGE_REASON_UNKNOWN        ((UINT32) 6)
#define SAFEUPLOAD_ADMISSION_COVERAGE_REASON_UNSUPPORTED    ((UINT32) 7)
#define SAFEUPLOAD_ADMISSION_COVERAGE_REASON_CANARY_PENDING ((UINT32) 8)
#define SAFEUPLOAD_ADMISSION_COVERAGE_REASON_CANARY_FAILED  ((UINT32) 9)
#define SAFEUPLOAD_ADMISSION_COVERAGE_REASON_WRITER_UNKNOWN ((UINT32) 10)
#define SAFEUPLOAD_ADMISSION_COVERAGE_REASON_WRITER_PENDING ((UINT32) 11)
#define SAFEUPLOAD_ADMISSION_COVERAGE_REASON_BOOT_POLICY    ((UINT32) 12)
#define SAFEUPLOAD_ADMISSION_COVERAGE_REASON_NO_FUTURE_GATE ((UINT32) 13)
#define SAFEUPLOAD_ADMISSION_COVERAGE_REASON_POLICY_FAILED  ((UINT32) 14)
#define SAFEUPLOAD_ADMISSION_COVERAGE_REASON_IDENTITY       ((UINT32) 15)
#define SAFEUPLOAD_ADMISSION_COVERAGE_REASON_AUDIT_ONLY     ((UINT32) 16)
#define SAFEUPLOAD_ADMISSION_COVERAGE_FLAG_COMPLETE        ((UINT32) 0x00000001)
#define SAFEUPLOAD_ADMISSION_COVERAGE_FLAG_STABLE          ((UINT32) 0x00000002)
#define SAFEUPLOAD_ADMISSION_COVERAGE_FLAG_FUTURE_GATE     ((UINT32) 0x00000004)
#define SAFEUPLOAD_ADMISSION_COVERAGE_FLAG_POLICY_PENDING   ((UINT32) 0x00000008)
#define SAFEUPLOAD_ADMISSION_COVERAGE_FLAG_REGISTRY_COMPLETE ((UINT32) 0x00000010)
#define SAFEUPLOAD_ADMISSION_COVERAGE_FLAG_POLICY_SCOPE_OVERFLOW ((UINT32) 0x00000020)
/* Emitted only by a feature driver implementing the taint-disable control. */
#define SAFEUPLOAD_ADMISSION_COVERAGE_FLAG_TEST_TAINT_CONTROL ((UINT32) 0x00000040)
#define SAFEUPLOAD_WRITER_REGISTRY_INSTANCE_LIMIT         ((UINT32) 1024)
#define SAFEUPLOAD_WRITER_REGISTRY_TOTAL_LIMIT            ((UINT32) 4096)
#define SAFEUPLOAD_WRITER_REGISTRY_COMPACT_INSTANCE_LIMIT ((UINT32) (4 * SAFEUPLOAD_WRITER_REGISTRY_INSTANCE_LIMIT))
#define SAFEUPLOAD_WRITER_REGISTRY_COMPACT_LIMIT          ((UINT32) (4 * SAFEUPLOAD_WRITER_REGISTRY_TOTAL_LIMIT))
#define SAFEUPLOAD_WRITER_REGISTRY_ALL_LIMIT              ((UINT32) (SAFEUPLOAD_WRITER_REGISTRY_TOTAL_LIMIT + SAFEUPLOAD_WRITER_REGISTRY_COMPACT_LIMIT))
#define SAFEUPLOAD_WRITER_REGISTRY_SOP_LIMIT              ((UINT32) (SAFEUPLOAD_WRITER_REGISTRY_ALL_LIMIT + SAFEUPLOAD_WRITER_REGISTRY_COMPACT_LIMIT))
#define SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS             ((UINT32) 512)
#define SAFEUPLOAD_WRITER_REGISTRY_NAME_BUDGET             ((UINT32) (4 * 1024 * 1024))
#define SAFEUPLOAD_ADMISSION_TRACE_RING_ENTRIES         ((UINT32) 16384) /* power of two; feature build only */
#define SAFEUPLOAD_ADMISSION_TRACE_BATCH_ENTRIES        ((UINT32) 8)
#define SAFEUPLOAD_PROMOTION_TRACE_RING_ENTRIES         ((UINT32) 256)
#define SAFEUPLOAD_PROMOTION_TRACE_BATCH_ENTRIES        ((UINT32) 4)
#define SAFEUPLOAD_ADMISSION_PROBE_MAX_STRING_CHARS     ((UINT16) 260)

#define SAFEUPLOAD_ADMISSION_TRACE_EVENT_PAGING_WRITE   ((UINT32) 1)
#define SAFEUPLOAD_ADMISSION_TRACE_EVENT_SECTION_ACQUIRE ((UINT32) 2)
#define SAFEUPLOAD_ADMISSION_TRACE_EVENT_SECTION_RELEASE ((UINT32) 3)
#define SAFEUPLOAD_ADMISSION_TRACE_EVENT_INSTANCE_SETUP ((UINT32) 4)
#define SAFEUPLOAD_ADMISSION_TRACE_EVENT_EXPLICIT_PROBE ((UINT32) 5)
#define SAFEUPLOAD_ADMISSION_TRACE_EVENT_UNOWNED_NONPAGING_WRITE ((UINT32) 6)
#define SAFEUPLOAD_ADMISSION_TRACE_EVENT_FILE_CLEANUP   ((UINT32) 7)
#define SAFEUPLOAD_ADMISSION_TRACE_EVENT_FILE_CLOSE     ((UINT32) 8)
#define SAFEUPLOAD_ADMISSION_TRACE_EVENT_W_BEGIN         ((UINT32) 9)
#define SAFEUPLOAD_ADMISSION_TRACE_EVENT_W_END           ((UINT32) 10)

#define SAFEUPLOAD_ADMISSION_TRACE_REGISTRY_SNAPSHOT_LOCKED       ((UINT32) 0x00000001) /* StateLock held during sample; not a whole-record seqlock */
#define SAFEUPLOAD_ADMISSION_TRACE_REGISTRY_SNAPSHOT_EXACT_ID      ((UINT32) 0x00000002)
#define SAFEUPLOAD_ADMISSION_TRACE_REGISTRY_SNAPSHOT_POST_RETIRE   ((UINT32) 0x00000004)

#define SAFEUPLOAD_ADMISSION_TRACE_MMDOES_NOT_APPLICABLE ((UINT32) 0)
#define SAFEUPLOAD_ADMISSION_TRACE_MMDOES_SKIPPED        ((UINT32) 1)
#define SAFEUPLOAD_ADMISSION_TRACE_MMDOES_NO             ((UINT32) 2)
#define SAFEUPLOAD_ADMISSION_TRACE_MMDOES_YES            ((UINT32) 3)

#define SAFEUPLOAD_ADMISSION_TRACE_CONTEXT_NOT_APPLICABLE ((UINT32) 0)
#define SAFEUPLOAD_ADMISSION_TRACE_CONTEXT_UNKNOWN        ((UINT32) 1)
#define SAFEUPLOAD_ADMISSION_TRACE_CONTEXT_ABSENT         ((UINT32) 2)
#define SAFEUPLOAD_ADMISSION_TRACE_CONTEXT_PRESENT        ((UINT32) 3)
#define SAFEUPLOAD_ADMISSION_TRACE_CONTEXT_NOT_QUERIED    ((UINT32) 4)

#define SAFEUPLOAD_ADMISSION_PROBE_STAGE_NOT_STARTED       ((UINT32) 0)
#define SAFEUPLOAD_ADMISSION_PROBE_STAGE_VOLUME_LOOKUP     ((UINT32) 1)
#define SAFEUPLOAD_ADMISSION_PROBE_STAGE_INSTANCE_LOOKUP   ((UINT32) 2)
#define SAFEUPLOAD_ADMISSION_PROBE_STAGE_INSTANCE_CONTEXT ((UINT32) 3)
#define SAFEUPLOAD_ADMISSION_PROBE_STAGE_VOLUME_KIND       ((UINT32) 4)
#define SAFEUPLOAD_ADMISSION_PROBE_STAGE_FILESYSTEM_TYPE   ((UINT32) 5)
#define SAFEUPLOAD_ADMISSION_PROBE_STAGE_PATH_ALLOCATION   ((UINT32) 6)
#define SAFEUPLOAD_ADMISSION_PROBE_STAGE_LOWER_OPEN        ((UINT32) 7)
#define SAFEUPLOAD_ADMISSION_PROBE_STAGE_COMPLETE          ((UINT32) 8)
#define SAFEUPLOAD_ADMISSION_PROBE_STAGE_IDENTITY_QUERY    ((UINT32) 9)
#define SAFEUPLOAD_ADMISSION_PROBE_STAGE_IDENTITY_OPEN     ((UINT32) 10)
#define SAFEUPLOAD_ADMISSION_PROBE_STAGE_IDENTITY_VERIFY   ((UINT32) 11)

#define SAFEUPLOAD_CANARY_PENDING     ((UINT32) 0)
#define SAFEUPLOAD_CANARY_RUNNING     ((UINT32) 1)
#define SAFEUPLOAD_CANARY_PASSED      ((UINT32) 2)
#define SAFEUPLOAD_CANARY_FAILED      ((UINT32) 3)
#define SAFEUPLOAD_CANARY_UNSUPPORTED ((UINT32) 4)
#define SAFEUPLOAD_CANARY_DETACHED    ((UINT32) 5) /* Untrusted; no current storage stack. */
#define SAFEUPLOAD_VOLUME_DETACHED_FLAG ((UINT32) 1)
#define SAFEUPLOAD_CANARY_RETAINED_YES ((UINT32) 1)
#define SAFEUPLOAD_CANARY_RELEASED_NO  ((UINT32) 2)
#define SAFEUPLOAD_CANARY_REMOVED      ((UINT32) 4)
#define SAFEUPLOAD_CANARY_DACL_VERIFIED ((UINT32) 8)
#define SAFEUPLOAD_CANARY_CHECKS_ALL     ((UINT32) 15)
#define SAFEUPLOAD_CANARY_MAX_HOLD_MS    ((UINT32) 30000)
#define SAFEUPLOAD_CANARY_VOLUME_CHARS   ((UINT32) 64)

#define SAFEUPLOAD_ADMISSION_TRACE_ATTACH_UNKNOWN         ((UINT32) 0)
#define SAFEUPLOAD_ADMISSION_TRACE_ATTACH_AUTOMATIC       ((UINT32) 1)
#define SAFEUPLOAD_ADMISSION_TRACE_ATTACH_MANUAL          ((UINT32) 2)
#define SAFEUPLOAD_ADMISSION_TRACE_ATTACH_NEWLY_MOUNTED   ((UINT32) 4)
#define SAFEUPLOAD_ADMISSION_TRACE_SYNC_UNAVAILABLE      ((UINT32) 0xffffffff)
#endif

//
//  Concede uma excecao para uma operacao que seria negada: um processo, um
//  caminho de destino exato, por um prazo curto, valida para um uso.
//
//  E o "bloqueio com justificativa": o usuario recebe a recusa, informa um
//  motivo de negocio, e a operacao seguinte passa - com o motivo na
//  auditoria. O kernel nunca pergunta se ha excecao; ele consulta uma tabela
//  que o modo usuario preencheu, e nada que o processo interceptado faca
//  cria uma entrada nela.
//

#define SAFEUPLOAD_CONTROL_GRANT_OVERRIDE ((UINT32) 3)

//
//  Capacities of the policy message. Fixed, like everything else here: the
//  kernel must be able to tell how big a message is before reading it, and
//  a policy that does not fit is a policy that has to be reduced, not a
//  reason to invent variable-length parsing on the boundary.
//

#define SAFEUPLOAD_MAX_EXTENSIONS      ((UINT32) 32)
#define SAFEUPLOAD_MAX_EXTENSION_CHARS ((UINT32) 16)
#define SAFEUPLOAD_MAX_PREFIXES        ((UINT32) 16)
#define SAFEUPLOAD_MAX_PREFIX_CHARS    ((UINT32) 260)
#define SAFEUPLOAD_BOOT_POLICY_VERSION ((UINT32) 1)
#define SAFEUPLOAD_BOOT_POLICY_MAX_PREFIXES ((UINT32) 32)
#define SAFEUPLOAD_BOOT_SCOPE_MAX_PREFIXES ((UINT32) (SAFEUPLOAD_BOOT_POLICY_MAX_PREFIXES * 2))
#define SAFEUPLOAD_MAX_SOURCE_PREFIXES ((UINT32) 16)
#define SAFEUPLOAD_MAX_IMAGES          ((UINT32) 16)
#define SAFEUPLOAD_MAX_IMAGE_CHARS     ((UINT32) 64)

//
//  SAFEUPLOAD_POLICY_MESSAGE.Flags
//

#define SAFEUPLOAD_POLICY_FLAG_REMOVABLE ((UINT32) 0x00000001)
#define SAFEUPLOAD_POLICY_FLAG_NETWORK   ((UINT32) 0x00000002)

//
//  Modo auditoria: avalia tudo, registra tudo, nao nega nada.
//
//  Precisa existir no kernel, e nao so no servico, porque a recusa por
//  processo marcado acontece aqui sem perguntar a ninguem - uma flag do
//  outro lado nao teria como desliga-la.
//
//  A marcacao continua acontecendo: sem ela nao ha o que medir. O que fica
//  suspenso sao as tres negacoes - escrita no destino, cancelamento no
//  pos-create e rename. Cada uma incrementa WouldHaveDenied em vez de
//  negar, e esse contador e a medida de quanto o bloqueio custaria se
//  fosse ligado hoje.
//

#define SAFEUPLOAD_POLICY_FLAG_AUDIT_ONLY ((UINT32) 0x00000004)

//
//  Dois modos de bloqueio, e so dois: com justificativa e sem.
//
//  Ligado, o usuario que levou uma recusa pode informar um motivo de negocio
//  e seguir - com o motivo registrado. Desligado, o mecanismo inteiro fica
//  fora do ar: o driver recusa conceder excecao, entao nem uma interface
//  comprometida consegue liberar nada.
//
//  A escolha e da organizacao, nao do usuario, e por isso vive na politica.
//

#define SAFEUPLOAD_POLICY_FLAG_ALLOW_OVERRIDE ((UINT32) 0x00000008)

/* Feature-build qualification only. Normal drivers reject this bit. It
 * bypasses both process-taint recording and lookup, never staged admission. */
#define SAFEUPLOAD_POLICY_FLAG_TEST_DISABLE_TAINT ((UINT32) 0x00000020)

// Classify supported file reads anywhere, without a configured source path.
#define SAFEUPLOAD_POLICY_FLAG_CLASSIFY_ALL_SOURCES ((UINT32) 0x00000010)

/* SET_POLICY Control.Reserved: sent only after Scopes is flushed and
 * PendingScopes is durably removed. Keeps protocol layout/version 18. */
#define SAFEUPLOAD_POLICY_CONTROL_FINALIZE_BOOT_SCOPES ((UINT32) 0x00000001)

/*
 * Durable registry format. It is separate from the port protocol: each
 * committed record has at most the live protocol's 16 destination prefixes;
 * PendingScopes may hold the union of the old and candidate records (32).
 * The driver reads both bounded records in DriverEntry before it starts
 * filtering. Version/size are exact and every unused slot must be zero.
 */
#define SAFEUPLOAD_BOOT_POLICY_FLAG_REMOVABLE ((UINT32) 0x00000001)
#define SAFEUPLOAD_BOOT_POLICY_FLAG_NETWORK   ((UINT32) 0x00000002)
typedef struct _SAFEUPLOAD_BOOT_POLICY {
    UINT32 Version;
    UINT32 StructSize;
    UINT32 PrefixCount;
    UINT32 Flags;
    WCHAR Prefixes[SAFEUPLOAD_BOOT_POLICY_MAX_PREFIXES][SAFEUPLOAD_MAX_PREFIX_CHARS];
} SAFEUPLOAD_BOOT_POLICY, *PSAFEUPLOAD_BOOT_POLICY;


#define SAFEUPLOAD_BOOT_POLICY_STATE_VALID          ((UINT32) 1)
#define SAFEUPLOAD_BOOT_POLICY_STATE_MISSING        ((UINT32) 2)
#define SAFEUPLOAD_BOOT_POLICY_STATE_CORRUPT_PARTIAL ((UINT32) 3)
#define SAFEUPLOAD_BOOT_POLICY_STATE_CORRUPT_EMPTY   ((UINT32) 4)
#define SAFEUPLOAD_BOOT_POLICY_STATE_ACL_REJECTED   ((UINT32) 5)
#define SAFEUPLOAD_BOOT_POLICY_STATE_UNREADABLE     ((UINT32) 6)
#define SAFEUPLOAD_BOOT_POLICY_STATE_PENDING_UNION  ((UINT32) 7)

#define SAFEUPLOAD_VOLUME_TRUST_UNTRUSTED_FLAGS      ((UINT32) 0)
#define SAFEUPLOAD_VOLUME_TRUST_CANARY_PENDING       ((UINT32) 1)
#define SAFEUPLOAD_VOLUME_TRUST_CONTEXT_UNAVAILABLE  ((UINT32) 2)
#define SAFEUPLOAD_VOLUME_TRUST_CANARY_PASSED        ((UINT32) 3)
#define SAFEUPLOAD_VOLUME_TRUST_CANARY_LOST          ((UINT32) 4)
#define SAFEUPLOAD_VOLUME_TRUST_PENDING_REBOOT       ((UINT32) 5)
#define SAFEUPLOAD_VOLUME_TRUST_DETACHED              ((UINT32) 6)
/* Filter Manager's FLTFL_INSTANCE_SETUP_NEWLY_MOUNTED_VOLUME value, mirrored
 * for the test inspector. The feature diagnostic packs TrustState into the
 * high 16 bits of SetupFlags so its existing version-18 record stays sized. */
#define SAFEUPLOAD_SETUP_FLAG_NEWLY_MOUNTED_VOLUME    ((UINT32) 0x00000004)
#define SAFEUPLOAD_SETUP_TRUST_STATE_SHIFT            ((UINT32) 16)
#define SAFEUPLOAD_SETUP_FLAGS_MASK                   ((UINT32) 0x0000FFFF)

typedef struct _SAFEUPLOAD_CONTROL {

    UINT32 Version;
    UINT32 StructSize;
    UINT32 Command;
    UINT32 Reserved;

} SAFEUPLOAD_CONTROL, *PSAFEUPLOAD_CONTROL;


//
//  The policy, as user mode hands it down.
//
//  Prefixes arrive in NT form (\Device\HarddiskVolume3\...), already
//  converted. That conversion belongs to user mode and happens once, when
//  the policy is loaded: doing it in the kernel would mean converting on
//  every operation, which is the cost this whole design exists to avoid.
//

typedef struct _SAFEUPLOAD_POLICY_MESSAGE {

    SAFEUPLOAD_CONTROL Control;

    UINT32 ExtensionCount;
    UINT32 PrefixCount;
    UINT32 ImageCount;
    UINT32 SourcePrefixCount;

    //
    //  SAFEUPLOAD_POLICY_FLAG_*: whether removable media and network
    //  volumes are monitored destinations in their own right, independent
    //  of any path prefix.
    //

    UINT32 Flags;

    //
    //  How long the kernel waits for a verdict, in milliseconds.
    //
    //  It comes from the policy rather than from a constant in the driver
    //  because the deadline belongs to the inspection, not to the
    //  transport: RN-012 gives the engine a budget, and having the same
    //  number written in two places is exactly how the two drift apart.
    //  User mode owns the value and the driver enforces it.
    //
    //  Zero means "use the driver's default", which is what an older
    //  client sending a zeroed Reserved field would produce - and the
    //  interpretation that keeps such a client working rather than giving
    //  it a zero-millisecond timeout, under which nothing is ever
    //  inspected.
    //
    //  Clamped by the driver to [SAFEUPLOAD_VERDICT_TIMEOUT_MIN_MS,
    //  SAFEUPLOAD_VERDICT_TIMEOUT_MAX_MS]. The upper bound is not a
    //  formality: this is time a file open is stalled, so a policy asking
    //  for a minute would hang the machine on the first monitored file.
    //

    UINT32 VerdictTimeoutMs;

    //
    //  Monitored extensions, with the leading dot, NUL-terminated.
    //

    WCHAR Extensions[SAFEUPLOAD_MAX_EXTENSIONS][SAFEUPLOAD_MAX_EXTENSION_CHARS];

    //
    //  Monitored path prefixes in NT form, NUL-terminated. A file is in
    //  scope when its normalized path starts with one of these.
    //

    WCHAR Prefixes[SAFEUPLOAD_MAX_PREFIXES][SAFEUPLOAD_MAX_PREFIX_CHARS];

    //
    //  Monitored SOURCE prefixes in NT form, NUL-terminated.
    //
    //  A different question from the destination list, and the two are not
    //  interchangeable. Destination scope asks "may a file end up here?".
    //  Source scope asks "is a file here worth reading to find out whether
    //  it is sensitive?" - which is what lets a process be marked as having
    //  handled sensitive content, so that a later write to a destination
    //  can be denied without inspecting anything.
    //
    //  Source scope is normally much broader than destination scope: user
    //  document folders, rather than the handful of places a file must not
    //  reach.
    //

    WCHAR SourcePrefixes[SAFEUPLOAD_MAX_SOURCE_PREFIXES][SAFEUPLOAD_MAX_PREFIX_CHARS];

    //
    //  Process images whose I/O is never inspected, NUL-terminated, final
    //  component only (for example "SafeUpload.Agent.Service.exe").
    //

    WCHAR Images[SAFEUPLOAD_MAX_IMAGES][SAFEUPLOAD_MAX_IMAGE_CHARS];

} SAFEUPLOAD_POLICY_MESSAGE, *PSAFEUPLOAD_POLICY_MESSAGE;


//
//  Mensagem de SAFEUPLOAD_CONTROL_GRANT_OVERRIDE.
//
//  O caminho e exato, e nao prefixo: uma excecao para uma pasta valeria para
//  tudo que fosse escrito nela depois. O prazo e limitado pelo driver entre
//  SAFEUPLOAD_OVERRIDE_MIN_SECONDS e SAFEUPLOAD_OVERRIDE_MAX_SECONDS - uma
//  excecao e um buraco na protecao, e um que dure uma hora e um buraco com
//  nome.
//

typedef struct _SAFEUPLOAD_OVERRIDE_MESSAGE {

    SAFEUPLOAD_CONTROL Control;

    UINT32 ProcessId;

    //
    //  Prazo pedido, em segundos. O driver limita.
    //

    UINT32 DurationSeconds;

    //
    //  Bytes de PathLength, sem o terminador.
    //

    UINT32 PathLength;

    UINT32 Reserved;

    //
    //  Caminho de destino em forma de dispositivo, como o filtro os entrega.
    //

    WCHAR Path[SAFEUPLOAD_MAX_PATH_CHARS];

} SAFEUPLOAD_OVERRIDE_MESSAGE, *PSAFEUPLOAD_OVERRIDE_MESSAGE;


// Authenticated service permit. Revoke=1 invalidates the transfer permit.
// Paths are exact normalized device names. Digest identifies inspected bytes;
// the service holds the snapshot read lock throughout the permit lifetime.
typedef struct _SAFEUPLOAD_PUBLICATION_MESSAGE {
    SAFEUPLOAD_CONTROL Control;
    GUID TransferId;
    UINT32 Revoke;
    UINT32 TemporaryPathLength;
    UINT32 DestinationPathLength;
    UINT32 Reserved;
    UCHAR Digest[32];
    WCHAR TemporaryPath[SAFEUPLOAD_MAX_PATH_CHARS];
    WCHAR DestinationPath[SAFEUPLOAD_MAX_PATH_CHARS];
} SAFEUPLOAD_PUBLICATION_MESSAGE, *PSAFEUPLOAD_PUBLICATION_MESSAGE;

#if defined(SAFEUPLOAD_STAGING_PROTOTYPE) && SAFEUPLOAD_STAGING_PROTOTYPE

/* Test-only canary hold; declared after SAFEUPLOAD_CONTROL, which it embeds. */
typedef struct _SAFEUPLOAD_ADMISSION_CANARY_HOLD_REQUEST {
    SAFEUPLOAD_CONTROL Control;
    UINT32 HoldMilliseconds;
    UINT16 VolumeNameChars;
    UINT16 Reserved;
    WCHAR VolumeName[SAFEUPLOAD_CANARY_VOLUME_CHARS];
} SAFEUPLOAD_ADMISSION_CANARY_HOLD_REQUEST, *PSAFEUPLOAD_ADMISSION_CANARY_HOLD_REQUEST;

typedef struct _SAFEUPLOAD_ADMISSION_CANARY_HOLD_REPLY {
    UINT32 StructSize;
    UINT32 Status;
    UINT32 PathChars;
    UINT32 Reserved;
    WCHAR CanaryPath[SAFEUPLOAD_MAX_PATH_CHARS];
} SAFEUPLOAD_ADMISSION_CANARY_HOLD_REPLY, *PSAFEUPLOAD_ADMISSION_CANARY_HOLD_REPLY;

// Variable tail: volume name followed by relative path, with no terminators.
// Control.StructSize is the exact byte count for the declared character counts.
typedef struct _SAFEUPLOAD_ADMISSION_PROBE_REQUEST {
    SAFEUPLOAD_CONTROL Control;
    UINT16 VolumeNameChars;
    UINT16 RelativePathChars;
    UINT32 Reserved;
    WCHAR Strings[1];
} SAFEUPLOAD_ADMISSION_PROBE_REQUEST, *PSAFEUPLOAD_ADMISSION_PROBE_REQUEST;

/* Test-build-only request: remove one named C: fixture's stream context while its writer stays open. */
typedef struct _SAFEUPLOAD_ADMISSION_DELETE_STREAM_CONTEXT_REQUEST {
    SAFEUPLOAD_CONTROL Control;
    UINT16 VolumeNameChars;
    UINT16 RelativePathChars;
    UINT32 Reserved;
    WCHAR DriveLetter;
    WCHAR Reserved2;
    WCHAR Strings[1];
} SAFEUPLOAD_ADMISSION_DELETE_STREAM_CONTEXT_REQUEST,
  *PSAFEUPLOAD_ADMISSION_DELETE_STREAM_CONTEXT_REQUEST;

/* Feature-only diagnostic; Pending/Running or any query failure never proves trust. */
typedef struct _SAFEUPLOAD_ADMISSION_VOLUME_ENTRY {
    UINT64 Instance;
    UINT32 VolumeKind;
    UINT32 FileSystemType;
    UINT32 FileSystemStatus;
    UINT32 SetupFlags;
    UINT32 CanaryState;
    UINT32 CanaryStatus;
    UINT32 CanaryChecks;
    UINT32 CanaryCleanupStatus;
    UINT32 InstanceWritersUntracked;
    UINT32 ContextStatus;
    UINT32 VolumeGuidStatus;
    UINT32 VolumeGuidChars;
    UINT32 VolumeInfoStatus;
    UINT32 VolumeFlags;
#if defined(SAFEUPLOAD_STAGING_PROTOTYPE) && SAFEUPLOAD_STAGING_PROTOTYPE
    UINT32 InstanceRegistryUnknownReasons; /* Existing sticky per-instance mask; read-only evidence. */
    UINT32 FirstUnknownReason; /* First successful context publication, not event chronology. */
    UINT32 FirstUnknownSite; /* Origin line without file ID; use exact source and successful ContextStatus. */
#endif
    WCHAR VolumeGuid[64];
} SAFEUPLOAD_ADMISSION_VOLUME_ENTRY, *PSAFEUPLOAD_ADMISSION_VOLUME_ENTRY;

typedef struct _SAFEUPLOAD_ADMISSION_VOLUME_STATUS {
    UINT32 StructSize;
    UINT32 EntryCount;
    UINT32 WriterGlobalUnknown;
    UINT32 BootPolicyState;
    SAFEUPLOAD_ADMISSION_VOLUME_ENTRY Entries[SAFEUPLOAD_ADMISSION_VOLUME_MAX_ENTRIES];
} SAFEUPLOAD_ADMISSION_VOLUME_STATUS, *PSAFEUPLOAD_ADMISSION_VOLUME_STATUS;

/* Read-only, bounded admission-coverage receipt. It describes only the
 * current accepted destination admission gates. It is not a byte-privacy or
 * retained-section-lifetime claim. Prefixes are echoed so the caller can bind
 * the receipt to the policy whose final SET_POLICY was acknowledged. */
typedef struct _SAFEUPLOAD_ADMISSION_COVERAGE_SCOPE {
    UINT32 ScopeKind;
    UINT32 ScopeIndex;
    UINT32 Resolution;
    UINT32 State;
    UINT32 Reason;
    UINT32 MatchingInstances;
    UINT32 UniqueVolumes;
    UINT32 ReadyInstances;
    UINT32 PrefixChars;
    WCHAR Prefix[SAFEUPLOAD_MAX_PREFIX_CHARS];
} SAFEUPLOAD_ADMISSION_COVERAGE_SCOPE, *PSAFEUPLOAD_ADMISSION_COVERAGE_SCOPE;
C_ASSERT(sizeof(SAFEUPLOAD_ADMISSION_COVERAGE_SCOPE) == 556);

typedef struct _SAFEUPLOAD_ADMISSION_COVERAGE_STATUS {
    UINT32 StructSize;
    UINT32 ProtocolVersion;
    UINT32 State;
    UINT32 Flags;
    UINT32 PolicyGeneration;
    UINT32 PolicyFlags;
    UINT32 BootPolicyState;
    UINT32 ScopeCount;
    UINT32 ExpectedScopeCount;
    UINT32 PolicyGenerationEnd;
    UINT32 PolicyFlagsEnd;
    UINT32 BootPolicyStateEnd;
    UINT32 EpochGeneration;
    UINT32 EpochFlags;
    UINT32 EpochActiveCallbacks;
    UINT32 EpochGenerationEnd;
    UINT32 EpochFlagsEnd;
    UINT32 EpochActiveCallbacksEnd;
    UINT32 EnumeratedInstances;
    UINT32 SetupInFlight;
    UINT32 TeardownInFlight;
    UINT32 CoverageChangesInFlight;
    UINT32 WriterGlobalUnknown;
    UINT32 WriterEntries;
    UINT32 WriterEntriesNotReady;
    UINT32 WriterEntriesUnknown;
    UINT32 FutureMountGateReady;
    UINT32 Reason;
    UINT64 PolicyScopeSequenceStart;
    UINT64 PolicyScopeSequenceEnd;
    UINT64 TopologySequenceStart;
    UINT64 TopologySequenceEnd;
    UINT64 CoverageSequenceStart;
    UINT64 CoverageSequenceEnd;
    UINT64 RegistrySequenceStart;
    UINT64 RegistrySequenceEnd;
    SAFEUPLOAD_ADMISSION_COVERAGE_SCOPE Scopes[SAFEUPLOAD_ADMISSION_COVERAGE_MAX_SCOPES];
} SAFEUPLOAD_ADMISSION_COVERAGE_STATUS, *PSAFEUPLOAD_ADMISSION_COVERAGE_STATUS;
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_ADMISSION_COVERAGE_STATUS, Scopes) == 176);
C_ASSERT(sizeof(SAFEUPLOAD_ADMISSION_COVERAGE_STATUS) == 54664);
C_ASSERT(sizeof(SAFEUPLOAD_ADMISSION_COVERAGE_STATUS) <= 64 * 1024);

/*
 *  Mapped-writable stream diagnostics and protected-name quarantine. STATUS reads
 *  this; REFRESH reruns the scan. PagingWritesDenied is reserved and always zero.
 */
typedef struct _SAFEUPLOAD_FENCE_STATUS {
    UINT32 StructSize;
    UINT32 Entries;
    UINT32 Generation;
    UINT32 LastStatus;               // NTSTATUS of the latest refresh
    UINT32 FailureLine;              // StageFence.c line of the latest failed scan's first failure
    UINT32 StateFlags;              // SAFEUPLOAD_FENCE_STATUS_FLAG_*
    UINT64 RefreshStarted;
    UINT64 RefreshCompleted;
    UINT64 RefreshFailed;
    UINT64 PagingWritesDenied;        // reserved; always zero
    UINT64 OpensRefused;
    UINT64 DirectoriesScanned;
    UINT64 FilesScanned;
    UINT64 ReparseSkipped;
    UINT64 VolumeScopesSkipped;      // removable/network scopes the scan does not cover
    UINT64 StreamsReleased;          // entries dropped after their dirty pages were purged
    UINT64 ReleaseRefused;           // release attempts that left a stream fenced (still mapped or purge failed)
    UINT64 SectionsDenied;           // writable data sections refused on an unadmitted in-scope stream
    UINT64 SectionNameUnresolved;    // writable sections denied because no name could be resolved
    UINT64 FsctlUnresolved;          // selected mutating FSCTLs denied because name or NTFS alias scope was unresolved
    UINT64 LateRefreshesQueued;      // refreshes queued by an instance attachment after the load
} SAFEUPLOAD_FENCE_STATUS, *PSAFEUPLOAD_FENCE_STATUS;

#define SAFEUPLOAD_FENCE_STATUS_FLAG_LATE_REFRESH_PENDING ((UINT32)0x00000001)
#define SAFEUPLOAD_FENCE_STATUS_FLAG_UNLOAD_GATE_CLOSED   ((UINT32)0x00000002)
#define SAFEUPLOAD_FENCE_STATUS_FLAG_REFRESH_ACTIVE       ((UINT32)0x00000004)
#define SAFEUPLOAD_FENCE_STATUS_FLAG_QUARANTINED           ((UINT32)0x00000008)
/* Reuses StateFlags' former Reserved word; SAFEUPLOAD_FENCE_STATUS size is unchanged. */
#define SAFEUPLOAD_FENCE_STATUS_FLAG_RETRY_PENDING         ((UINT32)0x00000010)

/*
 *  Writer-state primitives (feature build, observe-only). H(F): file objects opened with write access,
 *  per stream. C(F): writable CreateSections acquired but not yet released. Counters are global.
 */
typedef struct _SAFEUPLOAD_WRITER_STATE_STATUS {
    UINT32 StructSize;
    UINT32 SectionInFlightNow;       // writable CreateSections acquired and not yet released
    UINT64 PostCreateRuns;           // post-create callbacks that looked at a successful create
    UINT64 WriteObjectsCounted;      // write file objects added to a stream's writer list
    UINT64 WriteObjectsReleased;     // write file objects removed again at IRP_MJ_CLEANUP
    UINT64 UntrackedCreates;         // write opens that could not be tracked (no stream contexts, allocation failure)
    UINT64 CleanupUnmatched;         // cleanups of write file objects that were never counted
    UINT64 DirectoryCreatesSkipped;  // write-access opens of directories, not counted
    UINT64 SectionInFlightInserted;
    UINT64 SectionInFlightReleased;
    UINT64 RetiredSectionOverflow;   // always 0: formerly the fixed-table overflow count (overflow now marks Unknown)
    UINT64 SectionInFlightStuck;     // entries older than the stuck threshold when sampled
    UINT64 SectionInFlightRemovedOnFailure;  // entries removed by post-operation because the acquire failed
    UINT32 SectionInFlightMaxDepth;
    UINT32 CleanupDirectoriesSkipped; // cleanups of write/delete-access directory handles, deliberately not tracked (formerly Reserved)
    UINT64 PagingCreatesSkipped;
    UINT64 VolumeCreatesSkipped;
    UINT32 StageStreams;
    UINT32 StageFileObjects;
    UINT32 LastUnloadVeto;
    UINT32 LastUnloadStatus;
#if defined(SAFEUPLOAD_STAGING_PROTOTYPE) && SAFEUPLOAD_STAGING_PROTOTYPE
    UINT64 WritersDroppedAtTeardown;      // writer nodes released with a teardown-marked instance token
    UINT64 WritersDroppedWhileMounted;    // writer nodes released before instance teardown was marked
    UINT64 InstanceTeardownsDismount;     // InstanceTeardownStart with FLTFL_INSTANCE_TEARDOWN_VOLUME_DISMOUNT
    UINT64 InstanceTeardownsOther;        // any other teardown reason (unload, manual, internal error)
    UINT64 TxfRefused;
    UINT64 RegistryCapacityFailures;
    UINT64 RegistryAllocationFailures;
    UINT64 RegistryIdentityFailures;
    UINT64 RegistryTransactionFailures;
    UINT64 RegistryRenameFailures;
    UINT64 RegistryDroppedAtDismount;
    UINT64 RegistryDroppedWhileMounted;
    UINT32 RegistryEntries;
    UINT32 RegistryReservations;
    UINT32 RegistryOverflow;
    UINT32 RegistryUnknownReasons;
    UINT32 RegistryInstanceUnknown;
    UINT32 RegistryCapacity;
    UINT32 TransactionAssociations;
    UINT32 Reserved2;
    UINT64 RegistryPruned;                // entries removed once provably quiescent (no writer, section, cache or transaction)
    UINT64 RegistryReclaimPasses;         // reclaim worker passes (queued at 3/4 of a limit or on a capacity failure)
    UINT32 RegistryNameTierEntries;       // live entries retaining full names
    UINT32 RegistryCompactTierEntries;    // live fixed-pool entries retaining identity without a path
#endif
} SAFEUPLOAD_WRITER_STATE_STATUS, *PSAFEUPLOAD_WRITER_STATE_STATUS;

#if defined(SAFEUPLOAD_STAGING_PROTOTYPE) && SAFEUPLOAD_STAGING_PROTOTYPE
#define SAFEUPLOAD_REGISTRY_STATE_UNSCOPED   ((UINT32)0)
#define SAFEUPLOAD_REGISTRY_STATE_ACTIVATING ((UINT32)1)
#define SAFEUPLOAD_REGISTRY_STATE_PROTECTED  ((UINT32)2)
#define SAFEUPLOAD_REGISTRY_STATE_UNKNOWN    ((UINT32)3)
#define SAFEUPLOAD_REGISTRY_S_UNKNOWN        ((UINT32)0)
#define SAFEUPLOAD_REGISTRY_S_NO             ((UINT32)1)
#define SAFEUPLOAD_REGISTRY_S_YES            ((UINT32)2)

/* Returned by the prototype-only registry-entry diagnostic after a passive file-ID probe. */
typedef struct _SAFEUPLOAD_REGISTRY_ENTRY_STATUS {
    UINT32 StructSize;
    UINT32 HistoryPresent;
    UINT32 State;
    UINT32 Free;
    UINT32 H;
    UINT32 S;
    UINT32 C;
    UINT32 T;
    UINT32 UnknownReasons;
    UINT32 FirstSeenGeneration;
    UINT64 VolumeSerialNumber;
    UINT8 FileId[16];
    UINT32 OpenerPidCount;
    UINT32 OpenerPids[8];
    UINT32 NameMatches;
} SAFEUPLOAD_REGISTRY_ENTRY_STATUS, *PSAFEUPLOAD_REGISTRY_ENTRY_STATUS;

#define SAFEUPLOAD_ACTIVATING_STATUS_MAX_ENTRIES ((UINT32)32)
typedef struct _SAFEUPLOAD_ACTIVATING_ENTRY_STATUS {
    UINT64 VolumeSerialNumber;
    UCHAR FileId[16];
    UINT32 Generation;
    UINT32 State;
    UINT32 H;
    UINT32 S;
    UINT32 C;
    UINT32 T;
    UINT32 W;
    UINT32 UnknownReasons;
    UINT32 ReservedFlags;
    UINT32 OpenerPidCount;
    UINT32 OpenerPids[8];
    UINT32 NameChars;
    WCHAR Name[SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS];
} SAFEUPLOAD_ACTIVATING_ENTRY_STATUS, *PSAFEUPLOAD_ACTIVATING_ENTRY_STATUS;

/* Reserved is the entry index. The 32-entry page remains below 64 KiB with 512-WCHAR paths. */
typedef struct _SAFEUPLOAD_ACTIVATING_STATUS_PAGE {
    UINT32 StructSize;
    UINT32 TotalEntries;
    UINT32 EntryCount;
    UINT32 StartIndex;
    UINT32 NextIndex;
    UINT32 PolicyGeneration;
    UINT64 ChangeSequence;
    UINT32 Flags;
    UINT32 Reserved;
    SAFEUPLOAD_ACTIVATING_ENTRY_STATUS Entries[SAFEUPLOAD_ACTIVATING_STATUS_MAX_ENTRIES];
} SAFEUPLOAD_ACTIVATING_STATUS_PAGE, *PSAFEUPLOAD_ACTIVATING_STATUS_PAGE;
C_ASSERT(sizeof(SAFEUPLOAD_ACTIVATING_STATUS_PAGE) <= 64 * 1024);

/* Inspector-only extension. Control 19 remains the fixed v18 agent evidence
 * wire page; this separate control exposes the last alias-classification result. */
#define SAFEUPLOAD_ACTIVATING_CLASSIFY_STEP_NONE          ((UINT32)0)
#define SAFEUPLOAD_ACTIVATING_CLASSIFY_STEP_OPEN_BY_ID    ((UINT32)1)
#define SAFEUPLOAD_ACTIVATING_CLASSIFY_STEP_LINK_QUERY    ((UINT32)2)
#define SAFEUPLOAD_ACTIVATING_CLASSIFY_STEP_PARENT_OPEN   ((UINT32)3)
#define SAFEUPLOAD_ACTIVATING_CLASSIFY_STEP_NAME_BUILD    ((UINT32)4)
#define SAFEUPLOAD_ACTIVATING_CLASSIFY_STEP_OTHER         ((UINT32)5)
#define SAFEUPLOAD_ACTIVATING_CLASSIFY_STEP_NO_NAMES      ((UINT32)6)
#define SAFEUPLOAD_ACTIVATING_CLASSIFY_STEP_PAGING_FILE   ((UINT32)7)
#define SAFEUPLOAD_ACTIVATING_CLASSIFY_STEP_OUTSIDE       ((UINT32)8)
#define SAFEUPLOAD_ACTIVATING_CLASSIFY_STEP_NOT_RUN       ((UINT32)9)
#define SAFEUPLOAD_ACTIVATING_CLASSIFY_STEP_FLUSH_PURGE   ((UINT32)10)
#define SAFEUPLOAD_ACTIVATING_CLASSIFY_STEP_CACHE_RETAINED ((UINT32)11)
/* Diagnostic rows for the activation pass's other deferrals. ClassificationStatus carries NTSTATUS-style detail:
 * LINK_SCAN_MORE and SCOPE_DEFERRED the pass status, MARKERS_LIVE STATUS_PENDING, and PROMOTE_DEFERRED
 * 0xE0000000 | SAFEUPLOAD_PROMOTE_FAIL_* (every predicate of the promotion CAS that did not hold). */
#define SAFEUPLOAD_ACTIVATING_CLASSIFY_STEP_LINK_SCAN_MORE ((UINT32)12)
#define SAFEUPLOAD_ACTIVATING_CLASSIFY_STEP_SCOPE_DEFERRED ((UINT32)13)
#define SAFEUPLOAD_ACTIVATING_CLASSIFY_STEP_MARKERS_LIVE   ((UINT32)14)
#define SAFEUPLOAD_ACTIVATING_CLASSIFY_STEP_PROMOTE_DEFERRED ((UINT32)15)
/* ClassificationStatus 0xD0000000 | source line of the StageRegistryActivationProcess exit that left the pass. */
#define SAFEUPLOAD_ACTIVATING_CLASSIFY_STEP_EXIT_SITE      ((UINT32)16)
#define SAFEUPLOAD_PROMOTE_FAIL_NOT_LISTED           ((ULONG)0x00000001)
#define SAFEUPLOAD_PROMOTE_FAIL_STATE                ((ULONG)0x00000002)
#define SAFEUPLOAD_PROMOTE_FAIL_H                    ((ULONG)0x00000004)
#define SAFEUPLOAD_PROMOTE_FAIL_T                    ((ULONG)0x00000008)
#define SAFEUPLOAD_PROMOTE_FAIL_W                    ((ULONG)0x00000010)
#define SAFEUPLOAD_PROMOTE_FAIL_UNKNOWN              ((ULONG)0x00000020)
#define SAFEUPLOAD_PROMOTE_FAIL_RENAME_IN_FLIGHT     ((ULONG)0x00000040)
#define SAFEUPLOAD_PROMOTE_FAIL_DIRECTORY_RENAME     ((ULONG)0x00000080)
#define SAFEUPLOAD_PROMOTE_FAIL_RENAME_VERSION       ((ULONG)0x00000100)
#define SAFEUPLOAD_PROMOTE_FAIL_ACTIVATION_GENERATION ((ULONG)0x00000200)
#define SAFEUPLOAD_PROMOTE_FAIL_NOT_ENFORCED         ((ULONG)0x00000400)
#define SAFEUPLOAD_PROMOTE_FAIL_NOT_SCOPED           ((ULONG)0x00000800)
#define SAFEUPLOAD_PROMOTE_FAIL_NAME                 ((ULONG)0x00001000)
#define SAFEUPLOAD_PROMOTE_FAIL_SPILLED_WRITERS      ((ULONG)0x00002000)
#define SAFEUPLOAD_PROMOTE_FAIL_SPILLED_MUTATING_IO  ((ULONG)0x00004000)
#define SAFEUPLOAD_PROMOTE_FAIL_SOP_NOT_EMPTY        ((ULONG)0x00008000)
#define SAFEUPLOAD_PROMOTE_FAIL_C                    ((ULONG)0x00010000)
#define SAFEUPLOAD_PROMOTE_FAIL_SIBLING              ((ULONG)0x00020000)
#define SAFEUPLOAD_PROMOTE_FAIL_REBOUND              ((ULONG)0x00040000)
#define SAFEUPLOAD_PROMOTE_FAIL_STATE_RECHECK        ((ULONG)0x00080000)
#define SAFEUPLOAD_PROMOTE_FAIL_SOP_MAP_MOVED        ((ULONG)0x00100000)
#define SAFEUPLOAD_PROMOTE_FAIL_INSTANCE_CONTEXT     ((ULONG)0x00200000)
#define SAFEUPLOAD_PROMOTE_FAIL_RENAME_LOSS          ((ULONG)0x00400000)

typedef struct _SAFEUPLOAD_ACTIVATING_DIAGNOSTIC_ENTRY_STATUS {
    SAFEUPLOAD_ACTIVATING_ENTRY_STATUS Entry;
    UINT32 ClassificationStatus;
    UINT32 ClassificationStep;
} SAFEUPLOAD_ACTIVATING_DIAGNOSTIC_ENTRY_STATUS,
    *PSAFEUPLOAD_ACTIVATING_DIAGNOSTIC_ENTRY_STATUS;

typedef struct _SAFEUPLOAD_ACTIVATING_DIAGNOSTIC_STATUS_PAGE {
    UINT32 StructSize;
    UINT32 TotalEntries;
    UINT32 EntryCount;
    UINT32 StartIndex;
    UINT32 NextIndex;
    UINT32 PolicyGeneration;
    UINT64 ChangeSequence;
    UINT32 Flags;
    UINT32 Reserved;
    SAFEUPLOAD_ACTIVATING_DIAGNOSTIC_ENTRY_STATUS Entries[SAFEUPLOAD_ACTIVATING_STATUS_MAX_ENTRIES];
} SAFEUPLOAD_ACTIVATING_DIAGNOSTIC_STATUS_PAGE,
    *PSAFEUPLOAD_ACTIVATING_DIAGNOSTIC_STATUS_PAGE;
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_ACTIVATING_DIAGNOSTIC_ENTRY_STATUS, Entry) == 0);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_ACTIVATING_DIAGNOSTIC_ENTRY_STATUS, ClassificationStatus) ==
    sizeof(SAFEUPLOAD_ACTIVATING_ENTRY_STATUS));
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_ACTIVATING_DIAGNOSTIC_ENTRY_STATUS, ClassificationStep) ==
    sizeof(SAFEUPLOAD_ACTIVATING_ENTRY_STATUS) + sizeof(UINT32));
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_ACTIVATING_DIAGNOSTIC_STATUS_PAGE, Entries) ==
    FIELD_OFFSET(SAFEUPLOAD_ACTIVATING_STATUS_PAGE, Entries));
C_ASSERT(sizeof(SAFEUPLOAD_ACTIVATING_DIAGNOSTIC_ENTRY_STATUS) ==
    sizeof(SAFEUPLOAD_ACTIVATING_ENTRY_STATUS) + 8);
C_ASSERT(sizeof(SAFEUPLOAD_ACTIVATING_DIAGNOSTIC_STATUS_PAGE) <= 64 * 1024);

/* Feature-only exact-name registry observation. MatchCount describes ONLY the
 * requested normalized NT name. Sequence endpoints are diagnostic global
 * values, NOT an assertion of a coherent machine-wide or interval snapshot. */
typedef struct _SAFEUPLOAD_ACTIVATING_TARGET_STATUS {
    UINT32 StructSize;
    UINT32 MatchCount;
    UINT32 PolicyGeneration;
    UINT32 Flags; /* bit 0: global registry uncertainty */
    UINT64 SequenceStart;
    UINT64 SequenceEnd;
    SAFEUPLOAD_ACTIVATING_DIAGNOSTIC_ENTRY_STATUS Diagnostic;
} SAFEUPLOAD_ACTIVATING_TARGET_STATUS, *PSAFEUPLOAD_ACTIVATING_TARGET_STATUS;
C_ASSERT(sizeof(SAFEUPLOAD_ACTIVATING_TARGET_STATUS) == 1168);

#define SAFEUPLOAD_ADMISSION_EPOCH_FLAG_PENDING       ((UINT32)0x00000001)
#define SAFEUPLOAD_ADMISSION_EPOCH_FLAG_FAILED_CLOSED ((UINT32)0x00000002)
#define SAFEUPLOAD_ADMISSION_EPOCH_FLAG_FINALIZING     ((UINT32)0x00000004)
typedef struct _SAFEUPLOAD_ADMISSION_EPOCH_STATUS {
    UINT32 StructSize;
    UINT32 PolicyGeneration;
    UINT32 EpochGeneration;
    UINT32 ActiveCallbacks;
    UINT32 Flags;
    UINT32 Reserved;
    UINT64 ChangeSequence;
} SAFEUPLOAD_ADMISSION_EPOCH_STATUS, *PSAFEUPLOAD_ADMISSION_EPOCH_STATUS;

/*
 *  Deny ring. Every operation SafeUpload completes itself with an error status (the pre-operation choke point in
 *  SafeUploadStageDispatch) is recorded in a fixed ring: no allocation and no name query on the I/O path. The
 *  newest SAFEUPLOAD_DENY_RING_SLOTS records are kept; a reader that falls behind sees the gap flag.
 *
 *  SiteOffset names the code that chose the refusal when it went through a shared refusal helper (the offset of the
 *  helper's caller from ImageBase, resolved offline with the driver's PDB); it is 0 when only the choke point saw it.
 *  Name is the tail of what the request itself carried: the requested path of a create (possibly relative to a
 *  directory handle) or the target of a rename or link. It is empty for every other operation.
 */
#define SAFEUPLOAD_DENY_RING_SLOTS          ((UINT32) 256)
#define SAFEUPLOAD_DENY_BATCH_ENTRIES       ((UINT32) 16)
#define SAFEUPLOAD_DENY_NAME_CHARS          ((UINT32) 64)

#define SAFEUPLOAD_DENY_FLAG_TOP_LEVEL_IRP        ((UINT32) 0x00000001)  /* IoGetTopLevelIrp() was non-NULL */
#define SAFEUPLOAD_DENY_FLAG_TRANSACTION          ((UINT32) 0x00000002)
#define SAFEUPLOAD_DENY_FLAG_PAGING_IO            ((UINT32) 0x00000004)
#define SAFEUPLOAD_DENY_FLAG_FAST_IO              ((UINT32) 0x00000008)
#define SAFEUPLOAD_DENY_FLAG_POST_OPERATION       ((UINT32) 0x00000010)  /* post-create cancel, not a pre-operation */
#define SAFEUPLOAD_DENY_FLAG_NAME_IS_RENAME_TARGET ((UINT32) 0x00000020)
#define SAFEUPLOAD_DENY_FLAG_NAME_IS_CREATE_NAME  ((UINT32) 0x00000040)
#define SAFEUPLOAD_DENY_FLAG_SERVICE_PROCESS      ((UINT32) 0x00000080)  /* requestor is the connected service */
#define SAFEUPLOAD_DENY_FLAG_KERNEL_MODE          ((UINT32) 0x00000100)  /* requestor mode was KernelMode */
#define SAFEUPLOAD_DENY_FLAG_NAME_TRUNCATED       ((UINT32) 0x00000200)  /* Name holds the tail of a longer name */

#define SAFEUPLOAD_DENY_BATCH_FLAG_GAP            ((UINT32) 0x00000001)  /* records after the cursor were overwritten */

typedef struct _SAFEUPLOAD_DENY_RECORD {
    UINT64 Sequence;                // 1-based, strictly increasing; 0 never appears in a reply
    UINT64 SystemTime;              // 100 ns since 1601 (KeQuerySystemTimePrecise)
    UINT32 Status;                  // NTSTATUS the operation was completed with
    UINT32 SiteOffset;              // see above; 0 = unknown
    UINT32 ProcessId;               // requestor process
    UINT32 ThreadId;
    UINT32 MajorFunction;
    UINT32 MinorFunction;
    UINT32 Irql;
    UINT32 Flags;                   // SAFEUPLOAD_DENY_FLAG_*
    UINT32 Access;                  // create: DesiredAccess; set-information: FILE_INFORMATION_CLASS; fsctl: code;
                                    // section: page protection; write: length
    UINT32 Options;                 // create: (disposition << 24) | options; write: low part of the offset
    UINT32 NameChars;
    UINT32 AuxStatus;               // NTSTATUS of the failed lookup that made the refusal fall back to "the whole volume"; 0 = none
    WCHAR Name[SAFEUPLOAD_DENY_NAME_CHARS];
} SAFEUPLOAD_DENY_RECORD, *PSAFEUPLOAD_DENY_RECORD;

typedef struct _SAFEUPLOAD_DENY_RING_REQUEST {
    SAFEUPLOAD_CONTROL Control;
    UINT64 AfterSequence;           // return records with Sequence > AfterSequence
} SAFEUPLOAD_DENY_RING_REQUEST, *PSAFEUPLOAD_DENY_RING_REQUEST;

typedef struct _SAFEUPLOAD_DENY_RING_BATCH {
    UINT32 StructSize;
    UINT32 ProtocolVersion;
    UINT32 Count;                   // valid entries
    UINT32 Flags;                   // SAFEUPLOAD_DENY_BATCH_FLAG_*
    UINT64 NextSequence;            // Sequence the next record will get; equal to AfterSequence + 1 when caught up
    UINT64 ImageBase;               // SiteOffset is relative to this
    SAFEUPLOAD_DENY_RECORD Entries[SAFEUPLOAD_DENY_BATCH_ENTRIES];
} SAFEUPLOAD_DENY_RING_BATCH, *PSAFEUPLOAD_DENY_RING_BATCH;

/* Counters that existed nowhere else: how often the choke point saw a refusal, and how often a code path that could
 * not resolve a name answered "the whole volume may be in scope" (the suspected cause of refusals outside every
 * scope). All values are monotonic since driver load. */
typedef struct _SAFEUPLOAD_DIAG_COUNTERS {
    UINT32 StructSize;
    UINT32 ProtocolVersion;
    UINT64 DenyRecorded;            // refusals written to the ring
    UINT64 DenyAccessDenied;
    UINT64 DenyRetry;
    UINT64 DenyOtherStatus;
    UINT64 DenyBenignIgnored;       // error completions that are normal results (end of file, no more files)
    UINT64 DenyNotRecorded;         // refusals seen at an IRQL the ring cannot be used at
    UINT64 VolumeWideQueries;       // SafeUploadPolicyMayMatchInstanceVolume calls
    UINT64 VolumeWideAnswers;       // ... of which answered TRUE
    UINT64 NextDenySequence;
    UINT64 ImageBase;
    UINT64 ReclaimPasses;           // reclaim worker passes since load
    UINT64 ReclaimParkedPasses;     // passes that ended with a scan or alias probe waiting on an outside event
    UINT64 ReclaimMoreWorkRequeues; // passes that requeued themselves because bounded work remained
    UINT64 ReclaimWakeupsSkipped;   // close/cleanup events that did not queue a pass (nothing waiting on that stream)
} SAFEUPLOAD_DIAG_COUNTERS, *PSAFEUPLOAD_DIAG_COUNTERS;
C_ASSERT(sizeof(SAFEUPLOAD_DENY_RECORD) == 192);
C_ASSERT(sizeof(SAFEUPLOAD_DENY_RING_REQUEST) == 24);
C_ASSERT(sizeof(SAFEUPLOAD_DENY_RING_BATCH) == 32 + 16 * 192);
C_ASSERT(FIELD_OFFSET(SAFEUPLOAD_DENY_RING_BATCH, Entries) == 32);
C_ASSERT(sizeof(SAFEUPLOAD_DIAG_COUNTERS) == 120);
#endif

/* A probe entry's AdmissionRecordState carries H(F) of the probed stream; this bit marks a lower bound. */
#define SAFEUPLOAD_WRITERS_UNTRACKED_BIT ((UINT32)0x80000000)
#define SAFEUPLOAD_UNLOAD_VETO_NONE ((UINT32)0)
#define SAFEUPLOAD_UNLOAD_VETO_CLIENT ((UINT32)1)
#define SAFEUPLOAD_UNLOAD_VETO_FENCE ((UINT32)2)
#define SAFEUPLOAD_UNLOAD_VETO_STAGE_DRAIN ((UINT32)3)
#define SAFEUPLOAD_UNLOAD_VETO_STAGE_OBJECTS ((UINT32)4)
#define SAFEUPLOAD_UNLOAD_VETO_FENCE_COMMIT ((UINT32)5)
/* A probe entry's SetupFlags carries C(F); unknown identity or pairing overflow sets this bit. */
#define SAFEUPLOAD_SECTIONS_UNTRACKED_BIT ((UINT32)0x80000000)

// A zero cursor and snapshot request a snapshot of all entries retained now.
// Later requests pass the returned NextCursor and SnapshotSequence.
typedef struct _SAFEUPLOAD_ADMISSION_TRACE_REQUEST {
    SAFEUPLOAD_CONTROL Control;
    UINT64 Cursor;
    UINT64 SnapshotSequence;
} SAFEUPLOAD_ADMISSION_TRACE_REQUEST, *PSAFEUPLOAD_ADMISSION_TRACE_REQUEST;

// Fixed-width values keep this trace message stable across x86/x64 clients.
// Pointer values are opaque integers and are never dereferenced by user mode.
typedef struct _SAFEUPLOAD_ADMISSION_TRACE_ENTRY {
    UINT64 Sequence;
    UINT64 Timestamp;
    UINT64 Instance;
    UINT64 TargetFileObject;
    UINT64 SectionObjectPointer;
    UINT32 EventKind;
    UINT32 ProcessId;
    UINT32 Irql;
    UINT32 MajorFunction;
    UINT32 MinorFunction;
    UINT32 IrpFlags;
    UINT32 MmDoesResult;
    UINT32 StreamContextState;
    UINT32 OwnedStream;
    UINT32 AdmissionRecordState;
    UINT32 SetupFlags;
    UINT32 VolumeKind;
    UINT32 AttachClass;
    UINT32 SyncType;
    UINT32 PageProtection;
    UINT32 SyncParametersValid;
    UINT32 ProbeStage;
    UINT32 ProbeStatus;
    UINT32 CanaryState;
    UINT32 CanaryStatus;
    UINT32 CanaryChecks;
    UINT32 CanaryCleanupStatus;
    UINT64 TicketSequence;          // W_BEGIN/W_END pair; zero for unrelated events
    UINT64 CallbackData;            // opaque PFLT_CALLBACK_DATA identity for pairing with lower fixture
    UINT64 VolumeSerialNumber;
    UINT8 FileId[16];               // all zero when no exact registry identity was bound
    UINT64 IoInformation;
    UINT32 H;
    UINT32 W;
    UINT32 RegistryState;
    UINT32 ActivationGeneration;   // independent aligned interlocked sample; not tuple-coherent with state/counts
    UINT32 PolicyGeneration;
    UINT32 IoStatus;
    UINT32 OperationCode;           // FSCTL code or FILE_INFORMATION_CLASS when applicable
    UINT32 CompletionFlags;         // bit0 post captured, bit1 draining, bit2 pre-lower retirement
    UINT32 RegistryUnknownReasons;
    UINT32 RegistrySnapshotFlags;   // StateLock held while sampling H/W/state; only W mutation is serialized; no whole-tuple seqlock
    UINT64 WriteOffset;
    UINT32 WriteLength;
    UINT32 ReservedWrite;
} SAFEUPLOAD_ADMISSION_TRACE_ENTRY, *PSAFEUPLOAD_ADMISSION_TRACE_ENTRY;

/* Feature-only receipt emitted after a successful ACTIVATING -> PROTECTED CAS.
 * PredicateFlags lists explicit basis facts, not the entire Free(F) predicate.
 * This separate schema preserves the existing 232-byte W-ticket event ABI. */
#define SAFEUPLOAD_PROMOTION_TEST_DISABLE_TAINT_UNAVAILABLE ((UINT32)0xffffffff)
#define SAFEUPLOAD_PROMOTION_BASIS_NAME_MATCH       ((UINT32)0x00000001)
#define SAFEUPLOAD_PROMOTION_BASIS_SOP_EMPTY        ((UINT32)0x00000002)
#define SAFEUPLOAD_PROMOTION_BASIS_NO_USER_WRITABLE  ((UINT32)0x00000004)
#define SAFEUPLOAD_PROMOTION_BASIS_MARKER_SCAN_CLEAR ((UINT32)0x00000008)
#define SAFEUPLOAD_PROMOTION_BASIS_CACHE_FLUSH_PURGE ((UINT32)0x00000010)
/* The recorded base-stream incarnation was replaced (same serial and file ID, new SOP); S and the cache barrier
 * were evaluated on the live stream, and neither this entry nor any other incarnation entry of the same data
 * stream held writer state. Named streams of the file are not part of this proof; their own rows gate them. */
#define SAFEUPLOAD_PROMOTION_BASIS_INCARNATION_REPLACED ((UINT32)0x00000020)
#define SAFEUPLOAD_PROMOTION_SNAPSHOT_NONCOHERENT     ((UINT32)0x00000001)
typedef struct _SAFEUPLOAD_PROMOTION_TRACE_REQUEST {
    SAFEUPLOAD_CONTROL Control;
    UINT64 Cursor;
    UINT64 SnapshotSequence;
} SAFEUPLOAD_PROMOTION_TRACE_REQUEST, *PSAFEUPLOAD_PROMOTION_TRACE_REQUEST;

typedef struct _SAFEUPLOAD_PROMOTION_TRACE_ENTRY {
    UINT64 Sequence;
    UINT64 Qpc;
    UINT64 Instance;
    UINT64 SectionObjectPointer;
    UINT64 VolumeSerialNumber;
    UINT64 RegistryChangeSequence; /* independent post-CAS sample, not an exclusive CAS sequence */
    UINT64 SopMarkerGenerationExpected;
    UINT64 SopMarkerGenerationAtCas;
    UINT8 FileId[16];
    UINT32 StateBefore;
    UINT32 StateAfter;
    UINT32 H;
    UINT32 W;
    UINT32 T;
    UINT32 CForSop;
    UINT32 LastS;
    UINT32 UnknownReasons;
    UINT32 RenameInFlight;
    UINT32 RenameVersion;
    UINT32 ActivationGeneration;
    UINT32 PolicyGeneration;
    UINT32 CurrentPolicyFlags;
    UINT32 TestDisableTaintState;
    UINT32 SpilledMutatingIoCount;
    UINT32 UnknownWriterCount;
    UINT32 PredicateFlags;
    UINT32 SnapshotFlags; /* CAS/state edge is exact; all other state/count/generation fields are samples. */
} SAFEUPLOAD_PROMOTION_TRACE_ENTRY, *PSAFEUPLOAD_PROMOTION_TRACE_ENTRY;

typedef struct _SAFEUPLOAD_PROMOTION_TRACE_BATCH {
    UINT32 Version;
    UINT32 StructSize;
    UINT32 EntryCount;
    UINT32 Flags;
    UINT64 Cursor;
    UINT64 SnapshotSequence;
    UINT64 NextCursor;
    UINT64 FirstAvailableSequence;
    UINT64 LostEvents;
    UINT64 OverwrittenEvents;
    SAFEUPLOAD_PROMOTION_TRACE_ENTRY Entries[SAFEUPLOAD_PROMOTION_TRACE_BATCH_ENTRIES];
} SAFEUPLOAD_PROMOTION_TRACE_BATCH, *PSAFEUPLOAD_PROMOTION_TRACE_BATCH;
#define SAFEUPLOAD_PROMOTION_TRACE_BATCH_FLAG_GAP ((UINT32)0x00000001)
C_ASSERT(sizeof(SAFEUPLOAD_PROMOTION_TRACE_REQUEST) == 32);
C_ASSERT(sizeof(SAFEUPLOAD_PROMOTION_TRACE_ENTRY) == 152);
C_ASSERT(sizeof(SAFEUPLOAD_PROMOTION_TRACE_BATCH) <= sizeof(SAFEUPLOAD_POLICY_MESSAGE));

typedef struct _SAFEUPLOAD_ADMISSION_TRACE_COUNTERS {
    UINT64 TotalEvents;
    UINT64 PagingWrites;
    UINT64 NonPagingWrites;
    UINT64 SectionAcquires;
    UINT64 SectionReleases;
    UINT64 InstanceSetups;
    UINT64 LostEntries;
} SAFEUPLOAD_ADMISSION_TRACE_COUNTERS, *PSAFEUPLOAD_ADMISSION_TRACE_COUNTERS;

typedef struct _SAFEUPLOAD_ADMISSION_TRACE_BATCH {
    SAFEUPLOAD_CONTROL Control;
    UINT32 EntryCount;
    UINT32 Reserved;
    UINT64 Cursor;
    UINT64 NextCursor;
    UINT64 SnapshotSequence;
    SAFEUPLOAD_ADMISSION_TRACE_COUNTERS Counters;
    SAFEUPLOAD_ADMISSION_TRACE_ENTRY Entries[SAFEUPLOAD_ADMISSION_TRACE_BATCH_ENTRIES];
} SAFEUPLOAD_ADMISSION_TRACE_BATCH, *PSAFEUPLOAD_ADMISSION_TRACE_BATCH;
#endif

//
//  Counters, read with SAFEUPLOAD_CONTROL_GET_COUNTERS.
//
//  These exist to answer "is the design working?" without a kernel
//  debugger. The whole point of the layered gates is that almost nothing
//  reaches user mode, and until these numbers can be read there is no way
//  to tell whether that is true - only whether the machine feels slow,
//  which is a terrible instrument.
//
//  They are cumulative since the driver loaded, and they never reset: a
//  reader that wants a rate takes two samples and subtracts.
//

typedef struct _SAFEUPLOAD_COUNTERS {

    UINT32 Version;
    UINT32 StructSize;

    //
    //  Every create the filter was called for.
    //

    UINT64 CreatesSeen;

    //
    //  Those that survived the cheap gates - data access requested, process
    //  not excluded, extension monitored. The ratio to CreatesSeen is the
    //  single most useful number here: it should be well under one percent.
    //

    UINT64 CreatesPastCheapGates;

    //
    //  Times a name had to be resolved to decide scope. Expensive, and the
    //  stream context exists to keep this from repeating per file.
    //

    UINT64 ScopeEvaluations;

    //
    //  Times the driver actually asked user mode. The target is one per
    //  file version, so this should sit far below ScopeEvaluations over
    //  time.
    //

    UINT64 UserModeRoundTrips;

    //
    //  Times a cached answer served instead. CacheHits against
    //  CacheHits + ScopeEvaluations is the hit rate.
    //

    UINT64 CacheHits;

    //
    //  Refused in pre-create, on process taint, with no round trip and no
    //  side effect. This is the strong refusal.
    //

    UINT64 DeniedPreCreate;

    //
    //  Refused in post-create with FltCancelFileOpen. Weaker: the create
    //  already happened.
    //

    UINT64 DeniedPostCreate;

    //
    //  Refused in pre-set-information: a rename or hard link by a tainted
    //  process whose destination is monitored. Counted apart from the
    //  create refusal because the two answer different questions - one is
    //  the file being written, the other is the file being moved into
    //  place around the write. Folding them together hides which link of
    //  the chain is actually holding.
    //

    UINT64 DeniedRename;

    //
    //  RN-013 in numbers: operations allowed because inspection could not
    //  happen - timeout, port closed, no memory, malformed reply. A number
    //  that grows here is a user working uninspected.
    //

    UINT64 AllowedWithoutInspection;

    //
    //  Taint table activity. TaintHits against TaintLookups says how often
    //  the table actually stops something, which is what decides whether
    //  the false positive cost is worth paying.
    //

    UINT64 TaintsRecorded;
    UINT64 TaintLookups;
    UINT64 TaintHits;

    //
    //  How far a rename or hard link got down the pre-set-information
    //  path. These exist to localise a refusal that does not happen: the
    //  callback can give up at three different points, and without these
    //  a DeniedRename of zero says only "somewhere before the end".
    //
    //  SetInformationSeen counts every entry into the callback, before any
    //  gate at all. It separates "the callback does not run" from "the
    //  callback runs and no rename ever arrives", which are different
    //  problems in different files and cannot be told apart otherwise.
    //
    //  RenamesSeen counts what got past the information-class gate - if
    //  this is zero while SetInformationSeen is not, no rename ever
    //  reached the callback and the question is not about this code.
    //
    //  RenamesFromTainted counts what got past the taint check, which is
    //  the last gate before the destination name is resolved.
    //

    UINT64 SetInformationSeen;
    UINT64 RenamesSeen;
    UINT64 RenamesFromTainted;

    //
    //  The same two stages for hard links, counted apart from renames.
    //
    //  They were folded together, and that made one question
    //  unanswerable: a class bitmap is global and cumulative, so seeing
    //  FileLinkInformation in it proves only that SOMETHING on the
    //  machine created a link - not that the link under test reached this
    //  callback. With the counts split, LinksSeen answers it directly.
    //

    UINT64 LinksSeen;
    UINT64 LinksFromTainted;

    //
    //  Operacoes que teriam sido negadas se o modo auditoria estivesse
    //  desligado. Em modo bloqueio fica em zero, porque ai elas sao
    //  negadas de fato e contadas nos Denied*.
    //

    UINT64 WouldHaveDenied;

    //
    //  Excecoes concedidas pelo modo usuario e efetivamente usadas. As duas
    //  juntas dizem se o bloqueio com justificativa e usado de verdade ou se
    //  o usuario apenas desiste da operacao - que e informacao de produto, e
    //  nao de depuracao.
    //

    UINT64 OverridesGranted;
    UINT64 OverridesUsed;

    //
    //  Bitmap of every FILE_INFORMATION_CLASS that reached the callback:
    //  bit N of Low for class N, bit N of High for class N + 64.
    //
    //  This exists to end a specific kind of round trip. Twice now an
    //  operation was refused while the counter for its refusal stayed at
    //  zero, and answering "which class actually arrived" cost a full
    //  build, deploy and test cycle each time. The bitmap answers it for
    //  every class at once, so the next surprise is read rather than
    //  guessed.
    //
    //  The classes that matter here: 10 FileRenameInformation, 11
    //  FileLinkInformation, 65 FileRenameInformationEx, 72
    //  FileLinkInformationEx.
    //

    UINT64 ClassesSeenLow;
    UINT64 ClassesSeenHigh;

} SAFEUPLOAD_COUNTERS, *PSAFEUPLOAD_COUNTERS;

#pragma pack(pop)

//
//  Layout guarantees. If a field is added, reordered or resized without
//  keeping the structures free of implicit padding, the build breaks here
//  rather than at runtime on the other side of the boundary.
//

C_ASSERT( sizeof( SAFEUPLOAD_REQUEST ) == 1192 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_REQUEST, Version )            == 0 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_REQUEST, StructSize )         == 4 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_REQUEST, RequestId )          == 8 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_REQUEST, Operation )          == 16 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_REQUEST, RequestorProcessId ) == 20 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_REQUEST, Flags )              == 24 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_REQUEST, PathLength )         == 28 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_REQUEST, ImageNameLength )    == 32 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_REQUEST, Reserved )           == 36 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_REQUEST, Path )               == 40 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_REQUEST, ImageName )          == 1064 );

C_ASSERT( sizeof( SAFEUPLOAD_RESPONSE ) == 152 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_RESPONSE, Version )    == 0 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_RESPONSE, StructSize ) == 4 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_RESPONSE, RequestId )  == 8 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_RESPONSE, Verdict )    == 16 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_RESPONSE, StageNameLength ) == 20 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_RESPONSE, StageName ) == 24 );

C_ASSERT( sizeof( SAFEUPLOAD_PUBLICATION_MESSAGE ) == 2128 );
C_ASSERT( sizeof( SAFEUPLOAD_CONTROL ) == 16 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_CONTROL, Version )    == 0 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_CONTROL, StructSize ) == 4 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_CONTROL, Command )    == 8 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_CONTROL, Reserved )   == 12 );

C_ASSERT( sizeof( SAFEUPLOAD_POLICY_MESSAGE ) == 19752 );
C_ASSERT( sizeof( SAFEUPLOAD_BOOT_POLICY ) == 16656 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_BOOT_POLICY, Prefixes ) == 16 );
C_ASSERT( sizeof( SAFEUPLOAD_OVERRIDE_MESSAGE ) == 1056 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_OVERRIDE_MESSAGE, ProcessId ) == 16 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_OVERRIDE_MESSAGE, Path )      == 32 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_POLICY_MESSAGE, Control )           == 0 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_POLICY_MESSAGE, ExtensionCount )    == 16 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_POLICY_MESSAGE, PrefixCount )       == 20 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_POLICY_MESSAGE, ImageCount )        == 24 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_POLICY_MESSAGE, SourcePrefixCount ) == 28 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_POLICY_MESSAGE, Flags )             == 32 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_POLICY_MESSAGE, VerdictTimeoutMs )  == 36 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_POLICY_MESSAGE, Extensions )        == 40 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_POLICY_MESSAGE, Prefixes )          == 1064 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_POLICY_MESSAGE, SourcePrefixes )    == 9384 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_POLICY_MESSAGE, Images )            == 17704 );

C_ASSERT( sizeof( SAFEUPLOAD_COUNTERS ) == 184 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_COUNTERS, Version )     == 0 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_COUNTERS, StructSize )  == 4 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_COUNTERS, CreatesSeen ) == 8 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_COUNTERS, TaintHits )   == 96 );

#if defined(SAFEUPLOAD_STAGING_PROTOTYPE) && SAFEUPLOAD_STAGING_PROTOTYPE
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_ADMISSION_PROBE_REQUEST, VolumeNameChars ) == 16 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_ADMISSION_PROBE_REQUEST, RelativePathChars ) == 18 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_ADMISSION_PROBE_REQUEST, Reserved ) == 20 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_ADMISSION_PROBE_REQUEST, Strings ) == 24 );
C_ASSERT( sizeof( SAFEUPLOAD_ADMISSION_PROBE_REQUEST ) == 28 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_ADMISSION_DELETE_STREAM_CONTEXT_REQUEST, VolumeNameChars ) == 16 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_ADMISSION_DELETE_STREAM_CONTEXT_REQUEST, DriveLetter ) == 24 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_ADMISSION_DELETE_STREAM_CONTEXT_REQUEST, Strings ) == 28 );
C_ASSERT( sizeof( SAFEUPLOAD_ADMISSION_DELETE_STREAM_CONTEXT_REQUEST ) == 32 ); /* 30 bytes padded to 4-byte alignment */
C_ASSERT( sizeof( SAFEUPLOAD_ADMISSION_CANARY_HOLD_REQUEST ) == 152 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_ADMISSION_CANARY_HOLD_REQUEST, VolumeName ) == 24 );
C_ASSERT( sizeof( SAFEUPLOAD_ADMISSION_CANARY_HOLD_REPLY ) == 1040 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_ADMISSION_CANARY_HOLD_REPLY, CanaryPath ) == 16 );
C_ASSERT( sizeof( SAFEUPLOAD_ADMISSION_TRACE_REQUEST ) == 32 );
C_ASSERT( sizeof( SAFEUPLOAD_ADMISSION_TRACE_ENTRY ) == 232 );
C_ASSERT( sizeof( SAFEUPLOAD_ADMISSION_TRACE_COUNTERS ) == 56 );
C_ASSERT( sizeof( SAFEUPLOAD_ADMISSION_TRACE_BATCH ) == 1960 );
#if defined(SAFEUPLOAD_STAGING_PROTOTYPE) && SAFEUPLOAD_STAGING_PROTOTYPE
C_ASSERT( sizeof( SAFEUPLOAD_ADMISSION_VOLUME_ENTRY ) == 208 );
#else
C_ASSERT( sizeof( SAFEUPLOAD_ADMISSION_VOLUME_ENTRY ) == 192 );
#endif
#if defined(SAFEUPLOAD_STAGING_PROTOTYPE) && SAFEUPLOAD_STAGING_PROTOTYPE
C_ASSERT( sizeof( SAFEUPLOAD_ADMISSION_VOLUME_STATUS ) == 6672 );
#else
C_ASSERT( sizeof( SAFEUPLOAD_ADMISSION_VOLUME_STATUS ) == 6160 );
#endif
C_ASSERT( sizeof( SAFEUPLOAD_POLICY_MESSAGE ) >= sizeof( SAFEUPLOAD_ADMISSION_VOLUME_STATUS ) );
C_ASSERT( sizeof( SAFEUPLOAD_POLICY_MESSAGE ) >= sizeof( SAFEUPLOAD_ADMISSION_CANARY_HOLD_REPLY ) );
C_ASSERT( sizeof( SAFEUPLOAD_POLICY_MESSAGE ) >= sizeof( SAFEUPLOAD_ADMISSION_CANARY_HOLD_REQUEST ) );
C_ASSERT( sizeof( SAFEUPLOAD_POLICY_MESSAGE ) >= sizeof( SAFEUPLOAD_ADMISSION_TRACE_BATCH ) );
C_ASSERT( sizeof( SAFEUPLOAD_FENCE_STATUS ) == 144 );
C_ASSERT( (ULONG)FIELD_OFFSET( SAFEUPLOAD_WRITER_STATE_STATUS, RetiredSectionOverflow ) == 72 );
C_ASSERT( (ULONG)FIELD_OFFSET( SAFEUPLOAD_WRITER_STATE_STATUS, CleanupDirectoriesSkipped ) == 100 );
C_ASSERT( (ULONG)FIELD_OFFSET( SAFEUPLOAD_WRITER_STATE_STATUS, TxfRefused ) == 168 );
C_ASSERT( (ULONG)FIELD_OFFSET( SAFEUPLOAD_WRITER_STATE_STATUS, RegistryPruned ) == 264 );
C_ASSERT( (ULONG)FIELD_OFFSET( SAFEUPLOAD_WRITER_STATE_STATUS, RegistryNameTierEntries ) == 280 );
C_ASSERT( (ULONG)FIELD_OFFSET( SAFEUPLOAD_WRITER_STATE_STATUS, RegistryCompactTierEntries ) == 284 );
C_ASSERT( sizeof( SAFEUPLOAD_WRITER_STATE_STATUS ) == 288 );
C_ASSERT( (ULONG)FIELD_OFFSET( SAFEUPLOAD_REGISTRY_ENTRY_STATUS, VolumeSerialNumber ) == 40 );
C_ASSERT( (ULONG)FIELD_OFFSET( SAFEUPLOAD_REGISTRY_ENTRY_STATUS, FileId ) == 48 );
C_ASSERT( (ULONG)FIELD_OFFSET( SAFEUPLOAD_REGISTRY_ENTRY_STATUS, NameMatches ) == 100 );
C_ASSERT( sizeof( SAFEUPLOAD_REGISTRY_ENTRY_STATUS ) == 104 );
C_ASSERT( (ULONG)FIELD_OFFSET( SAFEUPLOAD_WRITER_STATE_STATUS, InstanceTeardownsDismount ) == 152 );
C_ASSERT( (ULONG)FIELD_OFFSET( SAFEUPLOAD_WRITER_STATE_STATUS, InstanceTeardownsOther ) == 160 );
C_ASSERT( (ULONG)FIELD_OFFSET( SAFEUPLOAD_WRITER_STATE_STATUS, WritersDroppedAtTeardown ) == 136 );
C_ASSERT( (ULONG)FIELD_OFFSET( SAFEUPLOAD_WRITER_STATE_STATUS, WritersDroppedWhileMounted ) == 144 );
C_ASSERT( sizeof( SAFEUPLOAD_POLICY_MESSAGE ) >=
          FIELD_OFFSET( SAFEUPLOAD_ADMISSION_PROBE_REQUEST, Strings ) +
          (2 * SAFEUPLOAD_ADMISSION_PROBE_MAX_STRING_CHARS * sizeof( WCHAR )) );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_ADMISSION_TRACE_ENTRY, EventKind ) == 40 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_ADMISSION_TRACE_ENTRY, ProbeStage ) == 104 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_ADMISSION_TRACE_ENTRY, ProbeStatus ) == 108 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_ADMISSION_TRACE_ENTRY, TicketSequence ) == 128 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_ADMISSION_TRACE_ENTRY, CallbackData ) == 136 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_ADMISSION_TRACE_ENTRY, VolumeSerialNumber ) == 144 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_ADMISSION_TRACE_ENTRY, FileId ) == 152 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_ADMISSION_TRACE_ENTRY, IoInformation ) == 168 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_ADMISSION_TRACE_ENTRY, RegistryUnknownReasons ) == 208 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_ADMISSION_TRACE_ENTRY, RegistrySnapshotFlags ) == 212 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_ADMISSION_TRACE_ENTRY, WriteOffset ) == 216 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_ADMISSION_TRACE_ENTRY, WriteLength ) == 224 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_ADMISSION_TRACE_BATCH, Entries ) == 104 );
C_ASSERT( sizeof( SAFEUPLOAD_ACTIVATING_ENTRY_STATUS ) == 1128 );
C_ASSERT( sizeof( SAFEUPLOAD_ACTIVATING_STATUS_PAGE ) == 36136 );
C_ASSERT( sizeof( SAFEUPLOAD_ACTIVATING_DIAGNOSTIC_ENTRY_STATUS ) == 1136 );
C_ASSERT( sizeof( SAFEUPLOAD_ACTIVATING_DIAGNOSTIC_STATUS_PAGE ) == 36392 );
#endif

#endif // _SAFEUPLOAD_PROTOCOL_H_
