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
#define SAFEUPLOAD_ADMISSION_TRACE_RING_ENTRIES         ((UINT32) 16384) /* power of two; feature build only */
#define SAFEUPLOAD_ADMISSION_TRACE_BATCH_ENTRIES        ((UINT32) 8)
#define SAFEUPLOAD_ADMISSION_PROBE_MAX_STRING_CHARS     ((UINT16) 260)

#define SAFEUPLOAD_ADMISSION_TRACE_EVENT_PAGING_WRITE   ((UINT32) 1)
#define SAFEUPLOAD_ADMISSION_TRACE_EVENT_SECTION_ACQUIRE ((UINT32) 2)
#define SAFEUPLOAD_ADMISSION_TRACE_EVENT_SECTION_RELEASE ((UINT32) 3)
#define SAFEUPLOAD_ADMISSION_TRACE_EVENT_INSTANCE_SETUP ((UINT32) 4)
#define SAFEUPLOAD_ADMISSION_TRACE_EVENT_EXPLICIT_PROBE ((UINT32) 5)
#define SAFEUPLOAD_ADMISSION_TRACE_EVENT_UNOWNED_NONPAGING_WRITE ((UINT32) 6)
#define SAFEUPLOAD_ADMISSION_TRACE_EVENT_FILE_CLEANUP   ((UINT32) 7)
#define SAFEUPLOAD_ADMISSION_TRACE_EVENT_FILE_CLOSE     ((UINT32) 8)

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

// Classify supported file reads anywhere, without a configured source path.
#define SAFEUPLOAD_POLICY_FLAG_CLASSIFY_ALL_SOURCES ((UINT32) 0x00000010)

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
// Variable tail: volume name followed by relative path, with no terminators.
// Control.StructSize is the exact byte count for the declared character counts.
typedef struct _SAFEUPLOAD_ADMISSION_PROBE_REQUEST {
    SAFEUPLOAD_CONTROL Control;
    UINT16 VolumeNameChars;
    UINT16 RelativePathChars;
    UINT32 Reserved;
    WCHAR Strings[1];
} SAFEUPLOAD_ADMISSION_PROBE_REQUEST, *PSAFEUPLOAD_ADMISSION_PROBE_REQUEST;

/*
 *  Mapped-writable stream fence. A scan of the protected scopes registers streams that
 *  have user-writable mapped views; their unowned paging writes are refused and
 *  protected opens of their names are refused. STATUS reads this; REFRESH reruns the scan.
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
    UINT64 PagingWritesDenied;
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
} SAFEUPLOAD_ADMISSION_TRACE_ENTRY, *PSAFEUPLOAD_ADMISSION_TRACE_ENTRY;

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
C_ASSERT( sizeof( SAFEUPLOAD_ADMISSION_TRACE_REQUEST ) == 32 );
C_ASSERT( sizeof( SAFEUPLOAD_ADMISSION_TRACE_ENTRY ) == 112 );
C_ASSERT( sizeof( SAFEUPLOAD_ADMISSION_TRACE_COUNTERS ) == 56 );
C_ASSERT( sizeof( SAFEUPLOAD_ADMISSION_TRACE_BATCH ) == 1000 );
C_ASSERT( sizeof( SAFEUPLOAD_POLICY_MESSAGE ) >= sizeof( SAFEUPLOAD_ADMISSION_TRACE_BATCH ) );
C_ASSERT( sizeof( SAFEUPLOAD_FENCE_STATUS ) == 144 );
C_ASSERT( sizeof( SAFEUPLOAD_POLICY_MESSAGE ) >=
          FIELD_OFFSET( SAFEUPLOAD_ADMISSION_PROBE_REQUEST, Strings ) +
          (2 * SAFEUPLOAD_ADMISSION_PROBE_MAX_STRING_CHARS * sizeof( WCHAR )) );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_ADMISSION_TRACE_ENTRY, EventKind ) == 40 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_ADMISSION_TRACE_ENTRY, ProbeStage ) == 104 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_ADMISSION_TRACE_ENTRY, ProbeStatus ) == 108 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_ADMISSION_TRACE_BATCH, Entries ) == 104 );
#endif

#endif // _SAFEUPLOAD_PROTOCOL_H_
