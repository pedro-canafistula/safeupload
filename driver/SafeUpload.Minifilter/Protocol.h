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

    - Every message is a fixed-size structure. No pointers, no variable
      length tails, no heap ownership crossing the boundary.
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
//  reject a message whose Version they do not recognise, and a rejected
//  message means "allow" (RN-013), never "block".
//

#define SAFEUPLOAD_PROTOCOL_VERSION ((UINT32) 1)

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

    UINT32 Reserved;

} SAFEUPLOAD_RESPONSE, *PSAFEUPLOAD_RESPONSE;

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

C_ASSERT( sizeof( SAFEUPLOAD_RESPONSE ) == 24 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_RESPONSE, Version )    == 0 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_RESPONSE, StructSize ) == 4 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_RESPONSE, RequestId )  == 8 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_RESPONSE, Verdict )    == 16 );
C_ASSERT( FIELD_OFFSET( SAFEUPLOAD_RESPONSE, Reserved )   == 20 );

#endif // _SAFEUPLOAD_PROTOCOL_H_
