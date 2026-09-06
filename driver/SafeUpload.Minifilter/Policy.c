/*++

Module Name:

    Policy.c

Abstract:

    The scope policy, as pushed down from user mode over the communication
    port.

    Two properties matter here, and they pull in opposite directions:

    - Reads are on the hot path. Every create that survives the cheap gates
      consults the policy, thousands of times a second.

    - Writes are rare. The policy changes when the agent loads it and when
      an operator edits it.

    So the policy is an immutable snapshot behind a push lock: readers take
    it shared and never allocate, and a write builds an entirely new
    snapshot before swapping it in. Nothing is ever modified in place, which
    is what makes a reader safe without copying anything.

    Path prefixes arrive already in NT form. Converting DOS paths to NT form
    is user mode's job, done once when the policy is loaded - doing it here
    would mean converting on every operation, which is precisely the cost
    this design exists to avoid.

Environment:

    Kernel mode

--*/

#include "Filter.h"

//
//  Guards SafeUploadPolicy. Shared for readers, exclusive for the swap.
//

static EX_PUSH_LOCK SafeUploadPolicyLock;

//
//  The current snapshot, or NULL when user mode has not pushed one yet.
//  NULL means nothing is in scope, which is the correct reading: without a
//  policy there is no monitored destination and no monitored extension.
//

static PSAFEUPLOAD_POLICY SafeUploadPolicy = NULL;

static
VOID
SafeUploadBuildStringTable (
    _In_ PCWCH Storage,
    _In_ UINT32 EntryCount,
    _In_ UINT32 EntryChars,
    _Out_writes_(EntryCount) PUNICODE_STRING Table
    );

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(PAGE, SafeUploadInitializePolicy)
    #pragma alloc_text(PAGE, SafeUploadFreePolicy)
    #pragma alloc_text(PAGE, SafeUploadSetPolicy)
    #pragma alloc_text(PAGE, SafeUploadBuildStringTable)
#endif


VOID
SafeUploadInitializePolicy (
    VOID
    )
/*++

Routine Description:

    Prepares the policy lock. Called from DriverEntry before the port
    exists, because the first thing a client does is push a policy.

    IRQL: PASSIVE_LEVEL.

--*/
{
    PAGED_CODE();

    FltInitializePushLock( &SafeUploadPolicyLock );
    SafeUploadPolicy = NULL;
}


VOID
SafeUploadFreePolicy (
    VOID
    )
/*++

Routine Description:

    Releases the current snapshot and the lock. Called from the unload path,
    after the channel has been drained, so no reader can be in flight.

    IRQL: PASSIVE_LEVEL.

--*/
{
    PSAFEUPLOAD_POLICY previous;

    PAGED_CODE();

    FltAcquirePushLockExclusive( &SafeUploadPolicyLock );

    previous = SafeUploadPolicy;
    SafeUploadPolicy = NULL;

    FltReleasePushLock( &SafeUploadPolicyLock );

    if (previous != NULL) {

        ExFreePoolWithTag( previous, SAFEUPLOAD_POOL_TAG );
    }

    FltDeletePushLock( &SafeUploadPolicyLock );
}


static
VOID
SafeUploadBuildStringTable (
    _In_ PCWCH Storage,
    _In_ UINT32 EntryCount,
    _In_ UINT32 EntryChars,
    _Out_writes_(EntryCount) PUNICODE_STRING Table
    )
/*++

Routine Description:

    Points a table of UNICODE_STRINGs at the fixed-width character storage
    that came down in the message, measuring each entry once.

    Measuring here rather than at match time is the whole point: a prefix
    can be 260 characters, and running wcslen over it on every create would
    put a string walk in the hot path for nothing.

    IRQL: PASSIVE_LEVEL.

Arguments:

    Storage - Start of the fixed-width array in the snapshot.

    EntryCount - How many entries are populated.

    EntryChars - Width of each entry, in WCHARs, terminator included.

    Table - Receives one UNICODE_STRING per entry.

--*/
{
    UINT32 index;
    UINT32 length;
    PCWCH entry;

    PAGED_CODE();

    for (index = 0; index < EntryCount; index += 1) {

        entry = Storage + ((SIZE_T) index * EntryChars);

        //
        //  Bounded by the entry width, never by a terminator alone: the
        //  message came from user mode and an unterminated entry must not
        //  walk off the end.
        //

        for (length = 0; length < EntryChars; length += 1) {

            if (entry[length] == L'\0') {

                break;
            }
        }

        Table[index].Buffer = (PWCH) entry;
        Table[index].Length = (USHORT) (length * sizeof( WCHAR ));
        Table[index].MaximumLength = Table[index].Length;
    }
}


NTSTATUS
SafeUploadSetPolicy (
    _In_ CONST SAFEUPLOAD_POLICY_MESSAGE *Message
    )
/*++

Routine Description:

    Validates a policy message and installs it as the current snapshot.

    IRQL: PASSIVE_LEVEL.

Arguments:

    Message - The message, already copied out of user memory by the caller.
        Every count in it is treated as hostile until checked.

Return Value:

    STATUS_SUCCESS, or a failure status leaving the previous policy in
    place. A rejected policy never leaves the driver in a half-updated
    state: the new snapshot is fully built before anything is swapped.

--*/
{
    PSAFEUPLOAD_POLICY snapshot;
    PSAFEUPLOAD_POLICY previous;

    PAGED_CODE();

    //
    //  Bounds first. These counts index fixed arrays, so a value past the
    //  capacity would read beyond the message.
    //

    if (Message->ExtensionCount > SAFEUPLOAD_MAX_EXTENSIONS ||
        Message->PrefixCount > SAFEUPLOAD_MAX_PREFIXES ||
        Message->ImageCount > SAFEUPLOAD_MAX_IMAGES) {

        return STATUS_INVALID_PARAMETER;
    }

    snapshot = (PSAFEUPLOAD_POLICY) ExAllocatePool2( POOL_FLAG_NON_PAGED,
                                                     sizeof( SAFEUPLOAD_POLICY ),
                                                     SAFEUPLOAD_POOL_TAG );

    if (snapshot == NULL) {

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    //  The snapshot owns its own copy of the character data. The tables
    //  built below point into that copy, never into the caller's buffer.
    //

    RtlCopyMemory( &snapshot->Data, Message, sizeof( SAFEUPLOAD_POLICY_MESSAGE ) );

    snapshot->ExtensionCount = Message->ExtensionCount;
    snapshot->PrefixCount = Message->PrefixCount;
    snapshot->ImageCount = Message->ImageCount;
    snapshot->Flags = Message->Flags;

    SafeUploadBuildStringTable( &snapshot->Data.Extensions[0][0],
                                snapshot->ExtensionCount,
                                SAFEUPLOAD_MAX_EXTENSION_CHARS,
                                snapshot->Extensions );

    SafeUploadBuildStringTable( &snapshot->Data.Prefixes[0][0],
                                snapshot->PrefixCount,
                                SAFEUPLOAD_MAX_PREFIX_CHARS,
                                snapshot->Prefixes );

    SafeUploadBuildStringTable( &snapshot->Data.Images[0][0],
                                snapshot->ImageCount,
                                SAFEUPLOAD_MAX_IMAGE_CHARS,
                                snapshot->Images );

    FltAcquirePushLockExclusive( &SafeUploadPolicyLock );

    previous = SafeUploadPolicy;
    SafeUploadPolicy = snapshot;

    FltReleasePushLock( &SafeUploadPolicyLock );

    //
    //  Freed only after the lock is dropped, and only once no reader can
    //  still be holding it: readers take the lock shared, so releasing it
    //  exclusively above means every one of them has finished.
    //

    if (previous != NULL) {

        ExFreePoolWithTag( previous, SAFEUPLOAD_POOL_TAG );
    }

    SafeUploadTrace( "policy set: %u extensoes, %u prefixos, %u imagens, flags 0x%X\n",
                     snapshot->ExtensionCount,
                     snapshot->PrefixCount,
                     snapshot->ImageCount,
                     snapshot->Flags );

    return STATUS_SUCCESS;
}


BOOLEAN
SafeUploadPolicyMatchesExtension (
    _In_ PCUNICODE_STRING FileName
    )
/*++

Routine Description:

    Whether the final component of a name carries a monitored extension.

    Reads the name the caller supplied rather than a resolved one: this runs
    before anything expensive, and its job is to reject, cheaply, the
    overwhelming majority of operations. An inconclusive answer errs towards
    letting the operation reach the slow path, which resolves the real name.

    IRQL: <= APC_LEVEL. Takes a push lock shared and allocates nothing.

Arguments:

    FileName - Name as supplied by the caller. May be empty.

Return Value:

    FALSE when the operation certainly falls outside the monitored
    extensions.

--*/
{
    UNICODE_STRING extension;
    BOOLEAN matched = FALSE;
    UINT32 index;
    USHORT charCount;
    USHORT dotIndex = 0;
    USHORT walk;

    if (FileName == NULL || FileName->Length == 0 || FileName->Buffer == NULL) {

        //
        //  Nothing to judge - an open by file ID, for instance. Let it
        //  reach the slow path.
        //

        return TRUE;
    }

    charCount = (USHORT) (FileName->Length / sizeof( WCHAR ));

    //
    //  Walk back to the last dot of the final component. A separator ends
    //  the search: a dot in a directory name is not an extension.
    //

    for (walk = charCount; walk > 0; walk -= 1) {

        WCHAR current = FileName->Buffer[walk - 1];

        if (current == L'\\' || current == L':') {

            break;
        }

        if (current == L'.') {

            dotIndex = walk - 1;
            break;
        }
    }

    if (dotIndex == 0) {

        return FALSE;
    }

    extension.Buffer = &FileName->Buffer[dotIndex];
    extension.Length = (USHORT) ((charCount - dotIndex) * sizeof( WCHAR ));
    extension.MaximumLength = extension.Length;

    FltAcquirePushLockShared( &SafeUploadPolicyLock );

    if (SafeUploadPolicy != NULL) {

        for (index = 0; index < SafeUploadPolicy->ExtensionCount; index += 1) {

            if (RtlCompareUnicodeString( &extension,
                                         &SafeUploadPolicy->Extensions[index],
                                         TRUE ) == 0) {

                matched = TRUE;
                break;
            }
        }
    }

    FltReleasePushLock( &SafeUploadPolicyLock );

    return matched;
}


BOOLEAN
SafeUploadPolicyMatchesDestination (
    _In_ SAFEUPLOAD_VOLUME_KIND VolumeKind,
    _In_opt_ PCUNICODE_STRING NormalizedPath
    )
/*++

Routine Description:

    Whether an operation is heading somewhere the policy monitors.

    Removable media and network shares qualify by the kind of volume alone -
    every path on them is a destination. A fixed volume qualifies only when
    the path falls under one of the monitored prefixes, which is how cloud
    sync folders enter scope: from the file system's point of view they are
    ordinary local directories.

    IRQL: <= APC_LEVEL. Takes a push lock shared and allocates nothing.

Arguments:

    VolumeKind - Classification recorded in the instance context.

    NormalizedPath - Path in NT form, when one is available. Without it only
        the volume kind can be judged.

Return Value:

    TRUE when the operation is in scope.

--*/
{
    BOOLEAN matched = FALSE;
    UINT32 index;

    FltAcquirePushLockShared( &SafeUploadPolicyLock );

    if (SafeUploadPolicy == NULL) {

        //
        //  No policy means no monitored destination. Nothing is in scope
        //  until user mode says what is.
        //

        FltReleasePushLock( &SafeUploadPolicyLock );
        return FALSE;
    }

    if ((VolumeKind == SafeUploadVolumeRemovable &&
         FlagOn( SafeUploadPolicy->Flags, SAFEUPLOAD_POLICY_FLAG_REMOVABLE )) ||
        (VolumeKind == SafeUploadVolumeNetwork &&
         FlagOn( SafeUploadPolicy->Flags, SAFEUPLOAD_POLICY_FLAG_NETWORK ))) {

        matched = TRUE;
    }

    if (!matched && NormalizedPath != NULL && NormalizedPath->Length != 0) {

        for (index = 0; index < SafeUploadPolicy->PrefixCount; index += 1) {

            if (RtlPrefixUnicodeString( &SafeUploadPolicy->Prefixes[index],
                                        NormalizedPath,
                                        TRUE )) {

                matched = TRUE;
                break;
            }
        }
    }

    FltReleasePushLock( &SafeUploadPolicyLock );

    return matched;
}


BOOLEAN
SafeUploadPolicyExcludesImage (
    _In_ PCUNICODE_STRING ImageName
    )
/*++

Routine Description:

    Whether a process image is on the policy's exclusion list.

    This is the RN-014 list, and it exists for the same reason the driver
    already skips its own client: a process the agent depends on must not
    have its I/O routed through the agent.

    IRQL: <= APC_LEVEL.

Arguments:

    ImageName - Final component of the process image.

Return Value:

    TRUE when the process must never be inspected.

--*/
{
    BOOLEAN matched = FALSE;
    UINT32 index;

    if (ImageName == NULL || ImageName->Length == 0) {

        return FALSE;
    }

    FltAcquirePushLockShared( &SafeUploadPolicyLock );

    if (SafeUploadPolicy != NULL) {

        for (index = 0; index < SafeUploadPolicy->ImageCount; index += 1) {

            if (RtlCompareUnicodeString( ImageName,
                                         &SafeUploadPolicy->Images[index],
                                         TRUE ) == 0) {

                matched = TRUE;
                break;
            }
        }
    }

    FltReleasePushLock( &SafeUploadPolicyLock );

    return matched;
}
