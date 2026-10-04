/* Bounded, read-only registry bootstrap used by DriverEntry before
 * FltStartFiltering. No file-system I/O, user-mode dependency or worker is
 * involved here. */
#include "Filter.h"

#define SAFEUPLOAD_BOOT_POLICY_REG_BUFFER_BYTES \
    (FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + sizeof(SAFEUPLOAD_BOOT_POLICY))
#define SAFEUPLOAD_BOOT_POLICY_SD_BYTES 1024

typedef enum _SAFEUPLOAD_BOOT_VALUE_RESULT {
    SafeUploadBootValueMissing,
    SafeUploadBootValueValid,
    SafeUploadBootValueCorrupt,
    SafeUploadBootValueUnreadable
} SAFEUPLOAD_BOOT_VALUE_RESULT;

static DECLSPEC_ALIGN(8) UCHAR SafeUploadBootPolicyValueBuffer[SAFEUPLOAD_BOOT_POLICY_REG_BUFFER_BYTES];
static DECLSPEC_ALIGN(8) UCHAR SafeUploadBootPolicySecurityBuffer[SAFEUPLOAD_BOOT_POLICY_SD_BYTES];

static BOOLEAN SafeUploadBootPolicyPrefixValid(_In_reads_(Chars) PCWCH Buffer, _In_ ULONG Chars)
{
    static const WCHAR devicePrefixBuffer[] = L"\\Device\\";
    UNICODE_STRING devicePrefix;
    ULONG index, componentStart;
    BOOLEAN devicePath, uncPath;

    if (Chars == 0 || Chars >= SAFEUPLOAD_MAX_PREFIX_CHARS) return FALSE;
    RtlInitUnicodeString(&devicePrefix, devicePrefixBuffer);
    {
        UNICODE_STRING candidate;
        candidate.Buffer = (PWCH)Buffer;
        candidate.Length = (USHORT)(Chars * sizeof(WCHAR));
        candidate.MaximumLength = candidate.Length;
        devicePath = RtlPrefixUnicodeString(&devicePrefix, &candidate, TRUE);
    }
    uncPath = Chars >= 5 && Buffer[0] == L'\\' && Buffer[1] == L'\\';
    if (!devicePath && !uncPath) return FALSE;
    if (uncPath) {
        ULONG serverEnd = 2;
        while (serverEnd < Chars && Buffer[serverEnd] != L'\\') serverEnd += 1;
        if (serverEnd == Chars || serverEnd + 1 >= Chars || Buffer[serverEnd + 1] == L'\\')
            return FALSE; /* A UNC destination must name both server and share. */
    }

    componentStart = devicePath ? RTL_NUMBER_OF(devicePrefixBuffer) - 1 : 2;
    if (componentStart >= Chars) return FALSE;
    for (index = componentStart; index <= Chars; ++index) {
        if (index == Chars || Buffer[index] == L'\\') {
            ULONG componentLength = index - componentStart;
            if (componentLength == 0) {
                if (index == Chars && Chars != 0 && Buffer[Chars - 1] == L'\\') return TRUE;
                return FALSE;
            }
            if ((componentLength == 1 && Buffer[componentStart] == L'.') ||
                (componentLength == 2 && Buffer[componentStart] == L'.' &&
                 Buffer[componentStart + 1] == L'.')) return FALSE;
            componentStart = index + 1;
        } else if (Buffer[index] == UNICODE_NULL || Buffer[index] == L'/' ||
            Buffer[index] == L':' || Buffer[index] == L'*' || Buffer[index] == L'?') {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOLEAN SafeUploadBootPolicySlotRead(_In_reads_(SAFEUPLOAD_MAX_PREFIX_CHARS) PCWCH Slot,
    _Out_ PULONG Chars)
{
    ULONG index;
    *Chars = 0;
    for (index = 0; index < SAFEUPLOAD_MAX_PREFIX_CHARS; ++index) {
        if (Slot[index] == UNICODE_NULL) break;
    }
    if (index == SAFEUPLOAD_MAX_PREFIX_CHARS || index == 0 ||
        !SafeUploadBootPolicyPrefixValid(Slot, index)) return FALSE;
    for (; index < SAFEUPLOAD_MAX_PREFIX_CHARS; ++index) {
        if (Slot[index] != UNICODE_NULL) return FALSE;
    }
    /* The second scan above checked the tail. Recover the string length. */
    for (*Chars = 0; *Chars < SAFEUPLOAD_MAX_PREFIX_CHARS && Slot[*Chars] != UNICODE_NULL; ++*Chars) { }
    return *Chars != 0;
}

static VOID SafeUploadBootScopeAdd(_Inout_ PSAFEUPLOAD_BOOT_SCOPE_SET Scopes,
    _In_reads_(Chars) PCWCH Prefix, _In_ ULONG Chars)
{
    ULONG index;
    UNICODE_STRING candidate;
    candidate.Buffer = (PWCH)Prefix;
    candidate.Length = (USHORT)(Chars * sizeof(WCHAR));
    candidate.MaximumLength = candidate.Length;
    for (index = 0; index < Scopes->PrefixCount; ++index) {
        UNICODE_STRING existing;
        existing.Buffer = Scopes->Prefixes[index];
        existing.Length = (USHORT)(Scopes->PrefixChars[index] * sizeof(WCHAR));
        existing.MaximumLength = existing.Length;
        if (RtlEqualUnicodeString(&existing, &candidate, TRUE)) return;
    }
    if (Scopes->PrefixCount >= SAFEUPLOAD_BOOT_SCOPE_MAX_PREFIXES) {
        Scopes->Overflow = TRUE;
        return;
    }
    index = Scopes->PrefixCount++;
    RtlCopyMemory(Scopes->Prefixes[index], Prefix, Chars * sizeof(WCHAR));
    Scopes->Prefixes[index][Chars] = UNICODE_NULL;
    Scopes->PrefixChars[index] = (USHORT)Chars;
}

static BOOLEAN SafeUploadBootPolicyRecordStrict(_In_reads_bytes_(DataBytes) PCUCHAR Data,
    _In_ ULONG DataBytes, _In_ ULONG MaximumPrefixes, _Out_ PUINT32 Flags,
    _Out_writes_(SAFEUPLOAD_BOOT_POLICY_MAX_PREFIXES)
    USHORT PrefixChars[SAFEUPLOAD_BOOT_POLICY_MAX_PREFIXES])
{
    const SAFEUPLOAD_BOOT_POLICY *record;
    ULONG index, chars;

    *Flags = 0;
    RtlZeroMemory(PrefixChars, sizeof(USHORT) * SAFEUPLOAD_BOOT_POLICY_MAX_PREFIXES);
    if (DataBytes != sizeof(SAFEUPLOAD_BOOT_POLICY)) return FALSE;
    record = (const SAFEUPLOAD_BOOT_POLICY *)Data;
    if (record->Version != SAFEUPLOAD_BOOT_POLICY_VERSION ||
        record->StructSize != sizeof(SAFEUPLOAD_BOOT_POLICY) ||
        record->PrefixCount > MaximumPrefixes ||
        (record->Flags & ~(SAFEUPLOAD_BOOT_POLICY_FLAG_REMOVABLE | SAFEUPLOAD_BOOT_POLICY_FLAG_NETWORK)) != 0) {
        return FALSE;
    }
    for (index = 0; index < SAFEUPLOAD_BOOT_POLICY_MAX_PREFIXES; ++index) {
        if (index < record->PrefixCount) {
            if (!SafeUploadBootPolicySlotRead(record->Prefixes[index], &chars)) return FALSE;
            PrefixChars[index] = (USHORT)chars;
        } else {
            for (chars = 0; chars < SAFEUPLOAD_MAX_PREFIX_CHARS; ++chars) {
                if (record->Prefixes[index][chars] != UNICODE_NULL) return FALSE;
            }
        }
    }
    *Flags = record->Flags;
    return TRUE;
}

static VOID SafeUploadBootPolicySalvage(_In_reads_bytes_(AvailableBytes) PCUCHAR Data,
    _In_ ULONG AvailableBytes, _Inout_ PSAFEUPLOAD_BOOT_SCOPE_SET Scopes)
{
    const SAFEUPLOAD_BOOT_POLICY *record;
    const ULONG prefixOffset = FIELD_OFFSET(SAFEUPLOAD_BOOT_POLICY, Prefixes);
    const ULONG slotBytes = SAFEUPLOAD_MAX_PREFIX_CHARS * sizeof(WCHAR);
    ULONG index, chars, completeSlots;

    if (AvailableBytes < (ULONG)FIELD_OFFSET(SAFEUPLOAD_BOOT_POLICY, Prefixes)) return;
    record = (const SAFEUPLOAD_BOOT_POLICY *)Data;
    /* Slot offsets are meaningful only for the known v1 envelope. A future
     * or wrong-sized record is corrupt-empty, never guessed as v1. */
    if (record->Version != SAFEUPLOAD_BOOT_POLICY_VERSION ||
        record->StructSize != sizeof(SAFEUPLOAD_BOOT_POLICY)) return;
    Scopes->Flags |= record->Flags & (SAFEUPLOAD_BOOT_POLICY_FLAG_REMOVABLE |
                                      SAFEUPLOAD_BOOT_POLICY_FLAG_NETWORK);
    completeSlots = min(SAFEUPLOAD_BOOT_POLICY_MAX_PREFIXES,
        (AvailableBytes - prefixOffset) / slotBytes);
    for (index = 0; index < completeSlots; ++index) {
        if (SafeUploadBootPolicySlotRead(record->Prefixes[index], &chars)) {
            SafeUploadBootScopeAdd(Scopes, record->Prefixes[index], chars);
        }
    }
}

static SAFEUPLOAD_BOOT_VALUE_RESULT SafeUploadBootPolicyReadValue(_In_ HANDLE Key,
    _In_ PCUNICODE_STRING ValueName, _In_ ULONG MaximumPrefixes,
    _Inout_ PSAFEUPLOAD_BOOT_SCOPE_SET Scopes)
{
    PKEY_VALUE_PARTIAL_INFORMATION information =
        (PKEY_VALUE_PARTIAL_INFORMATION)SafeUploadBootPolicyValueBuffer;
    USHORT slotChars[SAFEUPLOAD_BOOT_POLICY_MAX_PREFIXES];
    ULONG returned = 0, bytesAvailable = 0;
    UINT32 flags = 0;
    NTSTATUS status;
    BOOLEAN strict;

    RtlZeroMemory(SafeUploadBootPolicyValueBuffer, sizeof(SafeUploadBootPolicyValueBuffer));
    status = ZwQueryValueKey(Key, (PUNICODE_STRING)ValueName, KeyValuePartialInformation,
        information, sizeof(SafeUploadBootPolicyValueBuffer), &returned);
    if (status == STATUS_OBJECT_NAME_NOT_FOUND) return SafeUploadBootValueMissing;
    if (status != STATUS_SUCCESS && status != STATUS_BUFFER_OVERFLOW && status != STATUS_BUFFER_TOO_SMALL)
        return SafeUploadBootValueUnreadable;
    if (returned < (ULONG)FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) ||
        information->Type != REG_BINARY) return SafeUploadBootValueCorrupt;

    bytesAvailable = min(information->DataLength, (ULONG)sizeof(SAFEUPLOAD_BOOT_POLICY));
    strict = status == STATUS_SUCCESS && information->DataLength == sizeof(SAFEUPLOAD_BOOT_POLICY) &&
        SafeUploadBootPolicyRecordStrict(information->Data, information->DataLength,
            MaximumPrefixes, &flags, slotChars);
    if (strict) {
        const SAFEUPLOAD_BOOT_POLICY *record = (const SAFEUPLOAD_BOOT_POLICY *)information->Data;
        ULONG index;
        Scopes->Flags |= flags;
        for (index = 0; index < record->PrefixCount; ++index)
            SafeUploadBootScopeAdd(Scopes, record->Prefixes[index], slotChars[index]);
        return SafeUploadBootValueValid;
    }

    SafeUploadBootPolicySalvage(information->Data, bytesAvailable, Scopes);
    return SafeUploadBootValueCorrupt;
}

static BOOLEAN SafeUploadBootPolicyVerifyAcl(_In_ HANDLE Key)
{
    PSECURITY_DESCRIPTOR descriptor = (PSECURITY_DESCRIPTOR)SafeUploadBootPolicySecurityBuffer;
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    ULONG returned = 0, revision = 0, sidLength;
    PSID owner = NULL;
    PACL dacl = NULL;
    PVOID acePointer = NULL;
    BOOLEAN ownerDefaulted = FALSE, daclPresent = FALSE, daclDefaulted = FALSE;
    UCHAR trustedInstallerStorage[SECURITY_MAX_SID_SIZE];
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID trustedInstallerSid = (PSID)trustedInstallerStorage;
    BOOLEAN sawSystem = FALSE, sawTrustedInstaller = FALSE;
    NTSTATUS status;
    ULONG index;

    RtlZeroMemory(SafeUploadBootPolicySecurityBuffer, sizeof(SafeUploadBootPolicySecurityBuffer));
    status = ZwQuerySecurityObject(Key, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        descriptor, sizeof(SafeUploadBootPolicySecurityBuffer), &returned);
    /* Validate against the whole zeroed buffer, not the returned length: the canary readback showed the length a
     * security query reports on success is not a reliable descriptor length (canary-security run 2). */
    if (status != STATUS_SUCCESS || returned > sizeof(SafeUploadBootPolicySecurityBuffer) ||
        !RtlValidRelativeSecurityDescriptor(descriptor, sizeof(SafeUploadBootPolicySecurityBuffer),
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)) return FALSE;
    revision = ((PISECURITY_DESCRIPTOR_RELATIVE)descriptor)->Revision;
    control = ((PISECURITY_DESCRIPTOR_RELATIVE)descriptor)->Control;
    if (revision != SECURITY_DESCRIPTOR_REVISION || !FlagOn(control, SE_SELF_RELATIVE) ||
        !FlagOn(control, SE_DACL_PRESENT) || !FlagOn(control, SE_DACL_PROTECTED)) return FALSE;
    status = RtlGetOwnerSecurityDescriptor(descriptor, &owner, &ownerDefaulted);
    if (!NT_SUCCESS(status) || owner == NULL || !RtlValidSid(owner) ||
        !RtlEqualSid(owner, SeExports->SeLocalSystemSid)) return FALSE;
    status = RtlGetDaclSecurityDescriptor(descriptor, &daclPresent, &dacl, &daclDefaulted);
    /* RtlValidAcl is not available to kernel mode; the descriptor validation above covers the DACL. */
    if (!NT_SUCCESS(status) || !daclPresent || dacl == NULL || dacl->AceCount != 2)
        return FALSE;

    /* S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464. */
    status = RtlInitializeSid(trustedInstallerSid, &ntAuthority, 6);
    if (!NT_SUCCESS(status)) return FALSE;
    RtlSubAuthoritySid(trustedInstallerSid, 0)[0] = 80u;
    RtlSubAuthoritySid(trustedInstallerSid, 1)[0] = 956008885u;
    RtlSubAuthoritySid(trustedInstallerSid, 2)[0] = 3418522649u;
    RtlSubAuthoritySid(trustedInstallerSid, 3)[0] = 1831038044u;
    RtlSubAuthoritySid(trustedInstallerSid, 4)[0] = 1853292631u;
    RtlSubAuthoritySid(trustedInstallerSid, 5)[0] = 2271478464u;

    sidLength = RtlLengthSid(SeExports->SeLocalSystemSid);
    for (index = 0; index < 2; ++index) {
        PACCESS_ALLOWED_ACE allowed;
        PSID trustee;
        status = RtlGetAce(dacl, index, &acePointer);
        if (!NT_SUCCESS(status) || acePointer == NULL) return FALSE;
        if (((PACE_HEADER)acePointer)->AceType != ACCESS_ALLOWED_ACE_TYPE ||
            ((PACE_HEADER)acePointer)->AceFlags != 0 ||
            ((PACE_HEADER)acePointer)->AceSize < FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) +
                FIELD_OFFSET(SID, SubAuthority)) return FALSE;
        allowed = (PACCESS_ALLOWED_ACE)acePointer;
        trustee = (PSID)&allowed->SidStart;
        /* Only the exact SYSTEM and TrustedInstaller SID lengths are valid;
         * validate the bounded count before RtlValidSid follows subauthorities. */
        if ((allowed->Header.AceSize == FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + 12 &&
             ((PISID)trustee)->SubAuthorityCount != 1) ||
            (allowed->Header.AceSize == FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + 32 &&
             ((PISID)trustee)->SubAuthorityCount != 6) ||
            (allowed->Header.AceSize != FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + 12 &&
             allowed->Header.AceSize != FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + 32) ||
            !RtlValidSid(trustee) || allowed->Mask != KEY_ALL_ACCESS) return FALSE;
        if (RtlEqualSid(trustee, SeExports->SeLocalSystemSid)) {
            if (sawSystem || allowed->Header.AceSize != FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + sidLength)
                return FALSE;
            sawSystem = TRUE;
        } else if (RtlEqualSid(trustee, trustedInstallerSid)) {
            if (sawTrustedInstaller || allowed->Header.AceSize !=
                FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + RtlLengthSid(trustedInstallerSid)) return FALSE;
            sawTrustedInstaller = TRUE;
        } else return FALSE;
    }
    UNREFERENCED_PARAMETER(ownerDefaulted);
    UNREFERENCED_PARAMETER(daclDefaulted);
    return sawSystem && sawTrustedInstaller;
}

NTSTATUS SafeUploadReadBootPolicy(_In_ PUNICODE_STRING ServiceRegistryPath,
    _Out_ PSAFEUPLOAD_POLICY_MESSAGE Policy, _Out_ PSAFEUPLOAD_BOOT_SCOPE_SET Scopes,
    _Out_ PUINT32 State, _Out_ PBOOLEAN BootStartMode)
{
    OBJECT_ATTRIBUTES attributes;
    HANDLE serviceKey = NULL, parametersKey = NULL, policyKey = NULL;
    UNICODE_STRING parametersName, policyName, committedName, pendingName, startName;
    SAFEUPLOAD_BOOT_VALUE_RESULT committed, pending;
    BOOLEAN aclRejected = FALSE, readFailed = FALSE, anyValue = FALSE, anyCorrupt = FALSE;
    UINT32 bootPolicyState = SAFEUPLOAD_BOOT_POLICY_STATE_UNREADABLE;
    NTSTATUS status;

    if (BootStartMode != NULL) *BootStartMode = TRUE; /* Unknown start mode skips volume scans. */
    if (ServiceRegistryPath == NULL || Policy == NULL || Scopes == NULL || State == NULL || BootStartMode == NULL ||
        ServiceRegistryPath->Buffer == NULL || ServiceRegistryPath->Length == 0 ||
        (ServiceRegistryPath->Length & 1) != 0) return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(Policy, sizeof(*Policy));
    RtlZeroMemory(Scopes, sizeof(*Scopes));
    *State = bootPolicyState;

    InitializeObjectAttributes(&attributes, ServiceRegistryPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenKey(&serviceKey, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | READ_CONTROL, &attributes);
    if (!NT_SUCCESS(status)) {
        *State = status == STATUS_OBJECT_NAME_NOT_FOUND ? SAFEUPLOAD_BOOT_POLICY_STATE_MISSING :
            (status == STATUS_ACCESS_DENIED ? SAFEUPLOAD_BOOT_POLICY_STATE_ACL_REJECTED :
             SAFEUPLOAD_BOOT_POLICY_STATE_UNREADABLE);
        goto Exit;
    }
    {
        DECLSPEC_ALIGN(8) UCHAR startBuffer[FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + sizeof(ULONG)];
        PKEY_VALUE_PARTIAL_INFORMATION startInformation = (PKEY_VALUE_PARTIAL_INFORMATION)startBuffer;
        ULONG startReturned = 0;
        ULONG startValue;

        RtlZeroMemory(startBuffer, sizeof(startBuffer));
        RtlInitUnicodeString(&startName, L"Start");
        status = ZwQueryValueKey(serviceKey, &startName, KeyValuePartialInformation,
            startInformation, sizeof(startBuffer), &startReturned);
        if (status == STATUS_SUCCESS &&
            startReturned >= FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + sizeof(ULONG) &&
            startInformation->Type == REG_DWORD && startInformation->DataLength == sizeof(ULONG)) {
            RtlCopyMemory(&startValue, startInformation->Data, sizeof(startValue));
            /* Demand-start remains the Phase 1 diagnostic path. Any boot,
             * system-start, or unreadable mode avoids scan-based fence work. */
            *BootStartMode = startValue != 3;
        }
        SafeUploadTrace("service start mode boot-scan-disabled=%u query-status=0x%08X\n",
            *BootStartMode ? 1 : 0, status);
    }
    RtlInitUnicodeString(&parametersName, L"Parameters");
    InitializeObjectAttributes(&attributes, &parametersName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, serviceKey, NULL);
    status = ZwOpenKey(&parametersKey, KEY_ENUMERATE_SUB_KEYS | READ_CONTROL, &attributes);
    if (!NT_SUCCESS(status)) {
        *State = status == STATUS_OBJECT_NAME_NOT_FOUND ? SAFEUPLOAD_BOOT_POLICY_STATE_MISSING :
            (status == STATUS_ACCESS_DENIED ? SAFEUPLOAD_BOOT_POLICY_STATE_ACL_REJECTED :
             SAFEUPLOAD_BOOT_POLICY_STATE_UNREADABLE);
        goto Exit;
    }
    if (!SafeUploadBootPolicyVerifyAcl(parametersKey)) aclRejected = TRUE;

    RtlInitUnicodeString(&policyName, L"BootPolicy");
    InitializeObjectAttributes(&attributes, &policyName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, parametersKey, NULL);
    status = ZwOpenKey(&policyKey, KEY_QUERY_VALUE | READ_CONTROL, &attributes);
    if (!NT_SUCCESS(status)) {
        *State = aclRejected || status == STATUS_ACCESS_DENIED ? SAFEUPLOAD_BOOT_POLICY_STATE_ACL_REJECTED :
            (status == STATUS_OBJECT_NAME_NOT_FOUND ? SAFEUPLOAD_BOOT_POLICY_STATE_MISSING :
             SAFEUPLOAD_BOOT_POLICY_STATE_UNREADABLE);
        goto Exit;
    }
    if (!SafeUploadBootPolicyVerifyAcl(policyKey)) aclRejected = TRUE;

    RtlInitUnicodeString(&committedName, L"Scopes");
    RtlInitUnicodeString(&pendingName, L"PendingScopes");
    committed = SafeUploadBootPolicyReadValue(policyKey, &committedName,
        SAFEUPLOAD_MAX_PREFIXES, Scopes);
    pending = SafeUploadBootPolicyReadValue(policyKey, &pendingName,
        SAFEUPLOAD_BOOT_POLICY_MAX_PREFIXES, Scopes);
    anyValue = committed != SafeUploadBootValueMissing || pending != SafeUploadBootValueMissing;
    anyCorrupt = committed == SafeUploadBootValueCorrupt || pending == SafeUploadBootValueCorrupt;
    readFailed = committed == SafeUploadBootValueUnreadable || pending == SafeUploadBootValueUnreadable;

    if (aclRejected) bootPolicyState = SAFEUPLOAD_BOOT_POLICY_STATE_ACL_REJECTED;
    else if (readFailed) bootPolicyState = SAFEUPLOAD_BOOT_POLICY_STATE_UNREADABLE;
    else if (anyCorrupt) bootPolicyState = Scopes->PrefixCount != 0 || Scopes->Flags != 0 || Scopes->Overflow ?
        SAFEUPLOAD_BOOT_POLICY_STATE_CORRUPT_PARTIAL : SAFEUPLOAD_BOOT_POLICY_STATE_CORRUPT_EMPTY;
    else if (!anyValue) bootPolicyState = SAFEUPLOAD_BOOT_POLICY_STATE_MISSING;
    else if (pending == SafeUploadBootValueValid) bootPolicyState = SAFEUPLOAD_BOOT_POLICY_STATE_PENDING_UNION;
    else bootPolicyState = SAFEUPLOAD_BOOT_POLICY_STATE_VALID;
    *State = bootPolicyState;

    Policy->Control.Version = SAFEUPLOAD_PROTOCOL_VERSION;
    Policy->Control.StructSize = sizeof(*Policy);
    Policy->PrefixCount = min(Scopes->PrefixCount, SAFEUPLOAD_MAX_PREFIXES);
    Policy->Flags = Scopes->Flags;
    {
        ULONG index;
        for (index = 0; index < Policy->PrefixCount; ++index) {
            RtlCopyMemory(Policy->Prefixes[index], Scopes->Prefixes[index],
                Scopes->PrefixChars[index] * sizeof(WCHAR));
            Policy->Prefixes[index][Scopes->PrefixChars[index]] = UNICODE_NULL;
        }
    }
    status = STATUS_SUCCESS;

Exit:
    if (policyKey != NULL) ZwClose(policyKey);
    if (parametersKey != NULL) ZwClose(parametersKey);
    if (serviceKey != NULL) ZwClose(serviceKey);
    SafeUploadTrace("boot policy state=%u identified-prefixes=%u flags=0x%X overflow=%u boot-start-mode=%u\n",
        *State, Scopes->PrefixCount, Scopes->Flags, Scopes->Overflow ? 1 : 0,
        *BootStartMode ? 1 : 0);
    return status;
}
