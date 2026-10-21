using System.Runtime.InteropServices;
using System.Buffers.Binary;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace SafeUpload.Agent.Service.Interception;

// Presence means prior public bytes were seeded (possibly through a private
// predecessor). Absence preserves legacy/no-public-seed behavior. This is a
// local allocation receipt, not bound-profile or original CREATE authority.
public sealed record StagedUnboundSeedExport(
    int FormatVersion, StagedStageIdentity SourceIdentity, string? RequestorSid,
    int ProcessId, long? ProcessCreationTime, StagedSeedAuthority ReadAuthority)
{
    internal void Validate(StagedTransfer transfer)
    {
        if (FormatVersion != 1 || SourceIdentity is null || !Enum.IsDefined(ReadAuthority) ||
            ProcessId != transfer.ProcessId || ProcessCreationTime != transfer.RequestorProcessCreationTime ||
            !string.Equals(RequestorSid, transfer.RequestorSid, StringComparison.OrdinalIgnoreCase) ||
            (ReadAuthority == StagedSeedAuthority.Allowed &&
             (string.IsNullOrWhiteSpace(RequestorSid) || ProcessCreationTime is not > 0)))
            throw new InvalidDataException("Invalid unbound seed export receipt.");
    }
}

public interface IStagedSeedReadAuthorityEvaluator
{
    // Borrowed exact source handle; implementations must inspect only security,
    // never infer caller authority from this service handle's granted access.
    StagedSeedAuthority Evaluate(StagedTransfer requestor, SafeFileHandle source);
}

internal sealed class StagedSeedReadAuthorityEvaluator : IStagedSeedReadAuthorityEvaluator
{
    public StagedSeedAuthority Evaluate(StagedTransfer requestor, SafeFileHandle source)
    {
        if (!OperatingSystem.IsWindows() || source.IsInvalid || source.IsClosed ||
            requestor.ProcessId <= 0 || requestor.RequestorProcessCreationTime is not > 0 ||
            string.IsNullOrWhiteSpace(requestor.RequestorSid)) return StagedSeedAuthority.Unproven;
        try { return EvaluateWindows(requestor, source); }
        catch (Exception error) when (error is System.ComponentModel.Win32Exception or
            ArgumentException or InvalidOperationException or UnauthorizedAccessException or IOException or
            System.Security.SecurityException)
        { return StagedSeedAuthority.Unproven; }
    }

    private static StagedSeedAuthority EvaluateWindows(StagedTransfer requestor, SafeFileHandle source)
    {
        // The shipped protocol has no captured thread-impersonation token. Only
        // the PID + creation-time + SID matched process-primary subject is evidence
        // here; this does not authorize a CREATE or claim to reconstruct its subject.
        using var process = OpenProcess(0x1000, false, requestor.ProcessId); // QUERY_LIMITED_INFORMATION
        if (process.IsInvalid || !GetProcessTimes(process, out long creation, out _, out _, out _) ||
            creation != requestor.RequestorProcessCreationTime ||
            !OpenProcessToken(process, 0x000A, out var primary)) // TOKEN_QUERY | TOKEN_DUPLICATE
            return StagedSeedAuthority.Unproven;
        using (primary)
        {
            using var identity = new WindowsIdentity(primary.DangerousGetHandle());
            if (!string.Equals(identity.User?.Value, requestor.RequestorSid, StringComparison.OrdinalIgnoreCase) ||
                requestor.SessionId is null || ReadTokenInteger(primary, 12) != requestor.SessionId ||
                ReadTokenInteger(primary, 29) != 0) return StagedSeedAuthority.Unproven; // TokenSessionId / TokenIsAppContainer
            int tokenIntegrity = ReadTokenIntegrity(primary);
            if (!DuplicateToken(primary, 2, out var subject)) return StagedSeedAuthority.Unproven;
            using (subject)
            {
                // GetSecurityInfo: OWNER | GROUP | DACL | LABEL | ATTRIBUTE |
                // SCOPE | PROCESS_TRUST_LABEL | ACCESS_FILTER_SECURITY_INFORMATION.
                // LABEL needs READ_CONTROL, not an audit-SACL privilege. This is
                // the held copy source, not a second pathname lookup or data read.
                // Never fall back to a reduced descriptor after a query failure:
                // omitted resource/scoped/conditional security is not permission.
                int status = GetSecurityInfo(source, 1, 0x1F7, out _, out _, out _, out _, out var sd);
                try
                {
                    if (status != 0 || sd == IntPtr.Zero) return StagedSeedAuthority.Unproven;
                    uint length = GetSecurityDescriptorLength(sd);
                    if (length == 0 || length > 65536) return StagedSeedAuthority.Unproven;
                    var bytes = new byte[length]; Marshal.Copy(sd, bytes, 0, bytes.Length);
                    var descriptor = new RawSecurityDescriptor(bytes, 0);
                    if (!LabelPermitsProof(descriptor, tokenIntegrity)) return StagedSeedAuthority.Unproven;
                    if (descriptor.DiscretionaryAcl is { } dacl)
                        foreach (GenericAce ace in dacl)
                            if (ace is not KnownAce known || (byte)ace.AceType is not (0 or 1) ||
                                ((byte)ace.AceFlags & ~0x1F) != 0 || (known.AccessMask & 0xF0000000u) != 0)
                                return StagedSeedAuthority.Unproven;
                    // AccessCheck uses the actual token's enabled/deny-only and
                    // restricted groups; no SID-only group reconstruction or SYSTEM
                    // privilege/grant is substituted. FILE_READ_DATA is exactly 1.
                    var read = CheckReadData(sd, subject);
                    if (read != StagedSeedAuthority.Allowed) return read;
                    // The hand-back ACL grants this account read access. Do
                    // not export an elevated/restricted/high-IL-only source
                    // grant into that broader recipient. The ordinary medium,
                    // unfiltered primary is the supported affirmative envelope.
                    // Traversal must be independently satisfied: file-only
                    // AccessCheck cannot prove denied ancestor traversal.
                    return ExportEnvelopePermitsProof(descriptor, identity.User!, tokenIntegrity,
                        ReadTokenInteger(primary, 18), ReadTokenInteger(primary, 20), ReadTokenInteger(primary, 21),
                        HasTraversalBypass(primary)) ? StagedSeedAuthority.Allowed : StagedSeedAuthority.Unproven;
                }
                finally { if (sd != IntPtr.Zero) LocalFree(sd); }
            }
        }
    }

    internal static bool ExportEnvelopePermitsProof(RawSecurityDescriptor descriptor, SecurityIdentifier account,
        int integrity, int elevationType, int elevated, int restrictions, bool traversalBypass) =>
        integrity == 0x2000 && elevationType == 1 && elevated == 0 && restrictions == 0 && traversalBypass &&
        AccountGrantPermitsExport(descriptor, account);

    internal static StagedSeedAuthority CheckReadData(IntPtr descriptor, SafeAccessTokenHandle subject)
    {
        var mapping = new GenericMapping(0x120089, 0x120116, 0x1200A0, 0x1F01FF);
        uint privilegeBytes = 4096;
        IntPtr privileges = Marshal.AllocHGlobal((int)privilegeBytes);
        try
        {
            if (!AccessCheck(descriptor, subject, 1, ref mapping, privileges, ref privilegeBytes,
                    out uint granted, out bool allowed)) return StagedSeedAuthority.Unproven;
            return allowed && (granted & 1) != 0 ? StagedSeedAuthority.Allowed : StagedSeedAuthority.Denied;
        }
        finally { Marshal.FreeHGlobal(privileges); }
    }

    private static bool AccountGrantPermitsExport(RawSecurityDescriptor descriptor, SecurityIdentifier account)
    {
        // The copier grants the account SID, not a logon/group SID. Do not turn
        // a group-only grant or a token-specific absence of a deny group into a
        // broader account grant on the returned file. Null DACL allows everyone.
        if (descriptor.DiscretionaryAcl is not { } dacl) return true;
        bool granted = false;
        foreach (GenericAce ace in dacl)
        {
            if ((ace.AceFlags & AceFlags.InheritOnly) != 0) continue;
            if (ace is not KnownAce known) return false;
            if ((known.AccessMask & 1) == 0) continue;
            if ((byte)ace.AceType == 1) return false;
            if ((byte)ace.AceType == 0 && known.SecurityIdentifier == account) granted = true;
        }
        return granted;
    }

    internal static bool LabelPermitsProof(RawSecurityDescriptor descriptor, int tokenIntegrity)
    {
        // Windows treats an unlabeled file as medium integrity. AccessCheck is
        // a DACL check, not a MIC check: prove the conservative stronger condition
        // token IL >= object IL even when NO_READ_UP is absent. Unsupported label
        // shapes/flags remain Unproven rather than being interpreted as permission.
        int objectIntegrity = 0x2000;
        if (descriptor.SystemAcl is { Count: > 0 } acl)
        {
            if (acl.Count != 1 || (byte)acl[0].AceType != 17 ||
                (acl[0].AceFlags & ~AceFlags.Inherited) != 0) return false;
            // SystemMandatoryLabel may be represented as CustomAce by .NET.
            // Its documented native layout is header, ACCESS_MASK, then SID.
            byte[] label = new byte[acl[0].BinaryLength]; acl[0].GetBinaryForm(label, 0);
            if (label.Length < 20) return false;
            int mask = BinaryPrimitives.ReadInt32LittleEndian(label.AsSpan(4));
            if ((mask & ~7) != 0 || (mask & 2) != 0) return false;
            var sid = new SecurityIdentifier(label, 8);
            if (sid.BinaryLength != label.Length - 8) return false;
            objectIntegrity = IntegrityRid(sid);
        }
        return tokenIntegrity >= 0 && objectIntegrity >= 0 && tokenIntegrity >= objectIntegrity;
    }

    private static int IntegrityRid(SecurityIdentifier sid)
    {
        string[] parts = sid.Value.Split('-');
        return parts.Length == 4 && parts[0] == "S" && parts[1] == "1" && parts[2] == "16" &&
            int.TryParse(parts[3], out int rid) && rid >= 0 ? rid : -1;
    }

    private static int ReadTokenIntegrity(SafeAccessTokenHandle token)
    {
        GetTokenInformation(token, 25, IntPtr.Zero, 0, out int size); // TokenIntegrityLevel
        if (size <= IntPtr.Size || size > 65536) return -1;
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            return GetTokenInformation(token, 25, buffer, size, out _) ?
                IntegrityRid(new SecurityIdentifier(Marshal.ReadIntPtr(buffer))) : -1;
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static int ReadTokenInteger(SafeAccessTokenHandle token, int informationClass)
    {
        IntPtr buffer = Marshal.AllocHGlobal(sizeof(int));
        try { return GetTokenInformation(token, informationClass, buffer, sizeof(int), out _) ? Marshal.ReadInt32(buffer) : -1; }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static bool HasTraversalBypass(SafeAccessTokenHandle token)
    {
        if (!LookupPrivilegeValue(null, "SeChangeNotifyPrivilege", out long traversal)) return false;
        GetTokenInformation(token, 3, IntPtr.Zero, 0, out int size); // TokenPrivileges
        if (size < 4 || size > 65536) return false;
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (!GetTokenInformation(token, 3, buffer, size, out _)) return false;
            int count = Marshal.ReadInt32(buffer);
            if (count < 0 || count > (size - 4) / 12) return false;
            for (int index = 0; index < count; index++)
                if (Marshal.ReadInt64(buffer, 4 + index * 12) == traversal &&
                    (Marshal.ReadInt32(buffer, 12 + index * 12) & 2) != 0) return true;
            return false;
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct GenericMapping(uint read, uint write, uint execute, uint all)
    { public uint Read = read, Write = write, Execute = execute, All = all; }
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(SafeProcessHandle process, out long creation, out long exit, out long kernel, out long user);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(SafeProcessHandle process, uint access, out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateToken(SafeAccessTokenHandle token, int level, out SafeAccessTokenHandle duplicate);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int informationClass, IntPtr buffer, int size, out int needed);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeValue(string? system, string name, out long luid);
    [DllImport("advapi32.dll")]
    private static extern int GetSecurityInfo(SafeFileHandle handle, int objectType, uint information,
        out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AccessCheck(IntPtr descriptor, SafeAccessTokenHandle token, uint access, ref GenericMapping mapping,
        IntPtr privileges, ref uint privilegeBytes, out uint granted, [MarshalAs(UnmanagedType.Bool)] out bool allowed);
    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
