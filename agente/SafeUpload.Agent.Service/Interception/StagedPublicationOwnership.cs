using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SafeUpload.Agent.Service.Interception;

/// <summary>
/// M2 MVP metadata (owner, 2026-10-29): a published file must belong to the user who saved it, not to the SYSTEM
/// service, and an edit must keep the existing file's DACL. The descriptor is supplied to the publication CREATE itself
/// (no separate security change on the protected name):
/// <list type="bullet">
/// <item>new file: owner = the saving user and an <b>absent</b> DACL, so NTFS inherits the parent's DACL exactly as for a
/// native create (CREATOR OWNER resolves to that user). An absent DACL is not a NULL DACL, which would grant everyone
/// access;</item>
/// <item>existing file: its owner, group and DACL with the protected/auto-inherit control bits. Explicit ACEs survive and
/// inherited ACEs are recomputed from the parent, as for an in-place edit.</item>
/// </list>
/// Exact parity (group of new files, SACL/label, ChangeTime) is deferred after the MVP.
/// </summary>
internal static class StagedPublicationOwnership
{
    private const ControlFlags KeptControl = ControlFlags.DiscretionaryAclPresent |
        ControlFlags.DiscretionaryAclProtected | ControlFlags.DiscretionaryAclAutoInherited |
        ControlFlags.DiscretionaryAclAutoInheritRequired;

    /// <summary>Null keeps the historical service-default creation (no requestor and no existing file).</summary>
    [SupportedOSPlatform("windows")]
    internal static byte[]? Descriptor(string destination, string? requestorSid)
    {
        if (File.Exists(destination))
        {
            // An unreadable existing descriptor fails the publication closed rather than silently dropping its ACEs.
            var existing = new FileInfo(destination).GetAccessControl(
                AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access);
            return Preserve(existing.GetSecurityDescriptorBinaryForm());
        }
        return string.IsNullOrWhiteSpace(requestorSid) ? null : NewFile(new SecurityIdentifier(requestorSid));
    }

    internal static byte[] NewFile(SecurityIdentifier owner)
    {
        var descriptor = new RawSecurityDescriptor(ControlFlags.SelfRelative, owner, null, null, null);
        if ((descriptor.ControlFlags & ControlFlags.DiscretionaryAclPresent) != 0)
            throw new InvalidOperationException("A new publication descriptor must leave the DACL to inheritance.");
        return Binary(descriptor);
    }

    internal static byte[] Preserve(byte[] existing)
    {
        var source = new RawSecurityDescriptor(existing, 0);
        if (source.Owner is null || (source.ControlFlags & ControlFlags.DiscretionaryAclPresent) == 0 ||
            source.DiscretionaryAcl is null)
            throw new IOException("The existing destination has no owner or DACL to preserve.");
        var kept = new RawSecurityDescriptor((source.ControlFlags & KeptControl) | ControlFlags.SelfRelative,
            source.Owner, source.Group, null, source.DiscretionaryAcl);
        return Binary(kept);
    }

    internal static SecurityIdentifier Owner(byte[] descriptor) =>
        new RawSecurityDescriptor(descriptor, 0).Owner ?? throw new IOException("Descriptor has no owner.");

    private static byte[] Binary(GenericSecurityDescriptor descriptor)
    {
        byte[] bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        return bytes;
    }

    /// <summary>
    /// Assigning an owner other than the service needs SeRestorePrivilege (LocalSystem holds it). Enabled only around the
    /// CREATE and restored to its previous state afterwards.
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal static IDisposable? RestorePrivilegeFor(byte[] descriptor)
    {
        using var self = WindowsIdentity.GetCurrent();
        if (Owner(descriptor) == self.User) return null;
        return new PrivilegeScope("SeRestorePrivilege");
    }

    [SupportedOSPlatform("windows")]
    private sealed class PrivilegeScope : IDisposable
    {
        private readonly IntPtr _token;
        private readonly TOKEN_PRIVILEGES _previous;
        private bool _restored;

        internal PrivilegeScope(string name)
        {
            if (!OpenProcessToken(GetCurrentProcess(), 0x0020 | 0x0008, out _token)) // ADJUST_PRIVILEGES | QUERY
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot open the service token.");
            try
            {
                if (!LookupPrivilegeValue(null, name, out long luid))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Unknown privilege " + name);
                var enable = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Luid = luid, Attributes = 0x2 }; // ENABLED
                if (!AdjustTokenPrivileges(_token, false, ref enable, Marshal.SizeOf<TOKEN_PRIVILEGES>(), out _previous, out _) ||
                    Marshal.GetLastWin32Error() != 0) // ERROR_NOT_ALL_ASSIGNED is reported through the last error
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot enable " + name + ".");
            }
            catch { CloseHandle(_token); throw; }
        }

        public void Dispose()
        {
            if (_restored) return;
            _restored = true;
            var previous = _previous;
            if (previous.PrivilegeCount != 0) AdjustTokenPrivileges(_token, false, ref previous, 0, out _, out _);
            CloseHandle(_token);
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct TOKEN_PRIVILEGES
    {
        public int PrivilegeCount;
        public long Luid;
        public int Attributes;
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr process, int access, out IntPtr token);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeValue(string? system, string name, out long luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AdjustTokenPrivileges(IntPtr token, [MarshalAs(UnmanagedType.Bool)] bool disableAll,
        ref TOKEN_PRIVILEGES state, int length, out TOKEN_PRIVILEGES previous, out int returned);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}
