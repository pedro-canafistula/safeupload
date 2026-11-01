using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using Microsoft.Win32.SafeHandles;

namespace SafeUpload.Agent.Service.Notifications;

// Opens notification record files without following reparse points and checks the object actually opened.
internal static class RecordFile
{
    internal const int MaximumManifestBytes = 128 * 1024;

    internal static FileSecurity ReadSecurity(FileStream stream, string path)
    {
        try { return stream.GetAccessControl(); }
        catch (UnauthorizedAccessException error)
        {
            throw new UnauthorizedAccessException("Record handle ACL query failed for '" + path + "'.", error);
        }
    }

    /// <summary>The parent folder must be owned by SYSTEM/administrators and not let ordinary users remove children.</summary>
    internal static void RequireProtectedParent(string directory)
    {
        string parent = Path.GetDirectoryName(directory) ?? throw new IOException("The record needs a protected parent directory.");
        if (!OperatingSystem.IsWindows()) return;
        var security = new DirectoryInfo(parent).GetAccessControl();
        var owner = security.GetOwner(typeof(System.Security.Principal.SecurityIdentifier)) as System.Security.Principal.SecurityIdentifier
            ?? throw new UnauthorizedAccessException("The record parent has no Windows owner.");
        if (!owner.IsWellKnown(System.Security.Principal.WellKnownSidType.LocalSystemSid) &&
            !owner.IsWellKnown(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid))
            throw new UnauthorizedAccessException("The record parent has an untrusted owner.");
        const FileSystemRights destructive = FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
            FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow || (rule.PropagationFlags & PropagationFlags.InheritOnly) != 0 ||
                (rule.FileSystemRights & destructive) == 0 || rule.IdentityReference is not System.Security.Principal.SecurityIdentifier sid)
                continue;
            if (!sid.IsWellKnown(System.Security.Principal.WellKnownSidType.LocalSystemSid) &&
                !sid.IsWellKnown(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid))
                throw new UnauthorizedAccessException("The record parent allows ordinary users to remove its children.");
        }
    }

    // Preservation authenticates the parent, not the damaged child's data or
    // DACL. A zero-access, no-follow handle suffices to refuse unsafe objects
    // before renaming them aside; never open their bytes or repair their ACLs.
    internal static void RequireRegularFileForPreservation(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            if ((File.GetAttributes(path) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                throw new IOException("Record preservation requires a regular file without reparse points.");
            return;
        }
        using var handle = CreateFile(path, 0, 7, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
        if (handle.IsInvalid)
            throw new IOException("Could not open record preservation metadata.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        RequireRegularFile(handle);
    }

    public static FileStream Open(string path, bool recoverAcl = false, bool writable = false, int maximumBytes = MaximumManifestBytes, bool writeThrough = true)
    {
        if (!OperatingSystem.IsWindows())
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Record contains a reparse point.");
            var stream = new FileStream(path, FileMode.Open, writable ? FileAccess.ReadWrite : FileAccess.Read,
                writable ? FileShare.Read : FileShare.Read | FileShare.Delete, 4096, FileOptions.Asynchronous);
            try { RequireBound(stream, maximumBytes); return stream; }
            catch { stream.Dispose(); throw; }
        }

        // GENERIC_READ (+ WRITE_DAC for recovery), OPEN_EXISTING,
        // OPEN_REPARSE_POINT | OVERLAPPED | BACKUP_SEMANTICS (so an
        // unexpected directory can be identified and refused). Never follow
        // the final link; trusted ownership is still checked by the caller.
        var handle = CreateFile(path, 0x80000000U | (writable ? 0x40000000U : 0) | (recoverAcl ? 0x40000U : 0),
            writable ? 1U : 5U, IntPtr.Zero, 3, 0x42200000U | (writable && writeThrough ? 0x80000000U : 0), IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = new Win32Exception(Marshal.GetLastWin32Error());
            handle.Dispose();
            throw error.NativeErrorCode switch
            {
                2 => new FileNotFoundException("Record manifest not found.", path),
                3 => new DirectoryNotFoundException("Record directory not found."),
                5 => new UnauthorizedAccessException("Record manifest access denied.", error),
                _ => new IOException("Could not open record manifest.", error)
            };
        }
        try
        {
            RequireRegularFile(handle);
            var stream = new FileStream(handle, writable ? FileAccess.ReadWrite : FileAccess.Read, 4096, isAsync: true);
            try { RequireBound(stream, maximumBytes); return stream; }
            catch { stream.Dispose(); throw; }
        }
        catch { handle.Dispose(); throw; }
    }

    private static void RequireRegularFile(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out var information))
            throw new IOException("Could not identify record manifest.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        if ((information.Attributes & 0x410) != 0 || information.LinkCount != 1)
            throw new IOException("Record manifest must be a regular file with exactly one link.");
    }

    private static void RequireBound(FileStream stream, int maximumBytes)
    {
        if (stream.Length > maximumBytes)
            throw new InvalidDataException("Record manifest exceeds the qualified size bound.");
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime, AccessTime, WriteTime;
        public uint VolumeSerial, SizeHigh, SizeLow, LinkCount, IdHigh, IdLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInformation information);
}
