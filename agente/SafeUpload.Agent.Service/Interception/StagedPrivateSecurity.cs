using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using Microsoft.Win32.SafeHandles;

namespace SafeUpload.Agent.Service.Interception;

// Startup must inspect the existing private namespace even while the loaded
// driver retains backing handles from the previous service lifetime. Query only
// metadata, with explicit READ_CONTROL and full sharing; never request data
// access or rely on GetNamedSecurityInfo's implicit reopen of the locator.
internal static class StagedPrivateSecurity
{
    internal static DirectorySecurity ReadDirectory(string path) => (DirectorySecurity)Read(path, directory: true);
    internal static FileSecurity ReadFile(string path) => (FileSecurity)Read(path, directory: false);

    private static FileSystemSecurity Read(string path, bool directory)
    {
        const uint readControlAndAttributes = 0x00020080;
        using var handle = CreateFile(path, readControlAndAttributes, 7, IntPtr.Zero, 3,
            0x02200000, IntPtr.Zero); // BACKUP_SEMANTICS | OPEN_REPARSE_POINT
        if (handle.IsInvalid) throw Failure(path, "open READ_CONTROL", Marshal.GetLastWin32Error());
        if (!GetFileInformationByHandle(handle, out var info))
            throw Failure(path, "identify ACL object", Marshal.GetLastWin32Error());
        if ((info.Attributes & 0x400) != 0 || ((info.Attributes & 0x10) != 0) != directory ||
            (!directory && info.LinkCount != 1))
            throw new IOException("Private ACL object has an unsafe type/link count: " + path);

        const uint ownerGroupDacl = 7;
        int status = GetSecurityInfo(handle, 1, ownerGroupDacl, out _, out _, out _, out _, out var descriptor);
        try
        {
            if (status != 0) throw Failure(path, "query OWNER/GROUP/DACL", status);
            if (descriptor == IntPtr.Zero) throw new IOException("Private ACL query returned no descriptor: " + path);
            uint length = GetSecurityDescriptorLength(descriptor);
            if (length == 0 || length > 128 * 1024)
                throw new IOException("Private ACL descriptor has an invalid length: " + path);
            var bytes = new byte[checked((int)length)];
            Marshal.Copy(descriptor, bytes, 0, bytes.Length);
            FileSystemSecurity security = directory ? new DirectorySecurity() : new FileSecurity();
            security.SetSecurityDescriptorBinaryForm(bytes,
                AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access);
            return security;
        }
        finally { if (descriptor != IntPtr.Zero) LocalFree(descriptor); }
    }

    private static Exception Failure(string path, string operation, int code)
    {
        var native = new Win32Exception(code);
        string message = $"Private ACL {operation} failed for '{path}' (Win32 {code}).";
        return code == 5 ? new UnauthorizedAccessException(message, native) : new IOException(message, native);
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
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInformation info);
    [DllImport("advapi32.dll")]
    private static extern int GetSecurityInfo(SafeFileHandle handle, int objectType, uint information,
        out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
