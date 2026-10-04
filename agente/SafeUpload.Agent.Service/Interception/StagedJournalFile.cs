using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SafeUpload.Agent.Service.Interception;

// Validate the object actually opened, then use that same handle for reading
// and ACL recovery. Protected ancestors remain the admission prerequisite.
internal static class StagedJournalFile
{
    internal const int MaximumManifestBytes = 128 * 1024;

    public static FileStream Open(string path, bool recoverAcl = false, bool writable = false, int maximumBytes = MaximumManifestBytes)
    {
        if (!OperatingSystem.IsWindows())
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Journal contains a reparse point.");
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
            writable ? 1U : 5U, IntPtr.Zero, 3, 0x42200000U | (writable ? 0x80000000U : 0), IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = new Win32Exception(Marshal.GetLastWin32Error());
            handle.Dispose();
            throw error.NativeErrorCode switch
            {
                2 => new FileNotFoundException("Journal manifest not found.", path),
                3 => new DirectoryNotFoundException("Journal directory not found."),
                5 => new UnauthorizedAccessException("Journal manifest access denied.", error),
                _ => new IOException("Could not open journal manifest.", error)
            };
        }
        try
        {
            if (!GetFileInformationByHandle(handle, out var information))
                throw new IOException("Could not identify journal manifest.",
                    new Win32Exception(Marshal.GetLastWin32Error()));
            if ((information.Attributes & 0x410) != 0 || information.LinkCount != 1)
                throw new IOException("Journal manifest must be a regular file with exactly one link.");
            var stream = new FileStream(handle, writable ? FileAccess.ReadWrite : FileAccess.Read, 4096, isAsync: true);
            try { RequireBound(stream, maximumBytes); return stream; }
            catch { stream.Dispose(); throw; }
        }
        catch { handle.Dispose(); throw; }
    }

    private static void RequireBound(FileStream stream, int maximumBytes)
    {
        if (stream.Length > maximumBytes)
            throw new InvalidDataException("Journal manifest exceeds the qualified size bound.");
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
