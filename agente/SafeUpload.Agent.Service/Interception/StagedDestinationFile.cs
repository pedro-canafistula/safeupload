using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace SafeUpload.Agent.Service.Interception;

// One exclusively held public temporary, containing only inspected bytes, is
// flushed and renamed on that same handle. POSIX replacement preserves existing
// readers of the old destination instead of failing intermittently while source
// classification or a sync reader has it open. The journal uses the same
// operation to replace manifests pinned by readers. Unsupported stacks fail closed.
internal static class StagedDestinationFile
{
    public static FileStream Create(string path)
    {
        if (!OperatingSystem.IsWindows())
            return new(path, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                64 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough);

        var handle = CreateFile(path, 0x40010000, 0, IntPtr.Zero, 1,
            0xC0000080, IntPtr.Zero); // GENERIC_WRITE | DELETE, CREATE_NEW, OVERLAPPED | WRITE_THROUGH
        if (handle.IsInvalid)
        {
            var error = new Win32Exception(Marshal.GetLastWin32Error());
            handle.Dispose();
            throw new IOException("Could not create approved publication file.", error);
        }
        try { return new FileStream(handle, FileAccess.Write, 64 * 1024, isAsync: true); }
        catch { handle.Dispose(); throw; }
    }

    public static void Commit(FileStream output, string temporary, string destination)
    {
        output.Flush(flushToDisk: true);
        if (!OperatingSystem.IsWindows())
        {
            File.Move(temporary, destination, overwrite: true);
            return;
        }

        byte[] name = Encoding.Unicode.GetBytes(Path.GetFullPath(destination));
        int offset = IntPtr.Size == 8 ? 20 : 12;
        byte[] buffer = new byte[checked(offset + name.Length + sizeof(char))];
        BitConverter.GetBytes(3U).CopyTo(buffer, 0); // REPLACE_IF_EXISTS | POSIX_SEMANTICS
        BitConverter.GetBytes(name.Length).CopyTo(buffer, offset - sizeof(uint));
        name.CopyTo(buffer, offset);
        if (!SetFileInformationByHandle(output.SafeFileHandle, 22, buffer, buffer.Length))
            throw new IOException("Could not replace the destination entry.",
                new Win32Exception(Marshal.GetLastWin32Error()));
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle file,
        int informationClass, byte[] buffer, int size);
}
