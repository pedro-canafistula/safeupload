using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SafeUpload.Agent.Service.Interception;

// The upper stream owns the only writable data cache. Seeding its backing
// with cached FileStream writes leaves a second NTFS cache which paging writes
// do not invalidate. Use aligned, noncached writes from the first byte onward.
internal static class StagedBackingFile
{
    public static async Task CreateAsync(string? source, string destination, long maximumBytes, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        await using var input = source is null ? null : new FileStream(source,
            FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        // Check on the held source handle before creating or writing output.
        // A streamed bound below also prevents growth from consuming more disk.
        if (input is not null && input.Length > maximumBytes)
            throw new IOException("The source exceeds the qualified private-version size limit.");
        using var output = CreateFile(destination, 0x40000000, 0, IntPtr.Zero, 1,
            0xA0000080, IntPtr.Zero); // GENERIC_WRITE, CREATE_NEW, NO_BUFFERING | WRITE_THROUGH
        if (output.IsInvalid) throw new IOException("Could not create private backing.", new Win32Exception());
        const int blockSize = 64 * 1024; // multiple of every admitted sector size
        byte[] bytes = new byte[blockSize];
        IntPtr allocation = Marshal.AllocHGlobal(blockSize * 2);
        IntPtr aligned = new((allocation.ToInt64() + blockSize - 1) & ~(blockSize - 1L));
        long length = 0;
        try
        {
            if (input is not null)
            {
                for (;;)
                {
                    int count = await input.ReadAtLeastAsync(bytes, blockSize, false, token).ConfigureAwait(false);
                    if (count == 0) break;
                    if (count > maximumBytes - length)
                        throw new IOException("The source grew beyond the qualified private-version size limit.");
                    bytes.AsSpan(count).Clear();
                    Marshal.Copy(bytes, 0, aligned, blockSize);
                    if (!WriteFile(output, aligned, blockSize, out int written, IntPtr.Zero) || written != blockSize)
                        throw new IOException("Could not seed private backing.", new Win32Exception());
                    length = checked(length + count);
                }
            }
            token.ThrowIfCancellationRequested();
            // A noncached handle's byte offset must be sector aligned, but
            // FileEndOfFileInfo accepts the exact (possibly partial) length.
            if (!SetFileInformationByHandle(output, 6, ref length, sizeof(long)) || !FlushFileBuffers(output))
                throw new IOException("Could not durably finish private backing.", new Win32Exception());
        }
        finally { Marshal.FreeHGlobal(allocation); }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WriteFile(SafeFileHandle file, IntPtr buffer, int bytes,
        out int written, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle file, int informationClass,
        ref long endOfFile, int size);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FlushFileBuffers(SafeFileHandle file);
}
