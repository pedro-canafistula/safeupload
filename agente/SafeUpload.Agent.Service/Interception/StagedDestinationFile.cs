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
        CommitHandle(output.SafeFileHandle, destination);
    }

    // Publication into a protected destination is written without the cache. A cached
    // write is persisted by paging writes, which the driver refuses for every tracked
    // stream inside a protected scope (run c01l: the service's own approved bytes were
    // denied at the write-through flush). Non-cached writes arrive on the permitted handle.
    private const int UnbufferedAlignment = 4096;
    private const int UnbufferedChunk = 1 << 20;

    public static SafeFileHandle CreateUnbuffered(string path)
    {
        if (!OperatingSystem.IsWindows())
            return File.OpenHandle(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);

        var handle = CreateFile(path, 0x40010000, 0, IntPtr.Zero, 1,
            0xA0000080, IntPtr.Zero); // GENERIC_WRITE | DELETE, CREATE_NEW, NO_BUFFERING | WRITE_THROUGH
        if (handle.IsInvalid)
        {
            var error = new Win32Exception(Marshal.GetLastWin32Error());
            handle.Dispose();
            throw new IOException("Could not create approved publication file.", error);
        }
        return handle;
    }

    public static async Task<long> WriteUnbufferedAsync(SafeFileHandle output, Stream source,
        CancellationToken token)
    {
        // Sector-aligned offsets, lengths and buffer address; the tail is zero-padded to the
        // alignment and then cut back to the exact length before the flush.
        byte[] raw = GC.AllocateUninitializedArray<byte>(UnbufferedChunk + UnbufferedAlignment, pinned: true);
        long address = Marshal.UnsafeAddrOfPinnedArrayElement(raw, 0).ToInt64();
        int start = (int)((UnbufferedAlignment - address % UnbufferedAlignment) % UnbufferedAlignment);
        Memory<byte> buffer = raw.AsMemory(start, UnbufferedChunk);
        long length = 0;
        while (true)
        {
            int filled = 0;
            while (filled < UnbufferedChunk)
            {
                int read = await source.ReadAsync(buffer[filled..], token).ConfigureAwait(false);
                if (read == 0) break;
                filled += read;
            }
            if (filled == 0) break;
            int aligned = (filled + UnbufferedAlignment - 1) / UnbufferedAlignment * UnbufferedAlignment;
            buffer.Span[filled..aligned].Clear();
            RandomAccess.Write(output, buffer.Span[..aligned], length);
            length += filled;
            if (filled < UnbufferedChunk) break;
        }
        RandomAccess.SetLength(output, length);
        if (OperatingSystem.IsWindows() && !FlushFileBuffers(output))
            throw new IOException("Could not flush the approved publication file.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        return length;
    }

    // Best effort before the handle closes: an uncommitted publication temporary is removed
    // through the handle that created it (its name's publication permit is already spent).
    public static void TryDeleteUncommitted(SafeFileHandle output)
    {
        if (!OperatingSystem.IsWindows() || output.IsInvalid || output.IsClosed) return;
        _ = SetFileInformationByHandle(output, 4, [1], 1); // FileDispositionInfo: DeleteFile = TRUE
    }

    public static void CommitHandle(SafeFileHandle output, string destination)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Handle-based publication commit requires Windows.");
        byte[] name = Encoding.Unicode.GetBytes(Path.GetFullPath(destination));
        int offset = IntPtr.Size == 8 ? 20 : 12;
        byte[] buffer = new byte[checked(offset + name.Length + sizeof(char))];
        BitConverter.GetBytes(3U).CopyTo(buffer, 0); // REPLACE_IF_EXISTS | POSIX_SEMANTICS
        BitConverter.GetBytes(name.Length).CopyTo(buffer, offset - sizeof(uint));
        name.CopyTo(buffer, offset);
        if (!SetFileInformationByHandle(output, 22, buffer, buffer.Length))
            throw new IOException("Could not replace the destination entry.",
                new Win32Exception(Marshal.GetLastWin32Error()));
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FlushFileBuffers(SafeFileHandle file);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle file,
        int informationClass, byte[] buffer, int size);
}
