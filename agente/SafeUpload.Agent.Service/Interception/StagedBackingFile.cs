using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SafeUpload.Agent.Service.Interception;

// The upper stream owns the only writable data cache. Seeding its backing
// with cached FileStream writes leaves a second NTFS cache which paging writes
// do not invalidate. Use aligned, noncached writes from the first byte onward.
internal static class StagedBackingFile
{
    public static async Task<StagedStageIdentity> CreateAsync(string? source, string destination, long maximumBytes,
        CancellationToken token, string? metadataSource = null, bool preserveCreation = true)
    {
        token.ThrowIfCancellationRequested();
        using StagedStageFile? heldSource = source is null ? null : StagedStageFile.Open(source);
        var metadata = heldSource is not null ? StagedFileMetadata.Capture(heldSource.Stream.SafeFileHandle) :
            metadataSource is null ? null : StagedFileMetadata.CapturePath(metadataSource);
        if (metadata is not null && (metadata.Attributes & 1) != 0)
            throw new StagedMetadataException("metadata_readonly_destination");
        // Truncation retains the old creation date, but has a new write date.
        if (metadata is not null && source is null)
            metadata = preserveCreation ? metadata with { LastWriteTime = DateTime.UtcNow.ToFileTimeUtc(),
                Attributes = (metadata.Attributes & ~0x80u) | 0x20u } : null;
        return (await CreateCoreAsync(heldSource?.Stream, destination, maximumBytes, token, null,
            captureIdentity: true, metadata)
            .ConfigureAwait(false))!;
    }

    // The bound allocator supplies the already checked source FILE_OBJECT.
    // Borrow it through the durable allocation claim; never reopen its locator.
    internal static Task CreateFromHeldSourceAsync(FileStream? input, string destination,
        long maximumBytes, CancellationToken token, StagedStageIdentity? existingPrivateObject = null)
        => CreateCoreAsync(input, destination, maximumBytes, token, existingPrivateObject, captureIdentity: false);

    private static async Task<StagedStageIdentity?> CreateCoreAsync(FileStream? input, string destination,
        long maximumBytes, CancellationToken token, StagedStageIdentity? existingPrivateObject, bool captureIdentity,
        StagedFileMetadata? metadata = null)
    {
        using var backingTiming = StagedRequestTiming.Measure("backing");
        token.ThrowIfCancellationRequested();
        // Check on the held source handle before creating or writing output.
        // A streamed bound below also prevents growth from consuming more disk.
        if (input is not null && input.Length > maximumBytes)
            throw new IOException("The source exceeds the qualified private-version size limit.");
        using var output = CreateFile(destination, 0x40000088, 0, IntPtr.Zero, existingPrivateObject is null ? 1u : 3u,
            0xA0200080, IntPtr.Zero); // GENERIC_WRITE; CREATE_NEW or exact OPEN_EXISTING; NO_BUFFERING | WRITE_THROUGH | OPEN_REPARSE_POINT
        if (output.IsInvalid) throw new IOException("Could not create private backing.", new Win32Exception());
        if (captureIdentity) _ = StagedFileMetadata.Capture(output); // inherited EFS/compression is unsupported too
        if (existingPrivateObject is not null && StagedDestinationFile.ReadIdentity(output) != existingPrivateObject)
            throw new IOException("The private seed target changed before copying.");
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
            metadata?.Apply(output);
        }
        finally { Marshal.FreeHGlobal(allocation); }
        return captureIdentity ? StagedDestinationFile.ReadIdentity(output) : null;
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
