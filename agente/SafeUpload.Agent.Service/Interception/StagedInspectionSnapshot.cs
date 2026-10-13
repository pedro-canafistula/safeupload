using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace SafeUpload.Agent.Service.Interception;

/// <summary>A private temporary file whose lifetime follows its exact open handles.</summary>
internal sealed class StagedInspectionSnapshot : IAsyncDisposable
{
    public string Path { get; }
    public FileStream Stream { get; }
    public string Digest { get; }

    private StagedInspectionSnapshot(string path, FileStream stream, string digest)
        => (Path, Stream, Digest) = (path, stream, digest);

    internal static async Task<StagedInspectionSnapshot> CreateAsync(FileStream source,
        string root, string extension, long expectedLength, CancellationToken token)
    {
        string path = System.IO.Path.Combine(root, Guid.NewGuid().ToString("N") + ".inspection" + extension);
        // Duplicates share one file object: only one asynchronous completion
        // port can bind it. Use synchronous native handles; .NET's FileStream
        // still supplies async calls and tracks explicit offsets per stream.
        var captured = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None,
            64 * 1024, FileOptions.WriteThrough | FileOptions.DeleteOnClose);
        FileStream? read = null;
        try
        {
            await StagedSnapshotCopy.CopyAsync(source, captured, expectedLength, token).ConfigureAwait(false);
            captured.Flush(flushToDisk: true);
            captured.Position = 0;
            string digest = Convert.ToHexString(await SHA256.HashDataAsync(captured, token).ConfigureAwait(false));
            captured.Position = 0;
            read = DuplicateRead(captured);
            await captured.DisposeAsync().ConfigureAwait(false);
            return new(path, read, digest);
        }
        catch
        {
            if (read is not null) await read.DisposeAsync().ConfigureAwait(false);
            await captured.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    // Duplicate the held object with read rights only. This performs no name
    // lookup, admits no external writer and outlives the publisher if a parser
    // ignores cancellation. Delete-on-close waits for this handle too.
    internal Stream OpenRead() => DuplicateRead(Stream);

    private static FileStream DuplicateRead(FileStream source)
    {
        const uint FileGenericRead = 0x00120089;
        IntPtr process = GetCurrentProcess();
        if (!DuplicateHandle(process, source.SafeFileHandle, process, out SafeFileHandle read,
            FileGenericRead, false, 0))
        {
            int error = Marshal.GetLastWin32Error();
            read?.Dispose();
            throw new IOException("The held inspection snapshot could not supply a read lease.", new Win32Exception(error));
        }
        try { return new FileStream(read, FileAccess.Read, 64 * 1024, isAsync: false); }
        catch { read.Dispose(); throw; }
    }

    public ValueTask DisposeAsync() => Stream.DisposeAsync();

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(IntPtr sourceProcess, SafeFileHandle source,
        IntPtr targetProcess, out SafeFileHandle target, uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inherit, uint options);
}
