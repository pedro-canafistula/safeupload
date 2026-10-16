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
    private IDisposable? _budgetLifetime;
    private int _references = 1;
    private int _disposed;

    private StagedInspectionSnapshot(string path, FileStream stream, string digest)
        => (Path, Stream, Digest) = (path, stream, digest);

    internal static async Task<StagedInspectionSnapshot> CreateAsync(FileStream source,
        string root, string extension, long expectedLength, CancellationToken token,
        StagedSpaceBudget? spaceBudget = null, Guid transferId = default)
    {
        string path = System.IO.Path.Combine(root, Guid.NewGuid().ToString("N") + ".inspection" + extension);
        // Duplicates share one file object: only one asynchronous completion
        // port can bind it. Use synchronous native handles; .NET's FileStream
        // still supplies async calls and tracks explicit offsets per stream.
        var captured = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None,
            64 * 1024, FileOptions.WriteThrough | FileOptions.DeleteOnClose);
        FileStream? read = null;
        IDisposable? budgetLifetime = null;
        try
        {
            budgetLifetime = spaceBudget?.BeginSnapshot(transferId, path, captured, expectedLength);
            await StagedSnapshotCopy.CopyAsync(source, captured, expectedLength, token).ConfigureAwait(false);
            captured.Flush(flushToDisk: true);
            captured.Position = 0;
            string digest = Convert.ToHexString(await SHA256.HashDataAsync(captured, token).ConfigureAwait(false));
            captured.Position = 0;
            read = DuplicateRead(captured);
            await captured.DisposeAsync().ConfigureAwait(false);
            return new(path, read, digest) { _budgetLifetime = budgetLifetime };
        }
        catch
        {
            if (read is not null) await read.DisposeAsync().ConfigureAwait(false);
            await captured.DisposeAsync().ConfigureAwait(false);
            budgetLifetime?.Dispose();
            throw;
        }
    }

    // Duplicate the held object with read rights only. This performs no name
    // lookup, admits no external writer and outlives the publisher if a parser
    // ignores cancellation. Delete-on-close waits for this handle too.
    internal Stream OpenRead()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        Interlocked.Increment(ref _references);
        try { return new ReadLease(DuplicateRead(Stream), ReleaseReference); }
        catch { ReleaseReference(); throw; }
    }

    private void ReleaseReference()
    {
        if (Interlocked.Decrement(ref _references) == 0)
            Interlocked.Exchange(ref _budgetLifetime, null)?.Dispose();
    }

    internal sealed class ReadLease(Stream input, Action release) : Stream
    {
        internal SafeFileHandle Handle => ((FileStream)input).SafeFileHandle;
        private Action? _release = release;
        public override bool CanRead => input.CanRead;
        public override bool CanSeek => input.CanSeek;
        public override bool CanWrite => false;
        public override long Length => input.Length;
        public override long Position { get => input.Position; set => input.Position = value; }
        public override int Read(byte[] buffer, int offset, int count) => input.Read(buffer, offset, count);
        public override int Read(Span<byte> buffer) => input.Read(buffer);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default) => input.ReadAsync(buffer, token);
        public override long Seek(long offset, SeekOrigin origin) => input.Seek(offset, origin);
        public override void Flush() => input.Flush();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing)
        {
            if (disposing) { try { input.Dispose(); } finally { Interlocked.Exchange(ref _release, null)?.Invoke(); } }
            base.Dispose(disposing);
        }
        public override async ValueTask DisposeAsync()
        {
            try { await input.DisposeAsync().ConfigureAwait(false); }
            finally { Interlocked.Exchange(ref _release, null)?.Invoke(); }
            GC.SuppressFinalize(this);
        }
    }

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

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        try { await Stream.DisposeAsync().ConfigureAwait(false); }
        finally { ReleaseReference(); }
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(IntPtr sourceProcess, SafeFileHandle source,
        IntPtr targetProcess, out SafeFileHandle target, uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inherit, uint options);
}
