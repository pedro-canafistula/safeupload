namespace SafeUpload.Agent.Core.Infrastructure;

/// <summary>Owns one captured file handle and never reads beyond its initial length.</summary>
internal sealed class AuditQueueReadWindow(FileStream source, long capturedLength) : Stream
{
    private long _remaining = capturedLength;
    public long CapturedLength { get; } = capturedLength;
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => CapturedLength;
    public override long Position { get => CapturedLength - _remaining; set => throw new NotSupportedException(); }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
    public override int Read(Span<byte> buffer)
    {
        int count = (int)Math.Min(_remaining, buffer.Length);
        return count == 0 ? 0 : Observe(source.Read(buffer[..count]));
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        int count = (int)Math.Min(_remaining, buffer.Length);
        return count == 0 ? 0 : Observe(await source.ReadAsync(buffer[..count], cancellationToken).ConfigureAwait(false));
    }

    private int Observe(int read)
    {
        if (read == 0) throw new IOException("Captured audit queue was truncated during the scan.");
        _remaining -= read;
        return read;
    }

    public override void Flush() => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    protected override void Dispose(bool disposing)
    {
        if (disposing) source.Dispose();
        base.Dispose(disposing);
    }
    public override async ValueTask DisposeAsync()
    {
        await source.DisposeAsync().ConfigureAwait(false);
        GC.SuppressFinalize(this);
    }
}
