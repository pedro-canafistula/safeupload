using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class StagedSnapshotCopyTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(65536)]
    [InlineData(65537)]
    public async Task Exact_snapshot_copy_reads_every_measured_byte_and_rewinds_the_source(int length)
    {
        byte[] original = Enumerable.Range(0, length).Select(i => (byte)(i % 251)).ToArray();
        using var source = new MemoryStream(original, writable: false);
        using var target = new MemoryStream();
        await StagedSnapshotCopy.CopyAsync(source, target, length, CancellationToken.None);
        Assert.Equal(original, target.ToArray()); Assert.Equal(0, source.Position);
    }

    [Fact]
    public async Task Late_source_growth_never_copies_bytes_beyond_the_measured_snapshot_budget()
    {
        const int measured = 128 * 1024;
        using var source = new ChangingSource(measured, measured * 64);
        using var target = new MemoryStream();
        await Assert.ThrowsAsync<IOException>(() => StagedSnapshotCopy.CopyAsync(source, target, measured, CancellationToken.None));
        Assert.Equal((long)measured, target.Length); Assert.Equal((long)measured, source.BytesRead);
    }

    [Fact]
    public async Task Early_eof_and_initial_length_mismatch_are_incomplete_capture_failures()
    {
        using var source = new ChangingSource(128 * 1024, 64 * 1024);
        using var target = new MemoryStream();
        await Assert.ThrowsAsync<EndOfStreamException>(() => StagedSnapshotCopy.CopyAsync(source, target, 128 * 1024, CancellationToken.None));
        Assert.Equal(64L * 1024, target.Length);
        using var mismatch = new MemoryStream(new byte[2], writable: false);
        using var emptyTarget = new MemoryStream();
        await Assert.ThrowsAsync<IOException>(() => StagedSnapshotCopy.CopyAsync(mismatch, emptyTarget, 1, CancellationToken.None));
        Assert.Equal(0, emptyTarget.Length); Assert.Equal(0, mismatch.Position);
    }

    [Fact]
    public async Task Caller_cancellation_does_not_copy_a_partial_snapshot()
    {
        using var source = new MemoryStream(new byte[1024], writable: false);
        using var target = new MemoryStream(); using var canceled = new CancellationTokenSource(); canceled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => StagedSnapshotCopy.CopyAsync(source, target, 1024, canceled.Token));
        Assert.Equal(0, target.Length);
    }

    private sealed class ChangingSource(long initialLength, long changedLength) : Stream
    {
        private bool _changed;
        private long _position;
        public long BytesRead { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => _changed ? changedLength : initialLength;
        public override long Position { get => _position; set => _position = value; }
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
        {
            token.ThrowIfCancellationRequested();
            int count = (int)Math.Min(buffer.Length, Math.Max(0, Length - _position));
            buffer.Span[..count].Fill(42); _position += count; BytesRead += count; _changed = true;
            return ValueTask.FromResult(count);
        }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
