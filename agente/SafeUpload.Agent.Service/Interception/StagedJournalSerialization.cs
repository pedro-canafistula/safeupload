using System.Text.Json;
namespace SafeUpload.Agent.Service.Interception;
internal static class StagedJournalSerialization
{
    internal static Task SerializeAsync<T>(Stream output, T value, CancellationToken token)
        => JsonSerializer.SerializeAsync(new BoundedOutput(output), value, cancellationToken: token);
    private sealed class BoundedOutput(Stream output) : Stream
    {
        private long _written;
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => _written;
        public override long Position { get => _written; set => throw new NotSupportedException(); }
        private void Charge(int bytes)
        {
            if (bytes > StagedJournalFile.MaximumManifestBytes - _written)
                throw new InvalidDataException("Journal manifest exceeds the qualified size bound.");
            _written += bytes;
        }
        public override void Write(byte[] buffer, int offset, int count) { Charge(count); output.Write(buffer, offset, count); }
        public override void Write(ReadOnlySpan<byte> buffer) { Charge(buffer.Length); output.Write(buffer); }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken token = default)
        { Charge(buffer.Length); return output.WriteAsync(buffer, token); }
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken token)
        { Charge(count); return output.WriteAsync(buffer, offset, count, token); }
        public override void Flush() => output.Flush();
        public override Task FlushAsync(CancellationToken token) => output.FlushAsync(token);
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
