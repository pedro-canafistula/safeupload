namespace SafeUpload.Agent.Network.Proxy;

/// <summary>
/// Fluxo que devolve primeiro alguns bytes já lidos e depois continua no fluxo
/// original.
///
/// Serve à passagem do CONNECT para o TLS: se o navegador mandou o início do
/// handshake no mesmo pacote do CONNECT, esses bytes já estão no buffer do
/// leitor HTTP, e o SslStream precisa recebê-los antes do resto da conexão.
/// </summary>
internal sealed class PrefixedStream(byte[] prefix, Stream inner) : Stream
{
    private int _offset;

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => inner.CanWrite;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override int Read(byte[] buffer, int offset, int count) =>
        Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        if (_offset < prefix.Length)
        {
            int take = Math.Min(buffer.Length, prefix.Length - _offset);
            prefix.AsSpan(_offset, take).CopyTo(buffer);
            _offset += take;
            return take;
        }

        return inner.Read(buffer);
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (_offset < prefix.Length)
        {
            return Read(buffer.Span);
        }

        return await inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
        inner.WriteAsync(buffer, cancellationToken);

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        inner.WriteAsync(buffer, offset, count, cancellationToken);

    public override void Flush() => inner.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            inner.Dispose();
        }

        base.Dispose(disposing);
    }
}
