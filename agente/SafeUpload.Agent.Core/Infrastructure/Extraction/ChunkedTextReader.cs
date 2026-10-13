namespace SafeUpload.Agent.Core.Infrastructure.Extraction;

// The iterator owns its current chunk until the next MoveNext. XML chunks can
// therefore reuse one fixed buffer without copying an entire value or document.
internal sealed class ChunkedTextReader : TextReader
{
    private readonly IEnumerator<ReadOnlyMemory<char>> _chunks;
    private ReadOnlyMemory<char> _current;
    private CancellationToken _token;
    private int _lookahead = -2;
    private bool _disposed;

    public ChunkedTextReader(Func<Func<CancellationToken>, IEnumerable<ReadOnlyMemory<char>>> chunks)
        => _chunks = chunks(() => _token).GetEnumerator();

    public override ValueTask<int> ReadAsync(Memory<char> buffer, CancellationToken token = default)
        => ValueTask.FromResult(Fill(buffer.Span, token));
    public override int Read(Span<char> buffer) => Fill(buffer, CancellationToken.None);
    public override int Read(char[] buffer, int index, int count)
    { ArgumentNullException.ThrowIfNull(buffer); return Fill(buffer.AsSpan(index, count), CancellationToken.None); }
    public override int Read()
    { Span<char> one = stackalloc char[1]; return Fill(one, CancellationToken.None) == 0 ? -1 : one[0]; }
    public override int Peek()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_lookahead == -2)
        { Span<char> one = stackalloc char[1]; _lookahead = Fill(one, CancellationToken.None) == 0 ? -1 : one[0]; }
        return _lookahead;
    }
    private int Fill(Span<char> buffer, CancellationToken token)
    {
        ObjectDisposedException.ThrowIf(_disposed, this); token.ThrowIfCancellationRequested(); _token = token;
        if (buffer.IsEmpty || _lookahead == -1) return 0;
        int written = 0;
        if (_lookahead >= 0) { buffer[written++] = (char)_lookahead; _lookahead = -2; }
        while (written < buffer.Length)
        {
            token.ThrowIfCancellationRequested();
            if (_current.IsEmpty)
            {
                if (!_chunks.MoveNext()) break;
                _current = _chunks.Current; continue;
            }
            int count = Math.Min(buffer.Length - written, _current.Length);
            _current.Span[..count].CopyTo(buffer[written..]);
            _current = _current[count..]; written += count;
        }
        return written;
    }
    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed) { _disposed = true; _chunks.Dispose(); _current = default; }
        base.Dispose(disposing);
    }
}
