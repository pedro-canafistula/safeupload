namespace SafeUpload.Agent.Core.Infrastructure.Extraction;

/// <summary>Replays complete small extractions within one inspection; larger texts reopen the extractor.</summary>
internal sealed class BoundedTextReplay(Func<Task<TextReader>> open, int maximumCharacters) : IDisposable
{
    private readonly char[] _text = new char[maximumCharacters > 0 ? maximumCharacters
        : throw new ArgumentOutOfRangeException(nameof(maximumCharacters))];
    private int _length;
    private bool _started, _complete, _disabled, _disposed;

    internal async Task<TextReader> OpenAsync()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_complete) return new ReplayReader(this);
        TextReader reader = await open().ConfigureAwait(false);
        if (_started || _disabled) return reader;
        _started = true;
        return new CaptureReader(this, reader);
    }

    private void Capture(ReadOnlySpan<char> value)
    {
        if (_disabled) return;
        if (value.Length > _text.Length - _length) { Disable(); return; }
        value.CopyTo(_text.AsSpan(_length));
        _length += value.Length;
    }

    private void Disable()
    {
        Array.Clear(_text);
        _length = 0;
        _complete = false;
        _disabled = true;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Disable();
    }

    private sealed class CaptureReader(BoundedTextReplay owner, TextReader inner) : TextReader
    {
        public override Task<int> ReadAsync(char[] buffer, int index, int count)
            => ReadAsync(buffer.AsMemory(index, count)).AsTask();
        public override int Read(char[] buffer, int index, int count) => Read(buffer.AsSpan(index, count));
        public override int Read()
        { Span<char> value = stackalloc char[1]; return Read(value) == 0 ? -1 : value[0]; }
        public override int Peek() => inner.Peek();
        public override async ValueTask<int> ReadAsync(Memory<char> buffer, CancellationToken token = default)
        {
            ObjectDisposedException.ThrowIf(owner._disposed, this);
            token.ThrowIfCancellationRequested();
            int count = await inner.ReadAsync(buffer, token).ConfigureAwait(false);
            if (!buffer.IsEmpty)
            {
                owner.Capture(buffer.Span[..count]);
                if (count == 0 && !owner._disabled) owner._complete = true;
            }
            return count;
        }
        public override int Read(Span<char> buffer)
        {
            ObjectDisposedException.ThrowIf(owner._disposed, this);
            int count = inner.Read(buffer);
            if (!buffer.IsEmpty)
            {
                owner.Capture(buffer[..count]);
                if (count == 0 && !owner._disabled) owner._complete = true;
            }
            return count;
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (!owner._complete) owner.Disable();
                inner.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    private sealed class ReplayReader(BoundedTextReplay owner) : TextReader
    {
        private int _position;
        private bool _disposed;
        public override Task<int> ReadAsync(char[] buffer, int index, int count)
            => ReadAsync(buffer.AsMemory(index, count)).AsTask();
        public override int Read(char[] buffer, int index, int count) => Read(buffer.AsSpan(index, count));
        public override int Read()
        { Span<char> value = stackalloc char[1]; return Read(value) == 0 ? -1 : value[0]; }
        public override int Peek()
        {
            ObjectDisposedException.ThrowIf(_disposed || owner._disposed, this);
            return _position == owner._length ? -1 : owner._text[_position];
        }
        public override ValueTask<int> ReadAsync(Memory<char> buffer, CancellationToken token = default)
        { token.ThrowIfCancellationRequested(); return ValueTask.FromResult(Read(buffer.Span)); }
        public override int Read(Span<char> buffer)
        {
            ObjectDisposedException.ThrowIf(_disposed || owner._disposed, this);
            int count = Math.Min(buffer.Length, owner._length - _position);
            owner._text.AsSpan(_position, count).CopyTo(buffer);
            _position += count;
            return count;
        }
        protected override void Dispose(bool disposing) { if (disposing) _disposed = true; base.Dispose(disposing); }
    }
}
