using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.Tests;

public sealed class BoundedTextReplayTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(8192)]
    public async Task Complete_replay_keeps_all_detector_precedence_and_masks_with_one_extraction(int chunk)
    {
        const string text = "529.982.247-25 11222333000181 4111111111111111 password: abcde AKIA1234567890ABCDEF";
        int opened = 0, disposed = 0;
        using var replay = new BoundedTextReplay(() =>
        {
            opened++;
            return Task.FromResult<TextReader>(new Fragmented(text, chunk, () => disposed++));
        }, 1024);
        var categories = Enum.GetValues<Category>().ToHashSet();
        var findings = await StreamingContentScanner.ScanAsync(replay.OpenAsync, categories, CancellationToken.None);
        Assert.Equal(ContentScanner.Scan(text, categories), findings);
        Assert.Equal(1, opened);
        Assert.Equal(1, disposed);
        using var scalar = await replay.OpenAsync();
        Assert.Equal((int)'5', scalar.Peek());
        Assert.Equal((int)'5', scalar.Read());
        Assert.Equal(text[1..], scalar.ReadToEnd());
        Assert.Equal(-1, scalar.Peek());
    }

    [Theory]
    [InlineData(31)]
    [InlineData(32)]
    [InlineData(33)]
    public async Task Capacity_boundary_and_overflow_never_truncate_or_partially_replay_text(int length)
    {
        string text = new('x', length);
        int opened = 0;
        using var replay = new BoundedTextReplay(() => { opened++; return Task.FromResult<TextReader>(new StringReader(text)); }, 32);
        for (int pass = 0; pass < 3; pass++)
        {
            using var reader = await replay.OpenAsync();
            Assert.Equal(text, await reader.ReadToEndAsync());
        }
        Assert.Equal(length > 32 ? 3 : 1, opened);
    }

    [Fact]
    public async Task Abandoned_capture_reopens_the_full_source_without_serving_its_prefix()
    {
        int opened = 0;
        using var replay = new BoundedTextReplay(() => { opened++; return Task.FromResult<TextReader>(new StringReader("full secret tail")); }, 32);
        using (var first = await replay.OpenAsync()) Assert.Equal((int)'f', first.Read());
        using var retry = await replay.OpenAsync();
        Assert.Equal("full secret tail", await retry.ReadToEndAsync());
        Assert.Equal(2, opened);
    }

    [Fact]
    public async Task A_late_extraction_failure_cannot_turn_captured_sensitive_text_into_a_complete_scan()
    {
        int opened = 0;
        using var replay = new BoundedTextReplay(() => { opened++; return Task.FromResult<TextReader>(new LateFailure()); }, 1024);
        await Assert.ThrowsAsync<InvalidDataException>(() => StreamingContentScanner.ScanAsync(replay.OpenAsync,
            Enum.GetValues<Category>().ToHashSet(), CancellationToken.None));
        using var retry = await replay.OpenAsync();
        await Assert.ThrowsAsync<InvalidDataException>(() => retry.ReadToEndAsync());
        Assert.Equal(2, opened);
    }

    [Fact]
    public async Task Owner_disposal_invalidates_replay_and_cancellation_cannot_yield_a_partial_read()
    {
        var replay = new BoundedTextReplay(() => Task.FromResult<TextReader>(new StringReader("private text")), 32);
        using (var capture = await replay.OpenAsync()) Assert.Equal("private text", await capture.ReadToEndAsync());
        using var reader = await replay.OpenAsync();
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => reader.ReadAsync(new char[4].AsMemory(), canceled.Token).AsTask());
        Assert.Equal((int)'p', reader.Peek());
        replay.Dispose();
        Assert.Throws<ObjectDisposedException>(() => reader.Read());
        await Assert.ThrowsAsync<ObjectDisposedException>(() => replay.OpenAsync());
    }

    private sealed class Fragmented(string text, int chunk, Action disposed) : StringReader(text)
    {
        public override ValueTask<int> ReadAsync(Memory<char> buffer, CancellationToken token = default)
            => base.ReadAsync(buffer[..Math.Min(buffer.Length, chunk)], token);
        protected override void Dispose(bool disposing) { if (disposing) disposed(); base.Dispose(disposing); }
    }

    private sealed class LateFailure : TextReader
    {
        private bool _first = true;
        public override Task<int> ReadAsync(char[] buffer, int index, int count)
            => ReadAsync(buffer.AsMemory(index, count)).AsTask();
        public override ValueTask<int> ReadAsync(Memory<char> buffer, CancellationToken token = default)
        {
            if (!_first) throw new InvalidDataException("Late extraction failure.");
            _first = false;
            const string prefix = "CPF: 529.982.247-25";
            prefix.AsSpan().CopyTo(buffer.Span);
            return ValueTask.FromResult(prefix.Length);
        }
    }
}
