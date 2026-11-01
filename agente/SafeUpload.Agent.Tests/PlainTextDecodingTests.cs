using System.Text;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.Tests;

public sealed class PlainTextDecodingTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();

    public static IEnumerable<object[]> ValidEncodings()
    {
        foreach (string encoding in new[] { "utf8", "utf8-bom", "utf16-le", "utf16-be", "utf32-le", "utf32-be" })
        {
            yield return [encoding, false];
            yield return [encoding, true];
        }
    }

    [Theory]
    [MemberData(nameof(ValidEncodings))]
    public async Task Valid_unicode_is_preserved_through_fragmented_reads_including_cpf_at_eof(
        string name, bool nonseekable)
    {
        const string text = "ação 😊\nCPF: 529.982.247-25";
        Encoding encoding = name switch
        {
            "utf8" => new UTF8Encoding(false, true),
            "utf8-bom" => new UTF8Encoding(true, true),
            "utf16-le" => new UnicodeEncoding(false, true, true),
            "utf16-be" => new UnicodeEncoding(true, true, true),
            "utf32-le" => new UTF32Encoding(false, true, true),
            "utf32-be" => new UTF32Encoding(true, true, true),
            _ => throw new ArgumentException(name)
        };
        byte[] bytes = [.. encoding.GetPreamble(), .. encoding.GetBytes(text)];
        using var content = new FragmentedStream(bytes, nonseekable);
        Assert.Equal(!nonseekable, content.CanSeek);

        string extracted = await new PlainTextExtractor().ExtractAsync(content, CancellationToken.None);

        Assert.Equal(text, extracted);
        Assert.Equal(Category.Cpf, Assert.Single(ContentScanner.Scan(extracted, new HashSet<Category> { Category.Cpf })).Category);
        Assert.False(content.Disposed);
        Assert.Equal(0, await content.ReadAsync(new byte[1]));
    }

    [Theory]
    [InlineData("")]
    [InlineData("x")]
    [InlineData("xy")]
    [InlineData("xyz")]
    [InlineData("xyzw")]
    public async Task Short_bomless_inputs_lose_no_prefix_bytes(string text)
    {
        using var content = new FragmentedStream(Encoding.UTF8.GetBytes(text), nonseekable: true);
        Assert.Equal(text, await new PlainTextExtractor().ExtractAsync(content, CancellationToken.None));
        Assert.False(content.Disposed);
    }

    public static IEnumerable<object[]> MalformedEncodings()
    {
        // Overlong/truncated UTF-8, unpaired UTF-16 surrogates/odd length,
        // UTF-32 surrogate/out-of-range scalar/truncated code unit. Include
        // BOM-switch cases that a permissive StreamReader silently replaces.
        foreach (string hex in new[]
        {
            "C0AF", "78E2", "EFBBBF78F0808080",
            "FFFE00D8", "FEFFD800", "FFFE78",
            "FFFE000000D80000", "0000FEFF00110000", "FFFE000078"
        })
        {
            yield return [hex, false];
            yield return [hex, true];
        }
    }

    [Theory]
    [MemberData(nameof(MalformedEncodings))]
    public async Task Malformed_text_fails_extraction_and_blocks_staged_inspection_without_a_cached_approval(
        string hex, bool staged)
    {
        byte[] bytes = Convert.FromHexString(hex);
        using (var content = new FragmentedStream(bytes, nonseekable: true))
        {
            await Assert.ThrowsAsync<DecoderFallbackException>(() =>
                new PlainTextExtractor().ExtractAsync(content, CancellationToken.None));
            Assert.False(content.Disposed);
        }
        string path = Path.Combine(_workspace.Root, "invalid.txt");
        await File.WriteAllBytesAsync(path, bytes);
        var policy = LocalPolicyStore.CreateStagedDefault() with { Version = 9 };
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        var service = new InspectionService(new FixedPolicyStore(policy), sink,
            new ExtractorRegistry([new PlainTextExtractor()]), new VerdictCache());
        var operation = TestWorkspace.Operation(path);
        for (int inspection = 0; inspection < 2; inspection++)
        {
            var result = staged
                ? await service.InspectStagedAsync(operation, CancellationToken.None)
                : await service.InspectAsync(operation, CancellationToken.None);
            Assert.Equal(staged ? Verdict.Blocked : Verdict.AllowedWithoutInspection, result.Verdict);
            Assert.Equal("parse_error:DecoderFallbackException", result.Reason);
            Assert.Equal(9, result.PolicyVersion);
            Assert.True(result.InScope);
            Assert.False(result.FromCache);
            Assert.Empty(result.Findings);
            Assert.False(await service.IsCurrentStagedApprovalAsync(operation, result, CancellationToken.None));
        }
        Assert.Equal(bytes, await File.ReadAllBytesAsync(path));
        Assert.Equal(staged ? 0 : 2, (await sink.ReadRecentAsync(10, CancellationToken.None)).Count);
    }

    [Fact]
    public async Task Cancellation_propagates_before_decoding_and_leaves_the_input_open()
    {
        using var content = new FragmentedStream(Encoding.UTF8.GetBytes("unchanged"), nonseekable: true);
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new PlainTextExtractor().ExtractAsync(content, cancelled.Token));
        Assert.False(content.Disposed);
        Assert.Equal((int)'u', content.ReadByte());
    }

    private sealed class FixedPolicyStore(Policy policy) : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken token) => Task.FromResult(policy);
        public Task<Policy> LoadCurrentAsync(CancellationToken token) => LoadAsync(token);
    }

    // One byte per read splits every BOM and multibyte code point. A
    // nonseekable input also proves that prefix detection does not rewind it.
    private sealed class FragmentedStream(byte[] bytes, bool nonseekable) : Stream
    {
        private readonly MemoryStream _input = new(bytes, writable: false);
        public bool Disposed { get; private set; }
        public override bool CanRead => _input.CanRead;
        public override bool CanSeek => !nonseekable;
        public override bool CanWrite => false;
        public override long Length => nonseekable ? throw new NotSupportedException() : _input.Length;
        public override long Position
        {
            get => nonseekable ? throw new NotSupportedException() : _input.Position;
            set { if (nonseekable) throw new NotSupportedException(); _input.Position = value; }
        }
        public override int Read(byte[] buffer, int offset, int count) => _input.Read(buffer, offset, Math.Min(1, count));
        public override int Read(Span<byte> buffer) => _input.Read(buffer[..Math.Min(1, buffer.Length)]);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default) =>
            _input.ReadAsync(buffer[..Math.Min(1, buffer.Length)], token);
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => nonseekable
            ? throw new NotSupportedException() : _input.Seek(offset, origin);
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing)
        {
            Disposed = true;
            if (disposing) _input.Dispose();
            base.Dispose(disposing);
        }
    }
}
