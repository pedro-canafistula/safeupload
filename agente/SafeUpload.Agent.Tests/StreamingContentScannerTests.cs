using System.Diagnostics;
using System.Text;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using Xunit.Abstractions;

namespace SafeUpload.Agent.Tests;

public sealed class StreamingContentScannerTests(ITestOutputHelper output) : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    private static readonly HashSet<Category> All = Enum.GetValues<Category>().ToHashSet();
    public void Dispose() => _workspace.Dispose();

    private static string[] Corpus =>
    [
        "", "Clean text.", "529.982.247-25", "11.222.333/0001-81", "4111 1111 1111 1111",
        "0000000000000000", "00000000000000000000000000000000", "529  98224725", "11222333\n000181",
        "pwd: abcd", "PASSWORD\r\n\t = \u0085abcd", "ſenha: abcd", "password-password:abcde",
        "password:4111111111111111", "pwd:CPF: 529.982.247-25", "pwd:abc pwd:abcdef",
        "\"AccessKeyId\": \"AKIAIOSFODNN7EXAMPLE\"", "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
        "AIzaSyD-1234567890abcdefghijklmnopqrstu", "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----BEGIN PRIVATE KEY-----BEGIN PRIVATE KEY-----",
        "xoxb-abcdefghij", "xoxb-aaaaaaaaaa-AKIAIOSFODNN7EXAMPLE", "xoxb-aaaaaaaaaa-AKIAIOSFODNN7EXAMPLE-52998224725",
        "xoxb-aaaaaaaaaa-password:abcde pwd:abcde", "eyJabcdefgh.abcdefgh.abcdefgh", "eyJabcdefg.abcdefgh.abcdefgh",
        "eyJabcdefgh-AKIAIOSFODNN7EXAMPLE.abcdefgh.abcdefgh", "eyJabcdefgh.eyJabcdefgh.abcdefgh.abcdefgh",
        "password=ghp_1234567890abcdefghijklmnopqrstuvwxyz", "pwd: eyJabcdefgh.abcdefgh.abcdefgh",
        "\u200CAKIAIOSFODNN7EXAMPLE", "\u0301AKIAIOSFODNN7EXAMPLE", "\u203Fpwd:abcd",
        "ghp_" + new string('a', 255), "ghp_" + new string('a', 256),
        "AIza" + new string('a', 34) + "-a", "xoxb-abc_eyJabcdefgh.abcdefgh.abcdefgh"
    ];

    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(257)]
    [InlineData(8192)]
    public async Task Fragmented_input_preserves_full_scanner_categories_masks_order_and_precedence(int chunk)
    {
        var categories = Enum.GetValues<Category>();
        foreach (string text in Corpus)
        {
            // Every category subset catches precedence when a longer rule is disabled.
            for (int mask = 0; mask < 1 << categories.Length; mask++)
            {
                var active = categories.Where((_, i) => (mask & 1 << i) != 0).ToHashSet();
                Assert.Equal(ContentScanner.Scan(text, active),
                    await StreamingContentScanner.ScanAsync(() => Task.FromResult<TextReader>(
                        new FragmentedReader(text, chunk)), active, CancellationToken.None));
            }
        }
    }

    [Fact]
    public async Task Fixed_patterns_preserve_real_boundaries_at_every_overlap_position()
    {
        foreach (string token in new[] { "AKIAIOSFODNN7EXAMPLE", "ghp_" + new string('a', 255),
                     "-----BEGIN ENCRYPTED PRIVATE KEY-----", "AIza" + new string('a', 34) + "-" })
            foreach (char tail in new[] { ' ', 'x', '\u0301', '\u200D', '-' })
                for (int offset = 0; offset <= 261; offset++)
                {
                    string text = new string(' ', 8192 - offset) + token + tail;
                    Assert.Equal(ContentScanner.Scan(text, All), await ScanAsync(text));
                }
    }

    [Fact]
    public async Task Deterministic_mixed_text_matches_the_existing_scanner()
    {
        var random = new Random(73291); var corpus = Corpus;
        for (int trial = 0; trial < 80; trial++)
        {
            var builder = new StringBuilder();
            for (int part = 0; part < 12; part++)
                builder.Append(corpus[random.Next(corpus.Length)]).Append(new[] { " ", "-", "\n", "_", ":" }[random.Next(5)]);
            string text = builder.ToString();
            Assert.Equal(ContentScanner.Scan(text, All), await ScanAsync(text, random.Next(1, 513)));
        }
    }

    [Theory]
    [InlineData("slack")]
    [InlineData("jwt")]
    [InlineData("password")]
    [InlineData("whitespace")]
    public async Task Unbounded_values_and_whitespace_need_no_source_sized_buffer(string kind)
    {
        const int length = 2 * 1024 * 1024;
        string prefix = kind switch { "slack" => "xoxb-", "jwt" => "eyJabcdefgh.abcdefgh.", _ => "password" };
        string before = kind == "whitespace" ? "" : kind == "password" ? ":" : "";
        string after = kind == "whitespace" ? ":abcdef" : "";
        var elapsed = Stopwatch.StartNew();
        var findings = await StreamingContentScanner.ScanAsync(() => Task.FromResult<TextReader>(
            new RepeatedReader(prefix + before, kind == "whitespace" ? ' ' : 'a', length, after)), All, CancellationToken.None);
        elapsed.Stop();
        var expected = ContentScanner.Scan(prefix + before + new string(kind == "whitespace" ? ' ' : 'a', length) + after, All);
        Assert.Equal(expected, findings);
        output.WriteLine($"StreamingText shape={kind} repeated_characters={length} elapsed_ms={elapsed.Elapsed.TotalMilliseconds:F3}");
    }

    [Fact]
    public async Task Candidate_budget_fails_explicitly_instead_of_returning_a_truncated_result()
    {
        string text = string.Concat(Enumerable.Repeat("529.982.247-25\n", StreamingContentScanner.MaximumCandidates + 1));
        await Assert.ThrowsAsync<InspectionLimitException>(() => ScanAsync(text));
        string path = _workspace.WriteText("many-findings.txt", text);
        var service = new InspectionService(new LocalPolicyStore(_workspace.PolicyFile),
            new LocalQueueAuditSink(_workspace.QueueFile), ExtractorRegistry.CreateDefault(), new VerdictCache());
        var result = await service.InspectStagedAsync(TestWorkspace.Operation(path), CancellationToken.None);
        Assert.Equal(Verdict.Blocked, result.Verdict); Assert.Equal("inspection_limit", result.Reason);
        Assert.Equal(InspectionFailureKind.Limit, result.FailureKind); Assert.Empty(result.Findings);
        Assert.False(await service.IsCurrentStagedApprovalAsync(TestWorkspace.Operation(path), result, CancellationToken.None));
    }

    [Theory]
    [InlineData("utf8")]
    [InlineData("utf8-bom")]
    [InlineData("utf16le")]
    [InlineData("utf16be")]
    [InlineData("utf32le")]
    [InlineData("utf32be")]
    public async Task Staged_plaintext_uses_strict_streaming_readers_and_preserves_the_source(string name)
    {
        Encoding encoding = name switch
        {
            "utf8" => new UTF8Encoding(false, true), "utf8-bom" => new UTF8Encoding(true, true),
            "utf16le" => new UnicodeEncoding(false, true, true), "utf16be" => new UnicodeEncoding(true, true, true),
            "utf32le" => new UTF32Encoding(false, true, true), _ => new UTF32Encoding(true, true, true)
        };
        string text = new string('a', 8191) + " CPF: 529.982.247-25\npassword=ghp_" + new string('a', 36);
        byte[] original = [.. encoding.GetPreamble(), .. encoding.GetBytes(text)];
        string path = Path.Combine(_workspace.Root, name + ".txt"); await File.WriteAllBytesAsync(path, original);
        var streaming = new ReaderOnlyExtractor();
        var service = new InspectionService(new LocalPolicyStore(_workspace.PolicyFile),
            new LocalQueueAuditSink(_workspace.QueueFile), new ExtractorRegistry([streaming]), new VerdictCache());
        var result = await service.InspectStagedAsync(TestWorkspace.Operation(path), CancellationToken.None);
        Assert.Equal(Verdict.Blocked, result.Verdict); Assert.Null(result.Reason);
        Assert.Equal(ContentScanner.Scan(text, All), result.Findings);
        Assert.True(streaming.Readers > 1); Assert.Equal(original, await File.ReadAllBytesAsync(path));
    }

    [Fact]
    public async Task Caller_cancellation_closes_readers_and_does_not_become_a_partial_result()
    {
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => StreamingContentScanner.ScanAsync(
            () => Task.FromResult<TextReader>(new StringReader("clean")), All, canceled.Token));
        using var bytes = new MemoryStream(Encoding.UTF8.GetBytes("clean"));
        using (var reader = await new PlainTextExtractor().OpenReaderAsync(bytes, CancellationToken.None))
            Assert.Equal("clean", await reader.ReadToEndAsync());
        Assert.True(bytes.CanRead); bytes.Position = 0;
        Assert.Equal((int)'c', bytes.ReadByte());
    }

    private static Task<IReadOnlyList<Finding>> ScanAsync(string text, int chunk = 8192) =>
        StreamingContentScanner.ScanAsync(() => Task.FromResult<TextReader>(new FragmentedReader(text, chunk)), All, CancellationToken.None);

    private sealed class FragmentedReader(string text, int chunk) : StringReader(text)
    {
        public override ValueTask<int> ReadAsync(Memory<char> buffer, CancellationToken cancellationToken = default) =>
            base.ReadAsync(buffer[..Math.Min(buffer.Length, chunk)], cancellationToken);
    }

    private sealed class ReaderOnlyExtractor : IStreamingTextExtractor
    {
        private readonly PlainTextExtractor _inner = new();
        public int Readers;
        public IReadOnlySet<string> SupportedExtensions => _inner.SupportedExtensions;
        public Task<string> ExtractAsync(Stream content, CancellationToken token) =>
            throw new InvalidOperationException("The staged path must not materialize the whole text.");
        public Task<TextReader> OpenReaderAsync(Stream content, CancellationToken token)
        { Readers++; return _inner.OpenReaderAsync(content, token); }
    }

    // A large logical source without allocating its repeated body in the reader.
    private sealed class RepeatedReader(string prefix, char repeated, long count, string suffix) : TextReader
    {
        private long _position;
        public override ValueTask<int> ReadAsync(Memory<char> buffer, CancellationToken token = default)
        {
            token.ThrowIfCancellationRequested(); long length = prefix.Length + count + suffix.Length;
            int read = (int)Math.Min(buffer.Length, length - _position);
            for (int i = 0; i < read; i++, _position++)
                buffer.Span[i] = _position < prefix.Length ? prefix[(int)_position]
                    : _position < prefix.Length + count ? repeated : suffix[(int)(_position - prefix.Length - count)];
            return ValueTask.FromResult(read);
        }
    }
}
