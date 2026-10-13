using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using Xunit.Abstractions;

namespace SafeUpload.Agent.Tests;

// Other test allocations must not enter the memory observations. This does
// not change production worker concurrency or any inspection budget.
[CollectionDefinition("Plaintext memory", DisableParallelization = true)]
public sealed class PlaintextMemoryCollection { }

[Collection("Plaintext memory")]
public sealed class LargePlaintextInspectionTests(ITestOutputHelper output) : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    private static readonly HashSet<Category> All = Enum.GetValues<Category>().ToHashSet();
    private const string SensitiveTail = " CPF: 529.982.247-25";
    public void Dispose() => _workspace.Dispose();

    [Theory]
    [InlineData(1, false)]
    [InlineData(1, true)]
    [InlineData(20, false)]
    [InlineData(20, true)]
    public async Task Default_limit_inspection_reads_eof_on_first_and_repeat_scans(int megabytes, bool sensitive)
    {
        int length = megabytes * 1024 * 1024;
        string path = Path.Combine(_workspace.Root, "default-limit.txt");
        await WriteAsciiAsync(path, length, sensitive ? SensitiveTail : "");
        string originalHash = await HashAsync(path);
        var extractor = new ObservedExtractor();
        var service = new InspectionService(new LocalPolicyStore(_workspace.PolicyFile),
            new LocalQueueAuditSink(_workspace.QueueFile), new ExtractorRegistry([extractor]), new VerdictCache());

        foreach (string phase in new[] { "first", "repeat" })
        {
            extractor.Reset();
            long baseline = GC.GetTotalMemory(forceFullCollection: true);
            long allocated = GC.GetTotalAllocatedBytes(precise: true);
            var elapsed = Stopwatch.StartNew();
            var operation = TestWorkspace.Operation(path);
            var result = await service.InspectStagedAsync(operation, CancellationToken.None);
            elapsed.Stop();

            Assert.Null(result.Reason);
            Assert.Equal(sensitive ? Verdict.Blocked : Verdict.Approved, result.Verdict);
            Assert.False(result.FromCache);
            if (sensitive)
            {
                Assert.Equal(Category.Cpf, Assert.Single(result.Findings).Category);
                Assert.DoesNotContain("529.982.247-25", result.Findings[0].MaskedSnippet);
            }
            else Assert.Empty(result.Findings);
            Assert.Equal(!sensitive, await service.IsCurrentStagedApprovalAsync(operation, result, CancellationToken.None));
            Assert.NotEmpty(extractor.Readers);
            Assert.All(extractor.Readers, reader =>
            {
                Assert.True(reader.EndOfInput);
                Assert.True(reader.Disposed);
                Assert.Equal((long)length, reader.Characters);
            });
            output.WriteLine($"PlaintextDefault phase={phase} bytes={length} sensitive={sensitive} elapsed_ms={elapsed.Elapsed.TotalMilliseconds:F3} " +
                $"passes={extractor.Readers.Count} allocated_bytes={GC.GetTotalAllocatedBytes(precise: true) - allocated} " +
                $"sampled_managed_delta_bytes={Math.Max(0, extractor.PeakManagedBytes - baseline)}");
        }
        Assert.Equal(originalHash, await HashAsync(path));
        Assert.Empty(await new LocalQueueAuditSink(_workspace.QueueFile).ReadRecentAsync(10, CancellationToken.None));
    }

    [Theory]
    [InlineData(8, false)]
    [InlineData(8, true)]
    [InlineData(64, false)]
    [InlineData(64, true)]
    public async Task Collected_live_scanner_state_stays_bounded_when_the_logical_source_grows(int megabytes, bool sensitive)
    {
        long length = (long)megabytes * 1024 * 1024;
        long baseline = GC.GetTotalMemory(forceFullCollection: true), peak = baseline;
        int samples = 0, readers = 0;
        // Collection changes throughput, so this control measures live managed
        // state only. It is not a policy/deadline or real-file benchmark.
        var findings = await StreamingContentScanner.ScanAsync(() =>
        {
            readers++;
            return Task.FromResult<TextReader>(new LogicalReader(length, sensitive ? SensitiveTail : "", () =>
            {
                peak = Math.Max(peak, GC.GetTotalMemory(forceFullCollection: true));
                samples++;
            }));
        }, All, CancellationToken.None);

        if (sensitive) Assert.Equal(Category.Cpf, Assert.Single(findings).Category);
        else Assert.Empty(findings);
        Assert.True(samples >= readers);
        // A whole source/text capture would exceed this bound even for the
        // smaller case. No source-sized body exists in the logical reader.
        Assert.InRange(peak - baseline, 0, 4L * 1024 * 1024);
        output.WriteLine($"PlaintextLive logical_characters={length} sensitive={sensitive} " +
            $"collected_managed_delta_bytes={peak - baseline} samples={samples} passes={readers}");
    }

    [Theory]
    [InlineData("utf8")]
    [InlineData("utf16")]
    [InlineData("utf32")]
    public async Task Malformed_encoding_at_eof_cannot_become_a_clean_staged_approval(string encoding)
    {
        var invalidTail = encoding switch
        {
            "utf8" => new byte[] { 0xF0, 0x9F },
            "utf16" => new byte[] { 0x61 },
            _ => new byte[] { 0x61, 0, 0 }
        };
        byte[] preamble = encoding switch
        {
            "utf16" => [0xFF, 0xFE], "utf32" => [0xFF, 0xFE, 0, 0], _ => []
        };
        string path = Path.Combine(_workspace.Root, "invalid.txt");
        await using (var file = File.Create(path))
        {
            await file.WriteAsync(preamble);
            await file.WriteAsync(new byte[1024 * 1024]); // Valid NUL characters, with no findings.
            await file.WriteAsync(invalidTail);
        }
        string originalHash = await HashAsync(path);
        var service = new InspectionService(new LocalPolicyStore(_workspace.PolicyFile),
            new LocalQueueAuditSink(_workspace.QueueFile), ExtractorRegistry.CreateDefault(), new VerdictCache());
        var result = await service.InspectStagedAsync(TestWorkspace.Operation(path), CancellationToken.None);
        Assert.Equal(Verdict.Blocked, result.Verdict);
        Assert.Equal(InspectionFailureKind.ReadOrParse, result.FailureKind);
        Assert.Empty(result.Findings);
        Assert.False(await service.IsCurrentStagedApprovalAsync(TestWorkspace.Operation(path), result, CancellationToken.None));
        Assert.Equal(originalHash, await HashAsync(path));

        await using var input = File.OpenRead(path);
        await Assert.ThrowsAsync<DecoderFallbackException>(() => StreamingContentScanner.ScanAsync(() =>
        {
            input.Position = 0;
            return new PlainTextExtractor().OpenReaderAsync(input, CancellationToken.None);
        }, new HashSet<Category>(), CancellationToken.None));
    }

    private static async Task WriteAsciiAsync(string path, int length, string tail)
    {
        await using var file = File.Create(path);
        byte[] buffer = new byte[16 * 1024]; Array.Fill(buffer, (byte)'a');
        int remaining = length - tail.Length;
        while (remaining != 0)
        {
            int count = Math.Min(remaining, buffer.Length);
            await file.WriteAsync(buffer.AsMemory(0, count)); remaining -= count;
        }
        await file.WriteAsync(Encoding.ASCII.GetBytes(tail));
    }

    private static async Task<string> HashAsync(string path)
    {
        await using var file = File.OpenRead(path);
        return Convert.ToHexString(await SHA256.HashDataAsync(file));
    }

    private sealed class ObservedExtractor : IStreamingTextExtractor
    {
        private readonly PlainTextExtractor _inner = new();
        public List<ObservedReader> Readers { get; } = [];
        public long PeakManagedBytes { get; private set; }
        public void Reset() { Readers.Clear(); PeakManagedBytes = 0; }
        public IReadOnlySet<string> SupportedExtensions => _inner.SupportedExtensions;
        public Task<string> ExtractAsync(Stream content, CancellationToken token) =>
            throw new InvalidOperationException("Large staged plaintext must use readers.");
        public async Task<TextReader> OpenReaderAsync(Stream content, CancellationToken token)
        {
            var reader = new ObservedReader(await _inner.OpenReaderAsync(content, token),
                () => PeakManagedBytes = Math.Max(PeakManagedBytes, GC.GetTotalMemory(forceFullCollection: false)));
            Readers.Add(reader); return reader;
        }
    }

    private sealed class ObservedReader(TextReader inner, Action sample) : TextReader
    {
        private long _nextSample = 1024 * 1024;
        public long Characters { get; private set; }
        public bool EndOfInput { get; private set; }
        public bool Disposed { get; private set; }
        public override async ValueTask<int> ReadAsync(Memory<char> buffer, CancellationToken token = default)
        {
            int count = await inner.ReadAsync(buffer, token);
            Characters += count;
            if (count == 0) EndOfInput = true;
            if (Characters >= _nextSample || count == 0)
            { sample(); _nextSample = Characters + 1024 * 1024; }
            return count;
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing) { inner.Dispose(); Disposed = true; }
            base.Dispose(disposing);
        }
    }

    private sealed class LogicalReader(long length, string tail, Action sample) : TextReader
    {
        private long _position, _nextSample = 16L * 1024 * 1024;
        private bool _sampledEof;
        public override ValueTask<int> ReadAsync(Memory<char> buffer, CancellationToken token = default)
        {
            token.ThrowIfCancellationRequested();
            int count = (int)Math.Min(buffer.Length, length - _position);
            buffer.Span[..count].Fill('a');
            long tailStart = length - tail.Length;
            if (_position + count > tailStart)
            {
                int offset = (int)Math.Max(0, tailStart - _position);
                int tailOffset = (int)Math.Max(0, _position - tailStart);
                tail.AsSpan(tailOffset, count - offset).CopyTo(buffer.Span[offset..]);
            }
            _position += count;
            if (_position >= _nextSample || count == 0 && !_sampledEof)
            {
                sample(); _nextSample = _position + 16L * 1024 * 1024;
                _sampledEof = count == 0;
            }
            return ValueTask.FromResult(count);
        }
    }
}
