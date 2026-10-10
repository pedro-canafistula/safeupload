using System.Diagnostics;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.Tests;

public sealed class InspectionWorkBudgetTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task Timed_out_noncooperative_parsers_keep_their_slots_and_late_results_never_authorize_content(
        bool staged, bool lateFailure)
    {
        var extractor = new NoncooperativeExtractor(lateFailure);
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        var service = Service(extractor, sink);
        var operation = TestWorkspace.Operation(_workspace.WriteText("bounded.txt", "CPF: 529.982.247-25"));
        Task<InspectionResult> Inspect(CancellationToken token) => staged
            ? service.InspectStagedAsync(operation, token) : service.InspectAsync(operation, token);
        var first = new[] { Inspect(CancellationToken.None), Inspect(CancellationToken.None) };
        try
        {
            await extractor.BothEntered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.All(await Task.WhenAll(first), result => AssertTimeout(result, staged));
            Assert.Equal(2, extractor.Active);

            var queued = Enumerable.Range(0, 6).Select(_ => Inspect(CancellationToken.None)).ToArray();
            Assert.All(await Task.WhenAll(queued), result => AssertTimeout(result, staged));
            Assert.Equal(2, extractor.Calls);
            Assert.Equal(2, extractor.Active);
            Assert.Equal(2, extractor.PeakActive);

            using var cancelled = new CancellationTokenSource();
            var waiting = Inspect(cancelled.Token);
            cancelled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
            Assert.Equal(2, extractor.Calls);

            extractor.Release.TrySetResult();
            await extractor.BothFinished.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await WaitForWorkerReleaseAsync(service);
            Assert.Equal(0, extractor.Active);
            // The abandoned workers return an intentionally clean result for
            // these same bytes. It must neither replace the timeout's outcome
            // nor install a cached approval when they eventually finish.
            Assert.Equal(staged ? 0 : 8, (await sink.ReadRecentAsync(20, CancellationToken.None)).Count);
            var recovered = await Inspect(CancellationToken.None);
            Assert.Equal(Verdict.Blocked, recovered.Verdict);
            Assert.Null(recovered.Reason);
            Assert.False(recovered.FromCache);
            Assert.Equal(Category.Cpf, Assert.Single(recovered.Categories));
            Assert.Equal(3, extractor.Calls);
            Assert.Equal(0, extractor.Active);
        }
        finally
        {
            extractor.Release.TrySetResult();
            await extractor.BothFinished.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await WaitForWorkerReleaseAsync(service);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Cooperative_parsers_receive_deadline_cancellation_and_return_capacity_for_a_complete_inspection(bool staged)
    {
        var extractor = new CooperativeExtractor();
        var service = Service(extractor, new LocalQueueAuditSink(_workspace.QueueFile));
        var operation = TestWorkspace.Operation(_workspace.WriteText("cooperative.txt", "CPF: 529.982.247-25"));
        Task<InspectionResult> Inspect() => staged
            ? service.InspectStagedAsync(operation, CancellationToken.None)
            : service.InspectAsync(operation, CancellationToken.None);

        AssertTimeout(await Inspect(), staged);
        await extractor.Cancelled.Task.WaitAsync(TimeSpan.FromSeconds(10));
        await WaitForWorkerReleaseAsync(service);
        Assert.Equal(0, extractor.Active);

        var recovered = await Inspect();
        Assert.Equal(Verdict.Blocked, recovered.Verdict);
        Assert.Null(recovered.Reason);
        Assert.False(recovered.FromCache);
        Assert.Equal(Category.Cpf, Assert.Single(recovered.Categories));
        Assert.Equal(0, extractor.Active);
    }

    private InspectionService Service(ITextExtractor extractor, LocalQueueAuditSink sink) => new(
        new FixedPolicyStore(LocalPolicyStore.CreateDefault() with { Version = 11, InspectionTimeoutSeconds = 3 }),
        sink, new ExtractorRegistry([extractor]), new VerdictCache());

    private static async Task WaitForWorkerReleaseAsync(InspectionService service)
    {
        var wait = Stopwatch.StartNew();
        while (service.ActiveInspectionWorkers != 0 && wait.Elapsed < TimeSpan.FromSeconds(10))
            await Task.Delay(10);
        Assert.Equal(0, service.ActiveInspectionWorkers);
    }

    private static void AssertTimeout(InspectionResult result, bool staged)
    {
        Assert.Equal(staged ? Verdict.Blocked : Verdict.AllowedWithoutInspection, result.Verdict);
        Assert.Equal("inspection_timeout", result.Reason);
        Assert.Equal(11, result.PolicyVersion);
        Assert.True(result.InScope);
        Assert.False(result.FromCache);
        Assert.Empty(result.Findings);
    }

    private sealed class FixedPolicyStore(Policy policy) : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken token) => Task.FromResult(policy);
    }

    private sealed class NoncooperativeExtractor(bool lateFailure) : ITextExtractor
    {
        public IReadOnlySet<string> SupportedExtensions { get; } = new HashSet<string> { ".txt" };
        public TaskCompletionSource BothEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource BothFinished { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _calls, _active, _peakActive, _finished;
        public int Calls => Volatile.Read(ref _calls);
        public int Active => Volatile.Read(ref _active);
        public int PeakActive => Volatile.Read(ref _peakActive);
        public async Task<string> ExtractAsync(Stream content, CancellationToken token)
        {
            int call = Interlocked.Increment(ref _calls);
            int active = Interlocked.Increment(ref _active);
            int peak;
            do { peak = Volatile.Read(ref _peakActive); }
            while (active > peak && Interlocked.CompareExchange(ref _peakActive, active, peak) != peak);
            if (call == 2) BothEntered.TrySetResult();
            try
            {
                if (call <= 2)
                {
                    await Release.Task; // Deliberately ignores deadline cancellation.
                    if (lateFailure) throw new InvalidDataException("Late parser diagnostic: 529.982.247-25");
                    return "clean late result";
                }
                return await new PlainTextExtractor().ExtractAsync(content, token);
            }
            finally
            {
                Interlocked.Decrement(ref _active);
                if (call <= 2 && Interlocked.Increment(ref _finished) == 2) BothFinished.TrySetResult();
            }
        }
    }

    private sealed class CooperativeExtractor : ITextExtractor
    {
        public IReadOnlySet<string> SupportedExtensions { get; } = new HashSet<string> { ".txt" };
        public TaskCompletionSource Cancelled { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _calls, _active;
        public int Active => Volatile.Read(ref _active);
        public async Task<string> ExtractAsync(Stream content, CancellationToken token)
        {
            int call = Interlocked.Increment(ref _calls);
            Interlocked.Increment(ref _active);
            try
            {
                if (call == 1) await Task.Delay(Timeout.Infinite, token);
                return await new PlainTextExtractor().ExtractAsync(content, token);
            }
            finally
            {
                Interlocked.Decrement(ref _active);
                if (call == 1 && token.IsCancellationRequested) Cancelled.TrySetResult();
            }
        }
    }
}
