using System.ComponentModel;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Diagnostics;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class AdmissionCoverageRetryTests
{
    private const int RetryHResult = unchecked((int)0x800704D5);
    private const string Prefix = @"\Device\HarddiskVolume3\Users\victor\Cloud";
    private static readonly TimeSpan[] RetryDelays =
    [
        TimeSpan.FromMilliseconds(10),
        TimeSpan.FromMilliseconds(20),
        TimeSpan.FromMilliseconds(40)
    ];

    [Theory]
    [InlineData("hresultOnly")]
    [InlineData("win32HresultOnly")]
    [InlineData("unwrappedRetry")]
    [InlineData("otherNativeError")]
    [InlineData("invalidData")]
    [InlineData("generic")]
    [InlineData("cancelledQuery")]
    public async Task Only_the_exact_Win32_native_error_retries(string kind)
    {
        Exception failure = TerminalFailure(kind);
        var script = new QueryScript(failure);
        var counts = new AdmissionCoverageRetryCounts();
        Exception? thrown = await Record.ExceptionAsync(() => AdmissionCoverageRetry.QueryAsync(
            script.Query, script.DelayAsync, CancellationToken.None, counts));

        Assert.Same(failure, thrown);
        Assert.Equal(1, script.QueryCount);
        Assert.Empty(script.Delays);
        Assert.Equal(0, counts.RetriesUsed);
        Assert.False(counts.Exhausted);

        var poll = new PollComposition();
        AdmissionCoverageDecision decision = await poll.RunAsync(new QueryScript(failure));
        AssertQueryFailed(decision);
        Assert.Single(poll.Published);
        AssertCounters(poll.Diagnostics, 0, 0);
    }

    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public async Task Retry_then_success_evaluates_once_without_publishing_Degraded(int successAttempt)
    {
        Win32Exception retry = RetryFailure();
        Assert.Equal(RetryHResult, retry.NativeErrorCode);
        Assert.NotEqual(RetryHResult, retry.HResult);
        AdmissionCoverageReceipt receipt = ReadyReceipt();
        object[] outcomes = Enumerable.Range(1, successAttempt)
            .Select(attempt => attempt == successAttempt ? (object)receipt : retry).ToArray();
        var script = new QueryScript(outcomes);
        var poll = new PollComposition();
        int evaluationsObserved = 0;

        AdmissionCoverageDecision decision = await poll.RunAsync(script, coverage =>
        {
            evaluationsObserved++;
            Assert.Empty(poll.Published);
            Assert.Equal(successAttempt, script.QueryCount);
            return MinifilterInterceptor.ApplyStageStartupReadiness(coverage, true, true, false);
        });

        Assert.Equal(AdmissionCoverageEvaluator.Evaluate(receipt, [Prefix], 0, 7), decision);
        Assert.Equal(AdmissionCoverageReadiness.Ready, decision.Readiness);
        Assert.Equal(1, evaluationsObserved);
        Assert.Single(poll.Published);
        Assert.DoesNotContain(poll.Published, value => value.Readiness == AdmissionCoverageReadiness.Degraded);
        Assert.Empty(poll.Warnings);
        Assert.Equal(successAttempt, script.QueryCount);
        Assert.Equal(RetryDelays.Take(successAttempt - 1), script.Delays);
        AssertCounters(poll.Diagnostics, successAttempt - 1, 0);
    }

    [Fact]
    public async Task Exhaustion_rethrows_the_final_exception_after_exactly_four_queries_and_three_delays()
    {
        Win32Exception finalFailure = RetryFailure();
        var script = new QueryScript(RetryFailure(), RetryFailure(), RetryFailure(), finalFailure);
        var counts = new AdmissionCoverageRetryCounts();

        Win32Exception thrown = await Assert.ThrowsAsync<Win32Exception>(() =>
            AdmissionCoverageRetry.QueryAsync(script.Query, script.DelayAsync, CancellationToken.None, counts));

        Assert.Same(finalFailure, thrown);
        Assert.Equal(4, script.QueryCount);
        Assert.Equal(RetryDelays, script.Delays);
        Assert.Equal(3, counts.RetriesUsed);
        Assert.True(counts.Exhausted);
        Assert.Equal(new[] { "query1", "delay10", "query2", "delay20", "query3", "delay40", "query4" },
            script.Events);
    }

    [Fact]
    public async Task Repeated_exhaustion_counts_every_sequence_while_duplicate_warnings_are_suppressed()
    {
        var poll = new PollComposition();
        for (int sequence = 1; sequence <= 2; ++sequence)
        {
            var script = ExhaustedScript();
            AssertQueryFailed(await poll.RunAsync(script));
            Assert.Equal(4, script.QueryCount);
            Assert.Equal(RetryDelays, script.Delays);
            AssertCounters(poll.Diagnostics, 3 * sequence, sequence);
        }

        Assert.Equal(2, poll.Published.Count);
        Assert.Single(poll.Warnings);

        // A real receipt resets the existing suppression, so a later exhausted
        // sequence is visible again; the service totals are never reset.
        await poll.RunAsync(new QueryScript(ReadyReceipt()));
        AssertQueryFailed(await poll.RunAsync(ExhaustedScript()));
        Assert.Equal(2, poll.Warnings.Count);
        AssertCounters(poll.Diagnostics, 9, 3);
    }

    [Theory]
    [InlineData("otherNativeError")]
    [InlineData("invalidData")]
    [InlineData("generic")]
    public async Task Retry_then_terminal_error_stops_without_another_query(string kind)
    {
        Exception terminal = TerminalFailure(kind);
        var script = new QueryScript(RetryFailure(), terminal);
        var counts = new AdmissionCoverageRetryCounts();
        Exception? thrown = await Record.ExceptionAsync(() => AdmissionCoverageRetry.QueryAsync(
            script.Query, script.DelayAsync, CancellationToken.None, counts));

        Assert.Same(terminal, thrown);
        Assert.Equal(2, script.QueryCount);
        Assert.Equal(RetryDelays.Take(1), script.Delays);
        Assert.Equal(1, counts.RetriesUsed);
        Assert.False(counts.Exhausted);

        var poll = new PollComposition();
        AssertQueryFailed(await poll.RunAsync(new QueryScript(RetryFailure(), terminal)));
        Assert.Single(poll.Published);
        AssertCounters(poll.Diagnostics, 1, 0);
    }

    [Fact]
    public async Task Retry_then_malformed_receipt_is_evaluated_as_Degraded_without_another_query()
    {
        AdmissionCoverageReceipt malformed = ReadyReceipt() with { ScopeCount = 2 };
        var script = new QueryScript(RetryFailure(), malformed);
        var poll = new PollComposition();
        AdmissionCoverageDecision decision = await poll.RunAsync(script);

        Assert.Equal(AdmissionCoverageEvaluator.Evaluate(malformed, [Prefix], 0, 7), decision);
        Assert.Equal(AdmissionCoverageReadiness.Degraded, decision.Readiness);
        Assert.Equal("MalformedReceipt", decision.Reason);
        Assert.Equal(2, script.QueryCount);
        Assert.Equal(RetryDelays.Take(1), script.Delays);
        Assert.Single(poll.Published);
        Assert.Empty(poll.Warnings);
        AssertCounters(poll.Diagnostics, 1, 0);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task Cancellation_during_any_retry_delay_stops_without_another_query_or_publication(int cancelledDelay)
    {
        using var cancellation = new CancellationTokenSource();
        var script = ExhaustedScript();
        script.OnDelay = (_, token) =>
        {
            Assert.Equal(cancellation.Token, token);
            if (script.Delays.Count == cancelledDelay)
            {
                cancellation.Cancel();
                token.ThrowIfCancellationRequested();
            }
            return Task.CompletedTask;
        };
        var poll = new PollComposition();
        int evaluationsObserved = 0;

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => poll.RunAsync(script, coverage =>
        {
            evaluationsObserved++;
            return coverage;
        }, cancellation.Token));

        Assert.Equal(cancelledDelay, script.QueryCount);
        Assert.Equal(RetryDelays.Take(cancelledDelay), script.Delays);
        Assert.Equal(0, evaluationsObserved);
        Assert.Empty(poll.Published);
        Assert.Empty(poll.Warnings);
        AssertCounters(poll.Diagnostics, cancelledDelay - 1, 0);
    }

    [Fact]
    public async Task Cancellation_is_checked_before_requery_even_if_the_delay_delegate_returns_normally()
    {
        using var cancellation = new CancellationTokenSource();
        var script = new QueryScript(RetryFailure(), ReadyReceipt());
        script.OnDelay = (_, _) =>
        {
            cancellation.Cancel();
            return Task.CompletedTask;
        };
        var poll = new PollComposition();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            poll.RunAsync(script, token: cancellation.Token));

        Assert.Equal(1, script.QueryCount);
        Assert.Equal(RetryDelays.Take(1), script.Delays);
        Assert.Empty(poll.Published);
        Assert.Empty(poll.Warnings);
        AssertCounters(poll.Diagnostics, 0, 0);
    }

    [Fact]
    public async Task Queries_are_sequential_and_the_previous_query_has_unwound_before_the_delay()
    {
        var script = new QueryScript(RetryFailure(), ReadyReceipt());
        var delayRelease = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var poll = new PollComposition();
        script.OnDelay = (_, _) =>
        {
            Assert.False(script.QueryActive);
            Assert.Equal(1, script.QueryCount);
            Assert.Empty(poll.Published);
            return delayRelease.Task;
        };

        Task<AdmissionCoverageDecision> pending = poll.RunAsync(script);
        Assert.False(pending.IsCompleted);
        Assert.Equal(1, script.QueryCount);
        Assert.Empty(poll.Published);
        delayRelease.SetResult(true);
        Assert.Equal(AdmissionCoverageReadiness.Ready, (await pending).Readiness);
        Assert.Equal(2, script.QueryCount);
        Assert.Equal(new[] { "query1", "delay10", "query2" }, script.Events);
    }

    [Theory]
    [InlineData("unknown", "WriterStateUnknown")]
    [InlineData("policy", "PolicyFailedClosed")]
    [InlineData("identity", "VolumeIdentityUnknown")]
    [InlineData("generation", "NativePolicyGenerationChanged")]
    public async Task Retry_then_failed_coverage_is_published_as_evaluated_and_never_upgraded(string kind, string reason)
    {
        AdmissionCoverageReceipt receipt = FailedReceipt(kind);
        var script = new QueryScript(RetryFailure(), receipt);
        var poll = new PollComposition();
        AdmissionCoverageDecision decision = await poll.RunAsync(script, coverage =>
            MinifilterInterceptor.ApplyStageStartupReadiness(coverage, true, true, true));

        Assert.Equal(AdmissionCoverageEvaluator.Evaluate(receipt, [Prefix], 0, 7), decision);
        Assert.Equal(AdmissionCoverageReadiness.Degraded, decision.Readiness);
        Assert.Equal(reason, decision.Reason);
        Assert.Equal(new[] { decision }, poll.Published);
        Assert.Equal(2, script.QueryCount);
        Assert.Equal(RetryDelays.Take(1), script.Delays);
        AssertCounters(poll.Diagnostics, 1, 0);
    }

    [Theory]
    [InlineData(false, true, false, AdmissionCoverageReadiness.Pending, "StageStartupPending")]
    [InlineData(true, false, false, AdmissionCoverageReadiness.Pending, "StageStartupPending")]
    [InlineData(true, true, true, AdmissionCoverageReadiness.Degraded, "StageStartupFailed")]
    public async Task Startup_rejection_arising_during_retry_is_sampled_after_the_final_receipt(
        bool currentHandshake, bool currentRecovery, bool currentFailure,
        AdmissionCoverageReadiness expected, string reason)
    {
        bool handshake = true, recovery = true, failed = false;
        var script = new QueryScript(RetryFailure(), ReadyReceipt());
        script.OnDelay = (_, _) =>
        {
            handshake = currentHandshake;
            recovery = currentRecovery;
            failed = currentFailure;
            return Task.CompletedTask;
        };
        var poll = new PollComposition();
        AdmissionCoverageDecision decision = await poll.RunAsync(script, coverage =>
        {
            Assert.Equal(AdmissionCoverageReadiness.Ready, coverage.Readiness);
            Assert.Equal(2, script.QueryCount);
            return MinifilterInterceptor.ApplyStageStartupReadiness(coverage, handshake, recovery, failed);
        });

        Assert.Equal(expected, decision.Readiness);
        Assert.Equal(reason, decision.Reason);
        Assert.Equal(7u, decision.NativePolicyGeneration);
        Assert.Equal(new[] { decision }, poll.Published);
        AssertCounters(poll.Diagnostics, 1, 0);
    }

    [Theory]
    [InlineData("unknown")]
    [InlineData("policy")]
    [InlineData("identity")]
    public async Task Changing_snapshot_keeps_existing_Pending_precedence_after_retry_and_startup_failure(string kind)
    {
        AdmissionCoverageReceipt receipt = FailedReceipt(kind) with { RegistrySequenceEnd = 45 };
        var poll = new PollComposition();
        AdmissionCoverageDecision decision = await poll.RunAsync(new QueryScript(RetryFailure(), receipt), coverage =>
            MinifilterInterceptor.ApplyStageStartupReadiness(coverage, true, true, true));

        Assert.Equal(AdmissionCoverageEvaluator.Evaluate(receipt, [Prefix], 0, 7), decision);
        Assert.Equal(AdmissionCoverageReadiness.Pending, decision.Readiness);
        Assert.Equal("PolicyOrTopologyChanging", decision.Reason);
        Assert.Equal(new[] { decision }, poll.Published);
    }

    private static void AssertQueryFailed(AdmissionCoverageDecision decision)
    {
        Assert.Equal(AdmissionCoverageReadiness.Degraded, decision.Readiness);
        Assert.Equal("CoverageQueryFailed", decision.Reason);
        Assert.Equal(7u, decision.NativePolicyGeneration);
    }

    private static void AssertCounters(DriverDiagnosticsSource source, long retries, long exhausted)
    {
        var counters = source.ReadAdmissionCoverageRetryCounters();
        Assert.Equal(retries, counters["retries"]!.GetValue<long>());
        Assert.Equal(exhausted, counters["exhaustedSequences"]!.GetValue<long>());
    }

    private static Win32Exception RetryFailure() => new(RetryHResult, "Admission coverage query failed");

    private static Exception TerminalFailure(string kind) => kind switch
    {
        "hresultOnly" => new HResultOnlyException(),
        "win32HresultOnly" => new HResultOnlyWin32Exception(),
        "unwrappedRetry" => new Win32Exception(1237, "Unwrapped ERROR_RETRY is not the port HRESULT"),
        "otherNativeError" => new Win32Exception(unchecked((int)0x80070005), "Access denied"),
        "invalidData" => new InvalidDataException("Malformed native receipt"),
        "generic" => new Exception("Query failed"),
        "cancelledQuery" => new OperationCanceledException("Query cancelled without the poll token being cancelled"),
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };

    private sealed class HResultOnlyException : Exception
    {
        internal HResultOnlyException() => HResult = RetryHResult;
    }

    private sealed class HResultOnlyWin32Exception : Win32Exception
    {
        internal HResultOnlyWin32Exception() : base(5, "Retry HRESULT only") => HResult = RetryHResult;
    }

    private static QueryScript ExhaustedScript() =>
        new(RetryFailure(), RetryFailure(), RetryFailure(), RetryFailure());

    private sealed class QueryScript(params object[] outcomes)
    {
        internal int QueryCount { get; private set; }
        internal bool QueryActive { get; private set; }
        internal List<TimeSpan> Delays { get; } = new();
        internal List<string> Events { get; } = new();
        internal Func<TimeSpan, CancellationToken, Task>? OnDelay { get; set; }

        internal AdmissionCoverageReceipt Query()
        {
            Assert.False(QueryActive);
            QueryActive = true;
            try
            {
                Events.Add("query" + ++QueryCount);
                Assert.True(QueryCount <= outcomes.Length, "Unexpected additional coverage query");
                object outcome = outcomes[QueryCount - 1];
                if (outcome is Exception failure) throw failure;
                return (AdmissionCoverageReceipt)outcome;
            }
            finally
            {
                QueryActive = false;
            }
        }

        internal Task DelayAsync(TimeSpan delay, CancellationToken token)
        {
            Assert.False(QueryActive);
            Events.Add("delay" + (int)delay.TotalMilliseconds);
            Delays.Add(delay);
            return OnDelay is null ? Task.CompletedTask : OnDelay(delay, token);
        }
    }

    // Exercise the loop's smallest seam without a native port or notifications:
    // retry -> evaluate -> sample startup, then its existing failure/suppression
    // handling and per-sequence diagnostics accounting.
    private sealed class PollComposition
    {
        internal DriverDiagnosticsSource Diagnostics { get; } = new();
        internal List<AdmissionCoverageDecision> Published { get; } = new();
        internal List<Exception> Warnings { get; } = new();
        private string? _lastQueryFailure;

        internal async Task<AdmissionCoverageDecision> RunAsync(QueryScript script,
            Func<AdmissionCoverageDecision, AdmissionCoverageDecision>? applyStartup = null,
            CancellationToken token = default)
        {
            var counts = new AdmissionCoverageRetryCounts();
            AdmissionCoverageDecision decision;
            try
            {
                var result = await MinifilterInterceptor.QueryAndEvaluateAdmissionCoverageAsync(
                    script.Query, script.DelayAsync, [Prefix], 0, 7, token, counts, applyStartup);
                decision = result.Decision;
                _lastQueryFailure = null;
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                if (MinifilterInterceptor.ShouldLogCoverageQueryFailure(ex, ref _lastQueryFailure))
                    Warnings.Add(ex);
                decision = new(AdmissionCoverageReadiness.Degraded, "CoverageQueryFailed", 7);
            }
            finally
            {
                Diagnostics.RecordAdmissionCoverageRetry(counts.RetriesUsed, counts.Exhausted);
            }

            Published.Add(decision);
            return decision;
        }
    }

    private static AdmissionCoverageReceipt FailedReceipt(string kind) => kind switch
    {
        "unknown" => ReadyReceipt() with { WriterGlobalUnknown = 1, WriterEntriesUnknown = 1 },
        "policy" => ReadyReceipt() with { EpochFlags = 2, EpochFlagsEnd = 2 },
        "identity" => ReadyReceipt() with
        {
            State = AdmissionCoverageContract.Degraded,
            Reason = 15,
            Scopes = [new(AdmissionCoverageContract.PrefixScope, 0,
                AdmissionCoverageContract.UniqueResolution, AdmissionCoverageContract.Degraded,
                15, 1, 1, 1, Prefix)]
        },
        "generation" => ReadyReceipt() with { PolicyGeneration = 8, PolicyGenerationEnd = 8 },
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };

    // Common receipt bits only: both normal and SAFEUPLOAD_ADMISSION_EVIDENCE
    // builds evaluate these, without enabling the feature-only taint flag.
    private static AdmissionCoverageReceipt ReadyReceipt() =>
        new(Contract.Version, AdmissionCoverageContract.Ready,
            AdmissionCoverageContract.CompleteFlag | AdmissionCoverageContract.StableFlag |
            AdmissionCoverageContract.FutureGateFlag | AdmissionCoverageContract.RegistryCompleteFlag,
            PolicyGeneration: 7, PolicyFlags: 0, BootPolicyState: 1,
            ScopeCount: 1, ExpectedScopeCount: 1,
            PolicyGenerationEnd: 7, PolicyFlagsEnd: 0,
            BootPolicyStateEnd: 1, EpochGeneration: 3, EpochFlags: 0,
            EpochActiveCallbacks: 0, EpochGenerationEnd: 3, EpochFlagsEnd: 0,
            EpochActiveCallbacksEnd: 0, EnumeratedInstances: 1,
            SetupInFlight: 0, TeardownInFlight: 0, CoverageChangesInFlight: 0,
            WriterGlobalUnknown: 0, WriterEntries: 0, WriterEntriesNotReady: 0,
            WriterEntriesUnknown: 0, FutureMountGateReady: 1,
            Reason: 0, PolicyScopeSequenceStart: 14,
            PolicyScopeSequenceEnd: 14, TopologySequenceStart: 22,
            TopologySequenceEnd: 22, CoverageSequenceStart: 30,
            CoverageSequenceEnd: 30, RegistrySequenceStart: 44,
            RegistrySequenceEnd: 44,
            Scopes: [new(AdmissionCoverageContract.PrefixScope, 0,
                AdmissionCoverageContract.UniqueResolution, AdmissionCoverageContract.Ready,
                0, 1, 1, 1, Prefix)]);
}
