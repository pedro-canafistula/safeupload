using System.Globalization;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class StagedRequestTimingTests
{
    [Fact]
    public void Phases_use_invariant_durations_and_dequeue_relative_offsets()
    {
        long now = 100;
        var timing = new StagedRequestTiming(() => now, 1000);
        var saved = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("pt-BR");
            using (timing.StartPhase("policy-and-owner")) now += 25;
            now += 10;
            using (timing.StartPhase("journal-wait")) now += 40;
            using (timing.StartPhase("reply")) now += 5;
            Assert.Equal("policy-and-owner=25.0@25.0,journal-wait=40.0@75.0,reply=5.0@80.0", timing.ToString());
            Assert.Equal(80d, timing.ElapsedMs);
        }
        finally { CultureInfo.CurrentCulture = saved; }
    }

    [Fact]
    public void Nested_scopes_restore_live_phase_and_dispose_only_once()
    {
        long now = 0;
        var timing = new StagedRequestTiming(() => now, 1000);
        using (timing.StartPhase("handler"))
        {
            using var scan = timing.StartPhase("journal-scan");
            now = 10;
            using (timing.StartPhase("journal-scan")) now = 15;
            Assert.Equal("journal-scan", timing.Snapshot().Phase);
            scan.Dispose();
            now = 20;
            Assert.Equal("handler", timing.Snapshot().Phase);
        }
        Assert.Equal("journal-scan=15.0@15.0,handler=20.0@20.0", timing.ToString());
        Assert.Equal("dequeued", timing.Snapshot().Phase);
    }

    [Fact]
    public void Overlapping_scans_complete_out_of_order_without_losing_the_live_phase_or_counting_time_twice()
    {
        long now = 0;
        var timing = new StagedRequestTiming(() => now, 1000);
        using var first = timing.StartPhase("journal-scan");
        now = 10;
        using var second = timing.StartPhase("journal-scan");
        now = 20;
        using var backing = timing.StartPhase("backing");
        now = 25;
        first.Dispose();
        Assert.Equal("backing", timing.Snapshot().Phase);
        now = 30;
        backing.Dispose();
        Assert.Equal("journal-scan", timing.Snapshot().Phase);
        now = 35;
        second.Dispose();
        Assert.Equal("dequeued", timing.Snapshot().Phase);
        Assert.Equal("backing=10.0@30.0,journal-scan=35.0@35.0", timing.ToString());
    }

    [Theory]
    [InlineData(999, false, false)]
    [InlineData(1000, false, true)]
    [InlineData(0, true, true)]
    public void Warning_rule_is_failed_reply_or_at_least_one_second(long elapsed, bool failed, bool expected)
    {
        long now = 0;
        var timing = new StagedRequestTiming(() => now, 1000);
        now = elapsed;
        Assert.Equal(expected, timing.ShouldWarn(failed));
    }

    [Fact]
    public async Task Ambient_request_flows_to_continuation_without_leaking_into_next_request()
    {
        var first = new StagedRequestTiming();
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task pending;
        using (first.Activate())
        {
            pending = Task.Run(async () =>
            {
                await ready.Task;
                Assert.Same(first, StagedRequestTiming.Current);
                using var scope = StagedRequestTiming.Measure("reply");
                Assert.Equal("reply", first.Snapshot().Phase);
            });
        }
        Assert.Null(StagedRequestTiming.Current);
        using (new StagedRequestTiming().Activate())
        {
            ready.SetResult();
            await pending;
            Assert.NotSame(first, StagedRequestTiming.Current);
        }
        Assert.Null(StagedRequestTiming.Current);
    }

    [Fact]
    public async Task Journal_wait_is_visible_until_acquisition_and_cancellation_restores_phase()
    {
        var gate = new StagedJournalGate();
        await gate.WaitAsync();
        var timing = new StagedRequestTiming();
        using var active = timing.Activate();
        using var handler = timing.StartPhase("handler");
        using var cancel = new CancellationTokenSource();
        Task waiting = gate.WaitAsync(cancel.Token);
        Assert.Equal("journal-wait", timing.Snapshot().Phase);
        cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
        Assert.Equal("handler", timing.Snapshot().Phase);
        Assert.Equal(0, gate.Release());
        await gate.WaitAsync();
        Assert.Equal("handler", timing.Snapshot().Phase);
        gate.Release();
    }
    [Fact]
    public async Task Create_inspection_reports_policy_phase_without_changing_verdict()
    {
        using var workspace = new TestWorkspace();
        var timing = new StagedRequestTiming(() => 0, 1000);
        var inspection = new SafeUpload.Agent.Core.Application.InspectionService(
            new SafeUpload.Agent.Core.Infrastructure.LocalPolicyStore(workspace.PolicyFile),
            new SafeUpload.Agent.Core.Infrastructure.LocalQueueAuditSink(workspace.QueueFile),
            SafeUpload.Agent.Core.Infrastructure.Extraction.ExtractorRegistry.CreateDefault(),
            new SafeUpload.Agent.Core.Application.VerdictCache());
        var operation = TestWorkspace.Operation(workspace.WriteText("clean.txt", "Ordinary clean text."));
        var result = await inspection.InspectAsync(operation, CancellationToken.None, timing.StartPhase);
        Assert.Equal(SafeUpload.Agent.Core.Domain.Verdict.Approved, result.Verdict);
        Assert.Equal("policy-and-owner=0.0@0.0", timing.ToString());
        Assert.Equal("dequeued", timing.Snapshot().Phase);
    }

}
