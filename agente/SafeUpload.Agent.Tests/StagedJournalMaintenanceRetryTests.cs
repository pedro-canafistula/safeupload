using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class StagedJournalMaintenanceRetryTests
{
    [Fact]
    public async Task Transient_metadata_failure_backs_off_monotonically_and_success_resets_retry()
    {
        long now = 0; int calls = 0, reports = 0;
        var retry = new StagedJournalMaintenanceRetry(() => now, 1000);
        Task Fail(CancellationToken _) { calls++; throw new IOException("injected private flush failure"); }
        for (int i = 0; i < 8; i++)
        {
            await retry.RunAsync(Fail, _ => reports++, default);
            Assert.Equal(i + 1, calls);
            now += Math.Min(250L << i, 8000) - 1;
            await retry.RunAsync(Fail, _ => reports++, default);
            Assert.Equal(i + 1, calls);
            now++;
        }
        Assert.Equal(8, reports);
        await retry.RunAsync(_ => { calls++; return Task.CompletedTask; }, _ => reports++, default);
        await retry.RunAsync(Fail, _ => reports++, default);
        Assert.Equal(10, calls); Assert.Equal(9, reports);
    }

    [Fact]
    public async Task Pending_retry_prevents_followup_scan_until_persistent_io_failure_clears()
    {
        long now = 0; int scans = 0; bool busy = true;
        var retry = new StagedJournalMaintenanceRetry(() => now, 1000);
        async Task Pass()
        {
            bool complete = await retry.RunAsync(_ => busy ? throw new IOException("sharing failure remains") : Task.CompletedTask,
                _ => { }, default);
            if (complete) scans++;
        }
        await Pass(); await Pass(); Assert.Equal(0, scans);
        now = 250; await Pass(); Assert.Equal(0, scans);
        busy = false; now = 749; await Pass(); Assert.Equal(0, scans);
        now = 750; await Pass(); Assert.Equal(1, scans);
    }

    [Fact]
    public async Task Integrity_failure_and_cancellation_escape_instead_of_becoming_a_retry()
    {
        var retry = new StagedJournalMaintenanceRetry();
        await Assert.ThrowsAsync<InvalidDataException>(() => retry.RunAsync(
            _ => throw new InvalidDataException("corrupt receipt"), _ => Assert.Fail("Integrity cannot be retried"), default));
        using var stop = new CancellationTokenSource(); stop.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() => retry.RunAsync(
            _ => throw new Exception("Cancelled work must not run"), _ => Assert.Fail("Cancelled work must not report I/O"), stop.Token));
    }
}
