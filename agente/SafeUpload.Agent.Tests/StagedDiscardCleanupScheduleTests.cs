using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class StagedDiscardCleanupScheduleTests
{
    [Fact]
    public void Idle_loop_keeps_the_one_second_interval()
    {
        var schedule = new StagedDiscardCleanupSchedule();
        Assert.Equal(TimeSpan.FromSeconds(1), schedule.NextDelay(pendingRemained: false));
        Assert.Equal(TimeSpan.FromSeconds(1), schedule.NextDelay(pendingRemained: false));
    }

    [Fact]
    public void Pending_discards_retry_on_a_short_growing_backoff_then_fall_back_to_idle()
    {
        var schedule = new StagedDiscardCleanupSchedule();
        var delays = Enumerable.Range(0, 8).Select(_ => schedule.NextDelay(pendingRemained: true)).ToArray();

        Assert.Equal([25, 50, 100, 200, 400, 800, 1000, 1000], delays.Select(d => (int)d.TotalMilliseconds));
        // The fast window is short: a discard that stays locked costs at most ~1.6 s of extra passes before the idle cadence.
        Assert.True(delays.Take(6).Sum(d => d.TotalMilliseconds) < 1600);
    }

    [Fact]
    public void An_empty_pass_restarts_the_backoff()
    {
        var schedule = new StagedDiscardCleanupSchedule();
        schedule.NextDelay(pendingRemained: true);
        schedule.NextDelay(pendingRemained: true);
        Assert.Equal(TimeSpan.FromSeconds(1), schedule.NextDelay(pendingRemained: false));
        Assert.Equal(TimeSpan.FromMilliseconds(25), schedule.NextDelay(pendingRemained: true));
    }

    [Fact]
    public async Task A_notification_wakes_a_long_wait_immediately_and_restarts_the_backoff()
    {
        var schedule = new StagedDiscardCleanupSchedule();
        for (int i = 0; i < 4; i++) schedule.NextDelay(pendingRemained: true);

        var wait = schedule.WaitAsync(TimeSpan.FromSeconds(30), CancellationToken.None);
        Assert.False(wait.IsCompleted);
        schedule.Notify();
        await wait.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal(TimeSpan.FromMilliseconds(25), schedule.NextDelay(pendingRemained: true));
    }

    [Fact]
    public async Task A_notification_before_the_wait_is_not_lost_and_repeats_coalesce()
    {
        var schedule = new StagedDiscardCleanupSchedule();
        schedule.Notify();
        schedule.Notify();
        schedule.Notify();

        await schedule.WaitAsync(TimeSpan.FromSeconds(30), CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(10));

        // The coalesced signal is consumed once: the next wait runs its full (here short) delay.
        var started = System.Diagnostics.Stopwatch.GetTimestamp();
        await schedule.WaitAsync(TimeSpan.FromMilliseconds(150), CancellationToken.None);
        Assert.True(System.Diagnostics.Stopwatch.GetElapsedTime(started) >= TimeSpan.FromMilliseconds(100));
    }

    [Fact]
    public async Task A_wait_without_a_signal_ends_at_its_delay_and_honours_cancellation()
    {
        var schedule = new StagedDiscardCleanupSchedule();
        await schedule.WaitAsync(TimeSpan.FromMilliseconds(20), CancellationToken.None);

        using var cancel = new CancellationTokenSource();
        var wait = schedule.WaitAsync(TimeSpan.FromSeconds(30), cancel.Token);
        cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => wait);
    }
}
