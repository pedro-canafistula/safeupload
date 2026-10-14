using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class StagedReceiveHeartbeatTests
{
    [Fact]
    public void Heartbeat_runs_only_while_started_and_emits_once_per_sixty_monotonic_seconds()
    {
        long now = 0;
        var heartbeat = new StagedReceiveHeartbeat(() => now, 1000);
        now = 60_000;
        Assert.Null(heartbeat.Poll());
        heartbeat.Start();
        now += 59_999;
        Assert.Null(heartbeat.Poll());
        now++;
        Assert.Equal("waiting for a message", heartbeat.Poll());
        Assert.Null(heartbeat.Poll());
        now += 600_000; // A process stall must not produce a catch-up burst.
        Assert.Equal("waiting for a message", heartbeat.Poll());
        Assert.Null(heartbeat.Poll());
        heartbeat.Stop();
        now += 60_000;
        Assert.Null(heartbeat.Poll());
        heartbeat.Start();
        Assert.Null(heartbeat.Poll());
    }

    [Fact]
    public void Heartbeat_names_current_operation_phase_and_dequeue_age()
    {
        long now = 0;
        var heartbeat = new StagedReceiveHeartbeat(() => now, 1000);
        heartbeat.Start();
        now = 1000;
        var timing = new StagedRequestTiming(() => now, 1000);
        heartbeat.Handling(1833, "StageSeal", timing);
        using (timing.StartPhase("journal-wait"))
        {
            now = 60_000;
            Assert.Equal("handling request 1833, operation StageSeal, phase journal-wait, age 59000.0 ms", heartbeat.Poll());
        }
        heartbeat.Complete(timing);
        heartbeat.Waiting();
        now = 120_000;
        Assert.Equal("waiting for a message", heartbeat.Poll());
    }

    [Fact]
    public void Waiting_loop_reports_oldest_continuation_and_completion_does_not_erase_new_handler()
    {
        long now = 0;
        var heartbeat = new StagedReceiveHeartbeat(() => now, 1000);
        heartbeat.Start();
        var first = new StagedRequestTiming(() => now, 1000);
        heartbeat.Handling(1, "StageAllocate", first);
        using var firstPhase = first.StartPhase("backing");
        heartbeat.Waiting();
        now = 1000;
        var second = new StagedRequestTiming(() => now, 1000);
        heartbeat.Handling(2, "Create", second);
        using var secondPhase = second.StartPhase("inspection");
        heartbeat.Waiting();
        now = 60_000;
        Assert.Equal("waiting for a message; asynchronous request 1, operation StageAllocate, phase backing, age 60000.0 ms", heartbeat.Poll());
        now = 61_000;
        var third = new StagedRequestTiming(() => now, 1000);
        heartbeat.Handling(3, "Read", third);
        using var thirdPhase = third.StartPhase("reply");
        heartbeat.Complete(first);
        heartbeat.Complete(second);
        now = 120_000;
        Assert.Equal("handling request 3, operation Read, phase reply, age 59000.0 ms", heartbeat.Poll());
        heartbeat.Stop();
        heartbeat.Complete(third); // A canceled continuation may finish after stop.
        heartbeat.Start();
        now = 180_000;
        Assert.Equal("waiting for a message", heartbeat.Poll());
    }
}
