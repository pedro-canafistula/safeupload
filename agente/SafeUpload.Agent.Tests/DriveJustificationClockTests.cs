using SafeUpload.Agent.Service.Drive;

namespace SafeUpload.Agent.Tests;

public sealed class DriveJustificationClockTests
{
    private const string Sid = "S-1-5-21-111-222-333-1001";

    [Theory]
    [InlineData(-6)]
    [InlineData(6)]
    public void Wall_clock_changes_do_not_shorten_a_fresh_justification(int hours)
    {
        var clock = new Clock();
        var store = new DriveJustifications(clock);
        var id = Guid.NewGuid();
        store.Remember(id, 7, Sid, "policy-binding", () => true);
        clock.Elapsed += TimeSpan.FromMinutes(9).Ticks;
        clock.Utc += TimeSpan.FromHours(hours);
        Assert.True(store.TryConsume(id.ToString(), 7, Sid, "policy-binding", out var approve));
        Assert.True(approve!());
        Assert.False(store.TryConsume(id.ToString(), 7, Sid, "policy-binding", out _));
    }

    [Theory]
    [InlineData(-6)]
    [InlineData(0)]
    [InlineData(6)]
    public void Expiry_uses_elapsed_time_even_if_civil_time_is_frozen_or_adjusted(int hours)
    {
        var clock = new Clock();
        var store = new DriveJustifications(clock);
        var id = Guid.NewGuid();
        store.Remember(id, 7, Sid, "policy-binding", () => true);
        clock.Elapsed += DriveJustifications.Window.Ticks;
        clock.Utc += TimeSpan.FromHours(hours);
        Assert.False(store.TryConsume(id.ToString(), 7, Sid, "policy-binding", out var approve));
        Assert.Null(approve);
    }

    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Utc = DateTimeOffset.UtcNow;
        public long Elapsed;
        public override DateTimeOffset GetUtcNow() => Utc;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Elapsed;
    }
}
