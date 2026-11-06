using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.Tests;

public sealed class PolicyCacheClockTests
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan Deadline = TimeSpan.FromSeconds(5);
    private static Policy Policy(int version) => LocalPolicyStore.CreateDefault() with { Version = version };

    [Theory]
    [InlineData(-6)] [InlineData(6)]
    public async Task Wall_clock_jump_does_not_expire_a_recent_snapshot(int hours)
    {
        var clock = new Clock(); var source = new Source();
        var store = new CachedPolicyStore(source, Lifetime, clock);
        var first = await store.LoadAsync(default);
        clock.Advance(TimeSpan.FromSeconds(10));
        clock.Utc += TimeSpan.FromHours(hours);
        Assert.Same(first, await store.LoadAsync(default));
        Assert.Equal(1, source.Calls);
    }

    [Theory]
    [InlineData(-6)] [InlineData(0)] [InlineData(6)]
    public async Task Elapsed_lifetime_expires_even_when_wall_clock_is_frozen_or_changed(int hours)
    {
        var clock = new Clock(); var source = new Source();
        var store = new CachedPolicyStore(source, Lifetime, clock);
        await store.LoadAsync(default);
        clock.Advance(Lifetime);
        clock.Utc += TimeSpan.FromHours(hours);
        Assert.Equal(2, (await store.LoadAsync(default)).Version);
        Assert.Equal(2, source.Calls);
    }

    [Fact]
    public async Task Already_cancelled_reader_does_not_receive_a_fresh_cached_snapshot()
    {
        var source = new Source(); var store = new CachedPolicyStore(source, Lifetime, new Clock());
        await store.LoadAsync(default);
        using var stop = new CancellationTokenSource(); stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.LoadAsync(stop.Token));
        Assert.Equal(1, source.Calls);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Origin_ignoring_cancellation_cannot_publish_its_result(bool warm)
    {
        var clock = new Clock(); var source = new Source();
        var store = new CachedPolicyStore(source, Lifetime, clock);
        if (warm) { await store.LoadAsync(default); clock.Advance(Lifetime); clock.Utc += Lifetime; }
        int before = source.Calls;
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var answer = new TaskCompletionSource<Policy>(TaskCreationOptions.RunContinuationsAsynchronously);
        source.Load = (_, _) => { entered.TrySetResult(); return answer.Task; };
        using var stop = new CancellationTokenSource();
        var pending = store.LoadAsync(stop.Token);
        await entered.Task.WaitAsync(Deadline);
        stop.Cancel(); answer.SetResult(Policy(99));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending.WaitAsync(Deadline));
        source.Load = (call, _) => Task.FromResult(Policy(call));
        Assert.Equal(before + 2, (await store.LoadAsync(default)).Version);
        Assert.Equal(before + 2, source.Calls);
    }

    [Fact]
    public async Task Lifetime_starts_when_the_successful_load_finishes()
    {
        var clock = new Clock(); var source = new Source();
        source.Load = (call, _) => { clock.Advance(TimeSpan.FromHours(1)); return Task.FromResult(Policy(call)); };
        var store = new CachedPolicyStore(source, Lifetime, clock);
        var first = await store.LoadAsync(default);
        clock.Advance(TimeSpan.FromSeconds(29));
        Assert.Same(first, await store.LoadAsync(default));
        clock.Advance(TimeSpan.FromSeconds(1));
        Assert.Equal(2, (await store.LoadAsync(default)).Version);
    }

    [Fact]
    public async Task Cancelling_a_waiter_does_not_cancel_the_active_load()
    {
        var source = new Source();
        var answer = new TaskCompletionSource<Policy>(TaskCreationOptions.RunContinuationsAsynchronously);
        source.Load = (_, _) => answer.Task;
        var store = new CachedPolicyStore(source, Lifetime, new Clock());
        var active = store.LoadAsync(default);
        using var stop = new CancellationTokenSource();
        var waiting = store.LoadAsync(stop.Token);
        stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting.WaitAsync(Deadline));
        Assert.False(active.IsCompleted);
        answer.SetResult(Policy(7));
        Assert.Equal(7, (await active.WaitAsync(Deadline)).Version);
        Assert.Equal(7, (await store.LoadAsync(default)).Version);
        Assert.Equal(1, source.Calls);
    }

    [Fact]
    public async Task Current_read_bypasses_snapshot_without_overwriting_it()
    {
        var source = new Source();
        var store = new CachedPolicyStore(source, Lifetime, new Clock());
        var classic = await store.LoadAsync(default);
        Assert.Equal(101, (await ((IPolicyStore)store).LoadCurrentAsync(default)).Version);
        Assert.Same(classic, await store.LoadAsync(default));
        Assert.Equal(1, source.Calls);
    }

    [Fact]
    public async Task Failed_current_read_cannot_return_a_fresh_cached_snapshot()
    {
        var store = new CachedPolicyStore(new FailingCurrentSource(), Lifetime, new Clock());
        await store.LoadAsync(default);
        await Assert.ThrowsAsync<IOException>(() => ((IPolicyStore)store).LoadCurrentAsync(default));
        Assert.Equal(1, (await store.LoadAsync(default)).Version);
    }
    private sealed class FailingCurrentSource : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken token) => Task.FromResult(Policy(1));
        public Task<Policy> LoadCurrentAsync(CancellationToken token) => throw new IOException("Synthetic current origin failure");
    }

    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Utc = new(2026, 10, 31, 12, 0, 0, TimeSpan.Zero);
        private long _elapsed;
        public override DateTimeOffset GetUtcNow() => Utc;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => _elapsed;
        public void Advance(TimeSpan elapsed) => _elapsed += elapsed.Ticks;
    }

    private sealed class Source : IPolicyStore
    {
        public int Calls;
        public Func<int, CancellationToken, Task<Policy>> Load = (call, _) => Task.FromResult(Policy(call));
        public Task<Policy> LoadAsync(CancellationToken token) => Load(++Calls, token);
        public Task<Policy> LoadCurrentAsync(CancellationToken token) { token.ThrowIfCancellationRequested(); return Task.FromResult(Policy(101)); }
    }
}
