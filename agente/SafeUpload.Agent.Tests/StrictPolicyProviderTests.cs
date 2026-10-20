using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Policies;

namespace SafeUpload.Agent.Tests;

public sealed class StrictPolicyProviderTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();

    [Theory]
    [InlineData("memory")]
    [InlineData("disk")]
    [InlineData("default")]
    public async Task Strict_read_refuses_every_fallback_source_and_does_not_overwrite_disk(string source)
    {
        using var handler = new Handler();
        using var client = new HttpClient(handler) { BaseAddress = new Uri("http://policy.invalid/agent/") };
        string cache = Path.Combine(_workspace.Root, "cache.json");
        DurableHttpPolicyStore Create() => new(client, "TEST", cache, false);
        var store = Create();
        if (source != "default") await store.LoadAsync(CancellationToken.None);
        if (source == "disk") store = Create();
        string? before = File.Exists(cache) ? await File.ReadAllTextAsync(cache) : null;
        handler.Fail = true;
        var legacy = await store.LoadAsync(CancellationToken.None);
        Assert.Equal(source == "default" ? 1 : 7, legacy.Version);
        Assert.Equal(source, store.LastSource);
        await Assert.ThrowsAsync<HttpRequestException>(() => store.LoadCurrentAsync(CancellationToken.None));
        Assert.Equal(source, store.LastSource); // Last completed load remains diagnostic only.
        Assert.Equal(before, File.Exists(cache) ? await File.ReadAllTextAsync(cache) : null);
        Assert.Equal(source == "default" ? 1 : 7, (await store.LoadAsync(CancellationToken.None)).Version);
    }

    [Fact]
    public async Task Valid_current_remote_policy_does_not_require_a_successful_disk_write()
    {
        string cache = Path.Combine(_workspace.Root, "cannot-replace-directory");
        Directory.CreateDirectory(cache);
        using var handler = new Handler();
        using var client = new HttpClient(handler) { BaseAddress = new Uri("http://policy.invalid/agent/") };
        var store = new DurableHttpPolicyStore(client, "TEST", cache, false);
        Assert.Equal(7, (await store.LoadCurrentAsync(CancellationToken.None)).Version);
        Assert.Equal("remote", store.LastSource);
        handler.Fail = true;
        Assert.Equal(7, (await store.LoadAsync(CancellationToken.None)).Version);
        await Assert.ThrowsAsync<HttpRequestException>(() => store.LoadCurrentAsync(CancellationToken.None));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Strict_decorator_reads_bypass_and_do_not_replace_the_legacy_snapshot(bool refreshing)
    {
        var inner = new ControlledStore();
        using var background = Refreshing(inner);
        IPolicyStore store = refreshing ? background : new CachedPolicyStore(inner, TimeSpan.FromHours(1));
        Assert.Equal(7, (await store.LoadAsync(CancellationToken.None)).Version);
        inner.Current = _ => Task.FromResult(Policy(9));
        Assert.Equal(9, (await store.LoadCurrentAsync(CancellationToken.None)).Version);
        Assert.Equal(9, (await store.LoadCurrentAsync(CancellationToken.None)).Version);
        Assert.Equal(2, inner.CurrentCalls);
        Assert.Equal(7, (await store.LoadAsync(CancellationToken.None)).Version);
        inner.Current = _ => throw new HttpRequestException("strict origin unavailable");
        await Assert.ThrowsAsync<HttpRequestException>(() => store.LoadCurrentAsync(CancellationToken.None));
        Assert.Equal(7, (await store.LoadAsync(CancellationToken.None)).Version);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Legacy_refresh_does_not_block_strict_decorator_reads_or_share_their_cancellation(bool refreshing)
    {
        var inner = new ControlledStore();
        using var background = Refreshing(inner);
        IPolicyStore store = refreshing ? background : new CachedPolicyStore(inner, TimeSpan.FromHours(1));
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<Policy>(TaskCreationOptions.RunContinuationsAsynchronously);
        inner.Legacy = async token => { started.SetResult(); return await release.Task.WaitAsync(token); };
        Task pending = refreshing ? background.RefreshAsync(CancellationToken.None) : store.LoadAsync(CancellationToken.None);
        try
        {
            await started.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(9, (await store.LoadCurrentAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5))).Version);
            using var cancelled = new CancellationTokenSource();
            cancelled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.LoadCurrentAsync(cancelled.Token));
            Assert.False(pending.IsCompleted);
            release.SetResult(Policy(8));
            await pending.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(8, (await store.LoadAsync(CancellationToken.None)).Version);
        }
        finally
        {
            release.TrySetResult(Policy(8));
            await pending.WaitAsync(TimeSpan.FromSeconds(5));
        }
    }

    [Fact]
    public async Task Strict_refreshing_read_does_not_initialize_a_disk_or_default_snapshot()
    {
        var inner = new ControlledStore();
        using var store = new RefreshingPolicyStore(inner, _ => throw new InvalidOperationException("must not restore"),
            TimeSpan.FromHours(1), NullLogger<RefreshingPolicyStore>.Instance);
        Assert.Equal(9, (await store.LoadCurrentAsync(CancellationToken.None)).Version);
        Assert.Equal(0, inner.LegacyCalls);
    }

    private static Policy Policy(int version) => LocalPolicyStore.CreateDefault() with { Version = version };
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Nonpositive_revisions_are_invalid(int version) =>
        Assert.Throws<InvalidPolicyException>(() => Policy(version).EnsureValid());

    [Fact]
    public void Undefined_domain_categories_are_invalid() => Assert.Throws<InvalidPolicyException>(() =>
        (Policy(7) with { ActiveCategories = new HashSet<Category> { (Category)999 } }).EnsureValid());

    private static RefreshingPolicyStore Refreshing(ControlledStore inner) => new(inner,
        _ => Task.FromResult(Policy(7)), TimeSpan.FromHours(1), NullLogger<RefreshingPolicyStore>.Instance);

    private sealed class ControlledStore : IPolicyStore
    {
        public int LegacyCalls, CurrentCalls;
        public Func<CancellationToken, Task<Policy>> Legacy = _ => Task.FromResult(Policy(7));
        public Func<CancellationToken, Task<Policy>> Current = _ => Task.FromResult(Policy(9));
        public Task<Policy> LoadAsync(CancellationToken token) { LegacyCalls++; return Legacy(token); }
        public Task<Policy> LoadCurrentAsync(CancellationToken token) { CurrentCalls++; return Current(token); }
    }

    private sealed class Handler : HttpMessageHandler
    {
        public bool Fail;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            if (Fail) throw new HttpRequestException("origin unavailable");
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            { Content = new StringContent("""{"version":7,"activeCategories":["Cpf"]}""") });
        }
    }
}
