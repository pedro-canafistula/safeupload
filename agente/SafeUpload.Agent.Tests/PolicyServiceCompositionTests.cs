using System.Net;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service;
using SafeUpload.Agent.Service.Dispatch;
using SafeUpload.Agent.Service.Interception;
using SafeUpload.Agent.Service.Policies;

namespace SafeUpload.Agent.Tests;

public sealed class PolicyServiceCompositionTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();

    private static IConfiguration Configuration(string? url = "http://policy.invalid/agent",
        string timeout = "5", string interval = "30") => new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["CentroAdministracao:BaseUrl"] = url,
                ["CentroAdministracao:TimeoutSeconds"] = timeout,
                ["CentroAdministracao:DispatchIntervalSeconds"] = interval
            }).Build();

    [Fact]
    public void Unconfigured_origin_uses_only_local_policy()
    {
        var services = new ServiceCollection();
        services.AddAgentPolicies(Configuration(""), "TEST");
        using var provider = services.BuildServiceProvider();
        Assert.IsType<LocalPolicyStore>(provider.GetRequiredService<IPolicyStore>());
        Assert.Empty(provider.GetServices<IHostedService>());
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Remote_service_and_seed_share_the_same_provider_and_HTTP_settings(bool hosted)
    {
        var services = new ServiceCollection().AddLogging();
        services.AddSingleton<IAuditSink>(new LocalQueueAuditSink(_workspace.QueueFile));
        services.AddAgentPolicies(Configuration(), "TEST", hosted);
        using var provider = services.BuildServiceProvider();
        var policy = provider.GetRequiredService<IPolicyStore>();
        Assert.Same(provider.GetRequiredService<RefreshingPolicyStore>(), policy);
        using var client = provider.GetRequiredService<IHttpClientFactory>()
            .CreateClient(PolicyServiceRegistration.HttpClientName);
        Assert.Equal(new Uri("http://policy.invalid/agent/"), client.BaseAddress);
        Assert.Equal(TimeSpan.FromSeconds(5), client.Timeout);
        var workers = provider.GetServices<IHostedService>().ToArray();
        if (hosted)
        {
            Assert.Equal(2, workers.Length);
            Assert.Same(policy, workers[0]);
            Assert.IsType<HttpAgentDispatcher>(workers[1]);
        }
        else Assert.Empty(workers);
    }

    [Theory]
    [InlineData("file:///C:/policy", "5", "30")]
    [InlineData("http://policy.invalid/", "0", "30")]
    [InlineData("http://policy.invalid/", "5", "-1")]
    [InlineData("http://policy.invalid/", "invalid", "30")]
    public void Invalid_remote_configuration_is_refused_before_startup(string url, string timeout, string interval)
    {
        var services = new ServiceCollection();
        Assert.Throws<InvalidOperationException>(() => services.AddAgentPolicies(Configuration(url, timeout, interval), "TEST"));
    }

    [Fact]
    public void Service_and_seed_resolve_settings_from_the_deployed_directory()
    {
        var builder = Program.CreateServiceBuilder([]);
        Assert.Equal(Path.GetFullPath(AppContext.BaseDirectory).TrimEnd(Path.DirectorySeparatorChar),
            Path.GetFullPath(builder.Environment.ContentRootPath).TrimEnd(Path.DirectorySeparatorChar));
    }

    [Fact]
    public async Task Host_waits_for_initial_remote_policy_before_starting_later_consumers()
    {
        using var handler = new Handler { WaitForPolicy = true };
        var probe = new Probe();
        using var host = CreateHost(handler, probe);
        var startup = host.StartAsync();
        try
        {
            await handler.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.False(startup.IsCompleted);
            Assert.False(probe.Started);
            handler.Release.SetResult();
            await startup.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.True(probe.Started);
            Assert.Equal(9, probe.Version);
            Assert.Equal(1, handler.PolicyCalls);
        }
        finally
        {
            handler.Release.TrySetResult();
            await startup.WaitAsync(TimeSpan.FromSeconds(5));
            await host.StopAsync().WaitAsync(TimeSpan.FromSeconds(5));
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Offline_startup_keeps_legacy_snapshot_but_strict_driver_read_still_fails(bool cached)
    {
        if (cached) await File.WriteAllTextAsync(_workspace.PolicyFile,
            """{"version":7,"activeCategories":["Cpf"]}""");
        using var handler = new Handler { Offline = true };
        var probe = new Probe();
        using var host = CreateHost(handler, probe);
        await host.StartAsync().WaitAsync(TimeSpan.FromSeconds(5));
        try
        {
            Assert.Equal(cached ? 7 : 1, probe.Version);
            await Assert.ThrowsAsync<HttpRequestException>(() => DriverPolicyLoader.LoadAsync(
                host.Services.GetRequiredService<IPolicyStore>(), CancellationToken.None));
            Assert.Equal(cached ? 7 : 1, (await host.Services.GetRequiredService<IPolicyStore>()
                .LoadAsync(CancellationToken.None)).Version);
        }
        finally { await host.StopAsync().WaitAsync(TimeSpan.FromSeconds(5)); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Configured_seed_uses_remote_strict_scope_and_preserves_prior_record_when_offline(bool offline)
    {
        const string prefix = @"\Device\HarddiskVolume7\RemoteProtected";
        using var handler = new Handler
        {
            Offline = offline,
            Document = """
                {"version":9,"activeCategories":["Cpf"],"monitoredScopes":{
                "extensions":[".txt"],"destinationPaths":["\\Device\\HarddiskVolume7\\RemoteProtected"],
                "removableDrives":false,"networkPaths":false}}
                """
        };
        var seedBuilder = Program.CreateBootPolicyBuilder(["--CentroAdministracao:BaseUrl=http://policy.invalid/agent"]);
        var services = seedBuilder.Services;
        services.AddHttpClient(PolicyServiceRegistration.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => handler);
        services.Replace(ServiceDescriptor.Singleton(provider => new DurableHttpPolicyStore(
            provider.GetRequiredService<IHttpClientFactory>().CreateClient(PolicyServiceRegistration.HttpClientName),
            "TEST", _workspace.PolicyFile, enforceProtectedAcl: false)));
        using var provider = services.BuildServiceProvider();
        var backend = new RegistryReceipt();
        var prior = backend.Committed.ToArray();
        var seed = BootPolicySeeder.SeedAsync(provider.GetRequiredService<IPolicyStore>(),
            new BootPolicyRegistryWriter(backend), CancellationToken.None);
        if (offline)
        {
            await Assert.ThrowsAsync<HttpRequestException>(() => seed);
            Assert.Equal(prior, backend.Committed);
            Assert.Equal(0, backend.Writes);
        }
        else
        {
            await seed;
            Assert.Equal([prefix], BootPolicyCodec.DecodeKnown(backend.Committed).Prefixes);
            Assert.Equal(0u, BootPolicyCodec.DecodeKnown(backend.Committed).Flags);
            Assert.Equal(3, backend.Writes);
        }
        Assert.Null(backend.Pending);
        Assert.Empty(provider.GetServices<IHostedService>());
        Assert.Equal(1, handler.PolicyCalls);
    }

    private sealed class RegistryReceipt : IBootPolicyRegistryBackend
    {
        public byte[] Committed = BootPolicyCodec.Encode(new BootPolicyScopes(
            [@"\Device\HarddiskVolume7\Previous"], 0));
        public byte[]? Pending;
        public int Writes;
        public BootPolicyScopes ReadKnownScopes() => BootPolicyCodec.DecodeKnown(Committed);
        public void WritePending(byte[] value) { Writes++; Pending = value; }
        public void WriteCommitted(byte[] value) { Writes++; Committed = value; }
        public void ClearPending() { Writes++; Pending = null; }
        public void VerifySeeded(byte[] expectedCommitted)
        { Assert.Equal(expectedCommitted, Committed); Assert.Null(Pending); }
    }

    private IHost CreateHost(Handler handler, Probe probe) => new HostBuilder().ConfigureServices(services =>
    {
        services.AddSingleton<IAuditSink>(new LocalQueueAuditSink(_workspace.QueueFile));
        services.AddAgentPolicies(Configuration(), "TEST");
        services.AddHttpClient(PolicyServiceRegistration.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => handler);
        // Only replace the cache location/ACL in the test container. Production
        // registration keeps the public ACL-enforcing constructor.
        services.Replace(ServiceDescriptor.Singleton(provider => new DurableHttpPolicyStore(
            provider.GetRequiredService<IHttpClientFactory>().CreateClient(PolicyServiceRegistration.HttpClientName),
            "TEST", _workspace.PolicyFile, enforceProtectedAcl: false)));
        services.AddSingleton<IHostedService>(provider =>
        {
            probe.PolicyStore = provider.GetRequiredService<IPolicyStore>();
            return probe;
        });
    }).Build();

    private sealed class Probe : IHostedService
    {
        public IPolicyStore PolicyStore = null!;
        public bool Started;
        public int Version;
        public async Task StartAsync(CancellationToken token)
        { Version = (await PolicyStore.LoadAsync(token)).Version; Started = true; }
        public Task StopAsync(CancellationToken token) => Task.CompletedTask;
    }

    private sealed class Handler : HttpMessageHandler
    {
        public bool Offline, WaitForPolicy;
        public string Document = """{"version":9,"activeCategories":["Cpf"]}""";
        public int PolicyCalls;
        public TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("/policy"))
            {
                Interlocked.Increment(ref PolicyCalls);
                Started.TrySetResult();
                if (WaitForPolicy) await Release.Task.WaitAsync(token);
                if (Offline) throw new HttpRequestException("controlled offline server");
                return new HttpResponseMessage(HttpStatusCode.OK)
                { Content = new StringContent(Document) };
            }
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}") };
        }
    }
}
