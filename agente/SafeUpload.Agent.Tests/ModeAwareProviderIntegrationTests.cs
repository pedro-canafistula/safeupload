using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Dispatch;
using SafeUpload.Agent.Service.Policies;

namespace SafeUpload.Agent.Tests;

public sealed class ModeAwareProviderIntegrationTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    private readonly List<IDisposable> _decorators = [];
    public void Dispose()
    {
        foreach (var item in _decorators) item.Dispose();
        _workspace.Dispose();
    }

    private static readonly string[] Providers = ["durable", "cached", "refreshing", "nested"];
    public static IEnumerable<object[]> LimitCases()
    {
        foreach (string provider in Providers)
        {
            yield return [provider, "", 20, 5, 4096, 900];
            yield return [provider, ",\"maxFileSizeMb\":17", 17, 5, 17, 900];
            yield return [provider, ",\"inspectionTimeoutSeconds\":7", 20, 7, 4096, 7];
            yield return [provider, ",\"maxFileSizeMb\":32,\"inspectionTimeoutSeconds\":11", 32, 11, 32, 11];
        }
    }
    public static IEnumerable<object[]> NullCases()
    {
        foreach (string provider in Providers)
        foreach (string field in new[] { "maxFileSizeMb", "inspectionTimeoutSeconds" })
            yield return [provider, field];
    }

    private IPolicyStore Create(string shape, HttpClient client, out RefreshingPolicyStore? refreshing)
    {
        var durable = new DurableHttpPolicyStore(client, "MODE-TEST", Cache, enforceProtectedAcl: false);
        refreshing = null;
        if (shape == "durable") return durable;
        if (shape == "cached") return new CachedPolicyStore(durable, TimeSpan.FromHours(1));
        refreshing = new RefreshingPolicyStore(durable, TimeSpan.FromHours(1), NullLogger<RefreshingPolicyStore>.Instance);
        _decorators.Add(refreshing);
        return shape == "refreshing" ? refreshing : new CachedPolicyStore(refreshing, TimeSpan.FromHours(1));
    }
    private string Cache => Path.Combine(_workspace.Root, "policy-cache.json");
    private static string Document(string fields) => "{\"version\":7,\"activeCategories\":[\"Cpf\"]" + fields + "}";
    private static void Limits(Policy policy, int size, int seconds)
    {
        Assert.Equal(7, policy.Version);
        Assert.Equal(size, policy.MaxFileSizeMb);
        Assert.Equal(seconds, policy.InspectionTimeoutSeconds);
    }

    [Theory]
    [MemberData(nameof(LimitCases))]
    public async Task Strict_defaults_do_not_expand_legacy_memory_refresh_or_reopened_disk(
        string shape, string fields, int legacySize, int legacySeconds, int stagedSize, int stagedSeconds)
    {
        using var handler = new Handler { Json = Document(fields) };
        using var client = new HttpClient(handler) { BaseAddress = new Uri("http://policy.invalid/agent/") };
        var store = Create(shape, client, out var refreshing);
        // Strict first: offline memory/disk must still retain the legacy projection.
        Limits(await store.LoadCurrentAsync(default), stagedSize, stagedSeconds);
        Limits(await store.LoadAsync(default), legacySize, legacySeconds);
        if (refreshing is not null) await refreshing.RefreshAsync(default);
        Limits(await store.LoadAsync(default), legacySize, legacySeconds);
        Limits(await store.LoadCurrentAsync(default), stagedSize, stagedSeconds);
        Limits(await store.LoadAsync(default), legacySize, legacySeconds);
        using (var cache = JsonDocument.Parse(await File.ReadAllTextAsync(Cache)))
        {
            Assert.Equal(fields.Contains("maxFileSizeMb", StringComparison.Ordinal), cache.RootElement.TryGetProperty("maxFileSizeMb", out _));
            Assert.Equal(fields.Contains("inspectionTimeoutSeconds", StringComparison.Ordinal), cache.RootElement.TryGetProperty("inspectionTimeoutSeconds", out _));
        }
        string before = await File.ReadAllTextAsync(Cache);
        handler.Offline = true;
        await Assert.ThrowsAsync<HttpRequestException>(() => store.LoadCurrentAsync(default));
        Limits(await store.LoadAsync(default), legacySize, legacySeconds);
        if (refreshing is not null) await refreshing.RefreshAsync(default);
        Limits(await store.LoadAsync(default), legacySize, legacySeconds);
        var reopened = new DurableHttpPolicyStore(client, "MODE-TEST", Cache, enforceProtectedAcl: false);
        Limits(await reopened.LoadAsync(default), legacySize, legacySeconds);
        Assert.Equal("disk", reopened.LastSource);
        await Assert.ThrowsAsync<HttpRequestException>(() => reopened.LoadCurrentAsync(default));
        Assert.Equal(before, await File.ReadAllTextAsync(Cache));
    }

    [Theory]
    [MemberData(nameof(NullCases))]
    public async Task Explicit_null_never_replaces_prior_document_or_becomes_staged_authority(string shape, string field)
    {
        using var handler = new Handler { Json = Document("") };
        using var client = new HttpClient(handler) { BaseAddress = new Uri("http://policy.invalid/agent/") };
        var store = Create(shape, client, out var refreshing);
        Limits(await store.LoadCurrentAsync(default), 4096, 900);
        Limits(await store.LoadAsync(default), 20, 5);
        string before = await File.ReadAllTextAsync(Cache);
        handler.Json = Document(",\"" + field + "\":null");
        await Assert.ThrowsAsync<JsonException>(() => store.LoadCurrentAsync(default));
        if (refreshing is not null) await refreshing.RefreshAsync(default);
        Limits(await store.LoadAsync(default), 20, 5);
        Assert.Equal(before, await File.ReadAllTextAsync(Cache));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Shared_registration_preserves_provider_and_optional_hosted_services(bool hosted)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CentroAdministracao:BaseUrl"] = "http://policy.invalid/agent",
            ["CentroAdministracao:TimeoutSeconds"] = "7"
        }).Build();
        var services = new ServiceCollection().AddLogging();
        services.AddSingleton<IAuditSink>(new LocalQueueAuditSink(_workspace.QueueFile));
        services.AddAgentPolicies(config, "MODE-TEST", hosted);
        using var provider = services.BuildServiceProvider();
        Assert.Same(provider.GetRequiredService<RefreshingPolicyStore>(), provider.GetRequiredService<IPolicyStore>());
        using var client = provider.GetRequiredService<IHttpClientFactory>().CreateClient(PolicyServiceRegistration.HttpClientName);
        Assert.Equal(new Uri("http://policy.invalid/agent/"), client.BaseAddress);
        Assert.Equal(TimeSpan.FromSeconds(7), client.Timeout);
        var workers = provider.GetServices<IHostedService>().ToArray();
        if (hosted)
        {
            Assert.Equal(2, workers.Length);
            Assert.Same(provider.GetRequiredService<IPolicyStore>(), workers[0]);
            Assert.IsType<HttpAgentDispatcher>(workers[1]);
        }
        else Assert.Empty(workers);
        // No host is started and the protected cache is never read/written here.
    }

    private sealed class Handler : HttpMessageHandler
    {
        public string Json = Document("");
        public bool Offline;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Assert.Equal("?endpointId=MODE-TEST", request.RequestUri!.Query);
            return Task.FromResult(new HttpResponseMessage(Offline ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK)
            { Content = new StringContent(Json, Encoding.UTF8, "application/json") });
        }
    }
}
