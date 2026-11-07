using System.Net;
using System.Text.Json;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.Tests;

public sealed class PolicyDuplicateFieldTests
{
    private const string Good = """{"version":7,"activeCategories":["Cpf"],"maxFileSizeMb":1}""";
    public static IEnumerable<object[]> Documents()
    {
        foreach (string fields in new[]
        {
            "\"version\":8,\"version\":9",
            "\"version\":8,\"VERSION\":9",
            "\"version\":8,\"maxFileSizeMb\":1,\"maxFileSizeMb\":4096",
            "\"version\":8,\"overrideAllowed\":false,\"OverrideAllowed\":true",
            "\"version\":8,\"auditOnly\":false,\"auditOnly\":true",
            "\"version\":8,\"monitoredScopes\":{\"extensions\":[\".txt\"],\"Extensions\":[\".pdf\"]}",
            "\"version\":8,\"ver\\u0073ion\":9",
            "\"version\":8,\"ActiveCategories\":[\"Cnpj\"]",
            "\"version\":8,\"clipboard\":{\"mode\":\"Block\",\"MODE\":\"Off\"}"
        }) yield return ["{\"activeCategories\":[\"Cpf\"]," + fields + "}"];
    }

    [Theory]
    [MemberData(nameof(Documents))]
    public async Task Local_policy_rejects_duplicate_fields_in_both_consumption_modes(string document)
    {
        using var workspace = new TestWorkspace();
        workspace.WritePolicy(document);
        var store = new LocalPolicyStore(workspace.PolicyFile);
        await Assert.ThrowsAsync<JsonException>(() => store.LoadAsync(default));
        workspace.WritePolicy(Good);
        Assert.Equal(7, (await store.LoadCurrentAsync(default)).Version);
    }

    [Theory]
    [MemberData(nameof(Documents))]
    public async Task Durable_remote_rejects_duplicate_fields_without_overwriting_last_known_good(string document)
    {
        using var workspace = new TestWorkspace();
        var handler = new Handler { Body = Good };
        using var http = Client(handler);
        var store = new DurableHttpPolicyStore(http, TestPolicies.Identity(http.BaseAddress!), workspace.PolicyFile, TestPolicies.Local, false);
        var original = await store.LoadAsync(default);
        byte[] persisted = await File.ReadAllBytesAsync(workspace.PolicyFile);
        handler.Body = document;
        Assert.Same(original, await store.LoadAsync(default));
        Assert.Equal(persisted, await File.ReadAllBytesAsync(workspace.PolicyFile));
        var restarted = new DurableHttpPolicyStore(http, TestPolicies.Identity(http.BaseAddress!), workspace.PolicyFile, TestPolicies.Local, false);
        Assert.Equal(7, (await restarted.LoadCachedOrDefaultAsync(default)).Version);
    }

    [Theory]
    [MemberData(nameof(Documents))]
    public async Task Ambiguous_durable_cache_is_not_restored_as_valid_policy(string document)
    {
        using var workspace = new TestWorkspace();
        workspace.WritePolicy(document);
        byte[] before = await File.ReadAllBytesAsync(workspace.PolicyFile);
        using var http = Client(new Handler { Body = Good });
        var store = new DurableHttpPolicyStore(http, TestPolicies.Identity(http.BaseAddress!), workspace.PolicyFile, TestPolicies.Local, false);
        Assert.Equal(LocalPolicyStore.CreateDefault().Version, (await store.LoadCachedOrDefaultAsync(default)).Version);
        Assert.Equal(before, await File.ReadAllBytesAsync(workspace.PolicyFile));
    }


    [Fact]
    public async Task Existing_local_comments_trailing_commas_and_case_insensitive_fields_remain_supported()
    {
        using var workspace = new TestWorkspace();
        workspace.WritePolicy("""
            { // Local configuration format already supports comments.
              "VERSION":7, "ActiveCategories":["Cpf",], "maxFileSizeMb":1,
              "monitoredScopes":{"extensions":["txt",], "destinationPaths":[],},
            }
            """);
        var store = new LocalPolicyStore(workspace.PolicyFile);
        foreach (var policy in new[] { await store.LoadAsync(default), await store.LoadCurrentAsync(default) })
        {
            Assert.Equal(7, policy.Version);
            Assert.True(policy.IsMonitoredExtension(".txt"));
            Assert.Equal(Category.Cpf, Assert.Single(policy.ActiveCategories));
        }
    }

    private static HttpClient Client(Handler handler) => new(handler) { BaseAddress = new("https://example.invalid/agent/") };
    private sealed class Handler : HttpMessageHandler
    {
        public required string Body;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Body) });
    }
}
