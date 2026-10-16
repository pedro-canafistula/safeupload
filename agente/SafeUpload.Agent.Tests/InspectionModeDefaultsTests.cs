using System.Net;
using System.Text;
using System.Text.Json;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.Tests;

public sealed class InspectionModeDefaultsTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();

    [Theory]
    [InlineData("", 20, 5, 4096, 900)]
    [InlineData(",\"maxFileSizeMb\":17", 17, 5, 17, 900)]
    [InlineData(",\"inspectionTimeoutSeconds\":7", 20, 7, 4096, 7)]
    [InlineData(",\"maxFileSizeMb\":32,\"inspectionTimeoutSeconds\":11", 32, 11, 32, 11)]
    public async Task Local_and_remote_consumers_select_mode_defaults_but_preserve_each_explicit_setting(
        string fields, int legacySize, int legacyTime, int stagedSize, int stagedTime)
    {
        string json = "{\"version\":7,\"activeCategories\":[\"Cpf\"]" + fields + "}";
        await File.WriteAllTextAsync(_workspace.PolicyFile, json);
        var local = new LocalPolicyStore(_workspace.PolicyFile);
        using var client = new HttpClient(new Response(json)) { BaseAddress = new Uri("http://policy.invalid/") };
        var remote = new HttpPolicyStore(client, "fixture");
        foreach (var store in new SafeUpload.Agent.Core.Application.IPolicyStore[] { local, remote })
        {
            var legacy = await store.LoadAsync(default); var staged = await store.LoadCurrentAsync(default);
            Assert.Equal(legacySize, legacy.MaxFileSizeMb); Assert.Equal(legacyTime, legacy.InspectionTimeoutSeconds);
            Assert.Equal(stagedSize, staged.MaxFileSizeMb); Assert.Equal(stagedTime, staged.InspectionTimeoutSeconds);
            Assert.Equal(7, legacy.Version); Assert.Equal(legacy.Version, staged.Version);
            if (legacySize != stagedSize || legacyTime != stagedTime)
                Assert.NotEqual(PolicyContentFingerprint.Compute(legacy), PolicyContentFingerprint.Compute(staged));
            else Assert.Equal(PolicyContentFingerprint.Compute(legacy), PolicyContentFingerprint.Compute(staged));
        }
    }

    [Theory]
    [InlineData("maxFileSizeMb")]
    [InlineData("inspectionTimeoutSeconds")]
    public async Task Explicit_null_is_malformed_in_both_modes_and_transports(string field)
    {
        string json = "{\"version\":1,\"activeCategories\":[\"Cpf\"],\"" + field + "\":null}";
        await File.WriteAllTextAsync(_workspace.PolicyFile, json);
        var local = new LocalPolicyStore(_workspace.PolicyFile);
        await Assert.ThrowsAsync<JsonException>(() => local.LoadAsync(default));
        await Assert.ThrowsAsync<JsonException>(() => local.LoadCurrentAsync(default));
        using var client = new HttpClient(new Response(json)) { BaseAddress = new Uri("http://policy.invalid/") };
        var remote = new HttpPolicyStore(client, "fixture");
        await Assert.ThrowsAsync<JsonException>(() => remote.LoadCurrentAsync(default));
        Assert.Equal(20, (await remote.LoadAsync(default)).MaxFileSizeMb); // Existing legacy transport fallback only.
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Provisioning_from_either_mode_does_not_serialize_one_modes_defaults_as_an_override(bool stagedFirst)
    {
        var store = new LocalPolicyStore(_workspace.PolicyFile);
        _ = stagedFirst ? await store.LoadCurrentAsync(default) : await store.LoadAsync(default);
        using var json = JsonDocument.Parse(await File.ReadAllTextAsync(_workspace.PolicyFile));
        Assert.False(json.RootElement.TryGetProperty("maxFileSizeMb", out _));
        Assert.False(json.RootElement.TryGetProperty("inspectionTimeoutSeconds", out _));
        Assert.Equal(20, (await new LocalPolicyStore(_workspace.PolicyFile).LoadAsync(default)).MaxFileSizeMb);
        Assert.Equal(5, (await store.LoadAsync(default)).InspectionTimeoutSeconds);
        Assert.Equal(4096, (await new LocalPolicyStore(_workspace.PolicyFile).LoadCurrentAsync(default)).MaxFileSizeMb);
        Assert.Equal(900, (await store.LoadCurrentAsync(default)).InspectionTimeoutSeconds);
    }

    [Fact]
    public async Task A_staged_read_cannot_enlarge_the_legacy_last_good_acl_fallback()
    {
        await File.WriteAllTextAsync(_workspace.PolicyFile, "{\"version\":1,\"activeCategories\":[\"Cpf\"]}");
        bool trusted = true;
        var store = new LocalPolicyStore(_workspace.PolicyFile, _ => trusted);
        Assert.Equal(4096, (await store.LoadCurrentAsync(default)).MaxFileSizeMb);
        trusted = false;
        var legacy = await store.LoadAsync(default);
        Assert.Equal(20, legacy.MaxFileSizeMb); Assert.Equal(5, legacy.InspectionTimeoutSeconds);
        await Assert.ThrowsAsync<PolicyFileAclRejectedException>(() => store.LoadCurrentAsync(default));
    }

    private sealed class Response(string json) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                { Content = new StringContent(json, Encoding.UTF8, "application/json") });
    }
}
