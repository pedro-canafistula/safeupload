using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Service.Diagnostics;
using SafeUpload.Agent.Service.Policies;

// Reuses the existing disposable Java/MySQL fixture; does not install or reconfigure any service.
internal static class ConsolePolicyAcceptance
{
    internal static async Task RunAsync(HttpClient agent, int hostId, string workspace,
        Func<string, string, Task<int>> publish, Action<string, bool> check, CancellationToken token)
    {
        string root = Path.Combine(workspace, "central-policy");
        Directory.CreateDirectory(root);
        string cache = Path.Combine(root, "cache.json"), path = Path.Combine(root, "same-content.txt");
        await File.WriteAllTextAsync(path, "CPF: 529.982.247-25", token);
        int first = await publish("alertar", "cpf");
        var operational = LocalPolicyStore.CreateDefault() with
        {
            Version = first, ActiveCategories = new HashSet<Category> { Category.Cnpj },
            MonitoredScopes = new(new HashSet<string> { ".txt" }, [root], false, false)
        };
        var options = new ConsolePolicyOptions(hostId, "10.90.0.21");
        DurableHttpPolicyStore Remote(HttpClient http) => new(http, "SMOKE-AGENT", cache,
            enforceProtectedAcl: false, observer: new CommunicationHealth(true),
            consolePolicy: options, operationalPolicy: new FixturePolicy(operational));
        var remote = Remote(agent);
        using var snapshots = new RefreshingPolicyStore(remote, TimeSpan.FromSeconds(30), NullLogger<RefreshingPolicyStore>.Instance);
        var queue = new LocalQueueAuditSink(Path.Combine(root, "queue.jsonl"));
        var engine = new InspectionService(snapshots, queue, ExtractorRegistry.CreateDefault(), new VerdictCache());
        var operation = new FileOperation(path, "same-content.txt", ".txt", new FileInfo(path).Length,
            File.GetLastWriteTimeUtc(path), "contract-smoke", 1, path, DestinationKind.Cloud);
        var before = await engine.InspectAsync(operation, token);
        check("local policy fixture approves before central load", before.Verdict == Verdict.Approved && before.PolicyVersion == first);
        await snapshots.RefreshAsync(token);
        var loadedA = await snapshots.LoadAsync(token);
        var decisionA = await engine.InspectAsync(operation, token);
        // The engine reports findings. AuditOnly enforcement belongs to the channel, not this component fixture.
        check("central A reaches the engine despite local revision collision", decisionA.PolicyVersion == first &&
            decisionA.Categories.Contains(Category.Cpf) && !decisionA.FromCache && loadedA.AuditOnly &&
            loadedA.OverrideAllowed == operational.OverrideAllowed);
        check("central cache was persisted", File.Exists(cache) && remote.LastSource == "remote");
        int second = await publish("bloquear", "cnpj");
        check("publication creates a newer identified policy", second > first && first > 0);
        await snapshots.RefreshAsync(token);
        var decisionB = await engine.InspectAsync(operation, token);
        var loadedB = await snapshots.LoadAsync(token);
        check("central B changes the same file decision", decisionB.PolicyVersion == second &&
            decisionB.Verdict == Verdict.Approved && !decisionB.FromCache && !loadedB.AuditOnly);
        byte[] persisted = await File.ReadAllBytesAsync(cache, token);
        await remote.LoadAsync(token);
        byte[] repeated = await File.ReadAllBytesAsync(cache, token);
        check("repeated central publication is idempotent", persisted.SequenceEqual(repeated));
        using var offline = new HttpClient(new OfflineHandler()) { BaseAddress = agent.BaseAddress, Timeout = TimeSpan.FromSeconds(1) };
        var reopened = Remote(offline);
        var restored = await reopened.LoadCachedOrDefaultAsync(token);
        check("new provider restores central B from disk without network", restored.Version == second &&
            restored.ActiveCategories.SetEquals([Category.Cnpj]) && reopened.LastSource == "disk");
        check("offline classic read retains central B", (await reopened.LoadAsync(token)).Version == second);
        bool refused = false;
        try { await reopened.LoadCurrentAsync(token); }
        catch (HttpRequestException) { refused = true; }
        check("offline cache never substitutes current publication authority", refused);
        byte[] recovered = await File.ReadAllBytesAsync(cache, token);
        check("offline recovery preserves persisted central cache", persisted.SequenceEqual(recovered));
        var pending = await new LocalQueueAuditSink(queue.QueueFilePath).ReadPendingAsync(100, token);
        check("isolated policy decisions retain their revisions in the local queue", pending.Count == 3 &&
            pending.Count(e => e.PolicyVersion == first) == 2 && pending.Count(e => e.PolicyVersion == second) == 1);
    }

    private sealed class FixturePolicy(Policy policy) : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken token) => Task.FromResult(policy);
    }
    private sealed class OfflineHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) =>
            throw new HttpRequestException("Synthetic offline transport for the component cache check.");
    }
}
