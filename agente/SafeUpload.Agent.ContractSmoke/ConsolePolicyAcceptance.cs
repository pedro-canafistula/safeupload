using Microsoft.Extensions.Logging.Abstractions;
using System.Text.Json;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Service.Diagnostics;
using SafeUpload.Agent.Service.Policies;

// Reuses the existing disposable Java/MySQL fixture; does not install or reconfigure any service.
internal static class ConsolePolicyAcceptance
{
    // Run in a fresh process after the disposable Java backend has actually been stopped.
    // This remains a component probe: no service installation, protected ACL or native mount is qualified.
    internal static async Task RunOfflineAsync(string root, int hostId, string ip, int revision)
    {
        using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var token = budget.Token;
        using var http = new HttpClient { BaseAddress = new Uri("http://127.0.0.1:18080/agent/"), Timeout = TimeSpan.FromSeconds(1) };
        string cache = Path.Combine(root, "cache.json");
        byte[] before = await File.ReadAllBytesAsync(cache, token);
        var remote = new DurableHttpPolicyStore(http, "SMOKE-AGENT", cache, false,
            consolePolicy: new ConsolePolicyOptions(hostId, ip), operationalPolicy: new LocalPolicyStore(Path.Combine(root, "operational.json")));
        bool unreachable = false;
        try { using var response = await http.GetAsync("api/policy?ip=" + Uri.EscapeDataString(ip), token); }
        catch (HttpRequestException error) when (error.StatusCode is null) { unreachable = true; }
        catch (OperationCanceledException) when (!token.IsCancellationRequested) { unreachable = true; }
        if (!unreachable) throw new InvalidOperationException("Expected a stopped backend, not an HTTP error fixture.");
        var restored = await remote.LoadCachedOrDefaultAsync(token);
        if (restored.Version != revision || remote.LastSource != "disk") throw new InvalidOperationException("Expected durable central revision.");
        using var snapshots = new RefreshingPolicyStore(remote, TimeSpan.FromSeconds(30), NullLogger<RefreshingPolicyStore>.Instance);
        await snapshots.StartAsync(token);
        try
        {
            string path = Path.Combine(root, "same-content.txt");
            var engine = new InspectionService(snapshots, new LocalQueueAuditSink(Path.Combine(root, "offline-queue.jsonl")),
                ExtractorRegistry.CreateDefault(), new VerdictCache());
            var decision = await engine.InspectAsync(new FileOperation(path, "same-content.txt", ".txt", new FileInfo(path).Length,
                File.GetLastWriteTimeUtc(path), "contract-smoke", 1, path, DestinationKind.Cloud), token);
            byte[] after = await File.ReadAllBytesAsync(cache, token);
            if (decision.PolicyVersion != revision || decision.Verdict != Verdict.Approved || !before.SequenceEqual(after))
                throw new InvalidOperationException("Offline inspection did not preserve the validated CNPJ policy.");
            Console.WriteLine("ConsoleOfflineActualConnectionFailure=True;NewProcess=True;Source=Disk;AppliedRevision=" + revision +
                ";Classification=Approved;CacheUnchanged=True;InstalledServiceQualified=False;NativeDriveQualified=False");
        }
        finally { await snapshots.StopAsync(CancellationToken.None); }
    }

    internal static async Task RunAsync(HttpClient agent, int hostId, string workspace,
        Func<string, string, Task<int>> publish, Action<string, bool> check, CancellationToken token)
    {
        string root = Path.Combine(workspace, "central-policy");
        Directory.CreateDirectory(root);
        string cache = Path.Combine(root, "cache.json"), path = Path.Combine(root, "same-content.txt");
        await File.WriteAllTextAsync(path, "CPF: 529.982.247-25", token);
        int first = await publish("bloquear", "cpf");
        var operational = LocalPolicyStore.CreateDefault() with
        {
            Version = first, ActiveCategories = new HashSet<Category> { Category.Cnpj }, OverrideAllowed = true,
            MonitoredScopes = new(new HashSet<string> { ".txt" }, [root], false, false)
        };
        string operationalFile = Path.Combine(root, "operational.json");
        await File.WriteAllTextAsync(operationalFile, JsonSerializer.Serialize(PolicyDocument.FromPolicy(operational)), token);
        var options = new ConsolePolicyOptions(hostId, "10.90.0.21");
        DurableHttpPolicyStore Remote(HttpClient http) => new(http, "SMOKE-AGENT", cache,
            enforceProtectedAcl: false, observer: new CommunicationHealth(true),
            consolePolicy: options, operationalPolicy: new LocalPolicyStore(operationalFile));
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
            decisionA.Verdict == Verdict.Blocked && decisionA.Categories.Contains(Category.Cpf) && !decisionA.FromCache && !loadedA.AuditOnly &&
            loadedA.OverrideAllowed == operational.OverrideAllowed);
        check("central cache was persisted", File.Exists(cache) && remote.LastSource == "remote");
        await File.WriteAllTextAsync(operationalFile,
            JsonSerializer.Serialize(PolicyDocument.FromPolicy(operational with { OverrideAllowed = false })), token);
        await snapshots.RefreshAsync(token);
        check("local revocation applies without a new central publication", !(await snapshots.LoadAsync(token)).OverrideAllowed &&
            (await snapshots.LoadAsync(token)).Version == first && remote.LastSource == "remote");
        check("reopened current read preserves local revocation with the same central revision",
            !(await Remote(agent).LoadCurrentAsync(token)).OverrideAllowed);
        int alert = await publish("alertar", "cpf");
        await snapshots.RefreshAsync(token);
        var alertPolicy = await snapshots.LoadAsync(token);
        var alertFinding = await engine.InspectAsync(operation, token);
        check("new alert action reaches snapshot and preserves completed CPF finding", alert > first && alertPolicy.AuditOnly &&
            alertFinding.PolicyVersion == alert && alertFinding.Categories.Contains(Category.Cpf) &&
            alertFinding.Reason is null && !alertFinding.FromCache);
        int second = await publish("bloquear", "cnpj");
        check("publication creates a newer identified policy", second > alert && first > 0);
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
        check("isolated policy decisions retain their revisions in the local queue", pending.Count == 4 &&
            pending.Count(e => e.PolicyVersion == first) == 2 && pending.Count(e => e.PolicyVersion == alert) == 1 &&
            pending.Count(e => e.PolicyVersion == second) == 1);
        Console.WriteLine("CONSOLE_POLICY_EVIDENCE=" + JsonSerializer.Serialize(new {
            hostId, hostIp = options.HostIp,
            before = new { revision = first, action = "bloquear", categories = loadedA.ActiveCategories.Select(c => c.ToString()), classification = decisionA.Verdict.ToString() },
            alert = new { revision = alert, action = "alertar", categories = alertPolicy.ActiveCategories.Select(c => c.ToString()), classification = alertFinding.Verdict.ToString(), channelReleaseQualified = false },
            after = new { revision = second, action = "bloquear", categories = loadedB.ActiveCategories.Select(c => c.ToString()), classification = decisionB.Verdict.ToString() },
            cache, appliedByEngine = true, nativeDriveQualified = false, offlineTransport = "controlled component failure"
        }));
    }
    private sealed class OfflineHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) =>
            throw new HttpRequestException("Synthetic offline transport for the component cache check.");
    }
}
