using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Service.Dispatch;
using SafeUpload.Agent.Service.Policies;

internal static class PolicyPublicationContract
{
    internal static async Task RunAsync(string[] args)
    {
        if (args.Length != 6)
            throw new ArgumentException("--policy-publication-contract temporary-root root-URL test-endpoint expected-version categories-CSV");
        string root = Path.GetFullPath(args[1]), endpoint = args[3];
        var uri = new Uri(args[2]);
        string temporary = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!root.StartsWith(temporary, StringComparison.OrdinalIgnoreCase) || !uri.IsLoopback || uri.Scheme != "http"
            || !endpoint.StartsWith("M2-POLICY-ANGULAR-", StringComparison.Ordinal))
            throw new ArgumentException("Only an isolated temporary directory, loopback HTTP and synthetic endpoint are allowed.");
        int version = int.Parse(args[4]);
        var expected = args[5].Split(',').Select(value => Enum.Parse<Category>(value, false)).ToHashSet();
        if (version is < 1 or > 3 || expected.Count == 0 || expected.Any(category => !Enum.IsDefined(category)))
            throw new ArgumentException("Invalid expected publication.");
        Directory.CreateDirectory(root);
        string receipt = Path.Combine(root, $"receipt-v{version}.json");
        if (File.Exists(receipt)) throw new InvalidOperationException("Preserve prior receipts; use a fresh test root.");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(40));
        var token = deadline.Token;
        var json = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
        var checks = new List<string>();
        var result = new Dictionary<string, object?> { ["status"] = "running", ["endpointId"] = endpoint,
            ["expectedVersion"] = version, ["expectedCategories"] = expected, ["checks"] = checks };
        void Check(bool condition, string description)
        { if (!condition) throw new InvalidOperationException(description); checks.Add(description); }
        try
        {
            using var agent = new HttpClient { BaseAddress = new Uri(uri, "agent/"), Timeout = TimeSpan.FromSeconds(5) };
            var durable = new DurableHttpPolicyStore(agent, endpoint, Path.Combine(root, "policy-cache.json"), false);
            using var snapshot = new RefreshingPolicyStore(durable, TimeSpan.FromSeconds(30), NullLogger<RefreshingPolicyStore>.Instance);
            var initial = await snapshot.LoadAsync(token);
            result["initialVersion"] = initial.Version;
            result["initialSource"] = durable.LastSource;
            Check(initial.Version == (version == 1 ? 1 : version - 1), "legacy snapshot starts from the preceding revision");
            if (version > 1) Check(durable.LastSource == "disk", "preceding revision restored from the actual cache file");
            var current = await snapshot.LoadCurrentAsync(token);
            result["strictPolicy"] = current;
            Check(durable.LastSource == "remote", "strict load used actual Java HTTP without fallback");
            Check(current.Version == version && current.ActiveCategories.SetEquals(expected), "revision and exact selected categories match the publication");
            var stillInitial = await snapshot.LoadAsync(token);
            Check(stillInitial.Version == initial.Version && stillInitial.ActiveCategories.SetEquals(initial.ActiveCategories),
                "strict load does not silently replace the legacy snapshot");
            await snapshot.RefreshAsync(token);
            var refreshed = await snapshot.LoadAsync(token);
            Check(refreshed.Version == version && refreshed.ActiveCategories.SetEquals(expected), "real refresh cycle advances the legacy snapshot");
            var wire = await agent.GetFromJsonAsync<JsonElement>($"policy?endpointId={Uri.EscapeDataString(endpoint)}", token);
            await File.WriteAllTextAsync(Path.Combine(root, $"wire-v{version}.json"), wire.GetRawText(), token);
            var scopes = wire.GetProperty("monitoredScopes");
            Check(wire.GetProperty("version").GetInt32() == current.Version
                && current.ActiveCategories.SetEquals(wire.GetProperty("activeCategories").EnumerateArray().Select(x => Enum.Parse<Category>(x.GetString()!))),
                "Java JSON and agent domain agree on version and categories");
            Check(current.MonitoredScopes.Extensions.SetEquals(scopes.GetProperty("extensions").EnumerateArray().Select(x => x.GetString()!))
                && current.MonitoredScopes.DestinationPaths.SequenceEqual(scopes.GetProperty("destinationPaths").EnumerateArray().Select(x => x.GetString()!))
                && current.MonitoredScopes.RemovableDrives == scopes.GetProperty("removableDrives").GetBoolean()
                && current.MonitoredScopes.NetworkPaths == scopes.GetProperty("networkPaths").GetBoolean(), "scope fields survive Java to C# translation");
            Check(current.MaxFileSizeMb == wire.GetProperty("maxFileSizeMb").GetInt32()
                && current.InspectionTimeoutSeconds == wire.GetProperty("inspectionTimeoutSeconds").GetInt32()
                && current.FailOpen == wire.GetProperty("failOpen").GetBoolean()
                && current.AuditOnly == wire.GetProperty("auditOnly").GetBoolean()
                && current.OverrideAllowed == wire.GetProperty("overrideAllowed").GetBoolean()
                && current.ExcludedProcesses.SetEquals(wire.GetProperty("excludedProcesses").EnumerateArray().Select(x => x.GetString()!)),
                "limits and operating flags survive Java to C# translation");
            Check(current.EffectiveClipboard.Mode == ClipboardMode.Off && wire.GetProperty("clipboard").GetProperty("mode").GetString() == "Off",
                "publication keeps clipboard disabled");
            Check(!current.MonitoredScopes.RemovableDrives && !current.MonitoredScopes.NetworkPaths,
                "current M2 publication keeps unqualified removable and network scopes disabled");
            string file = Path.Combine(root, "synthetic-policy-cpf.txt");
            await File.WriteAllTextAsync(file, "CPF: 529.982.247-25", token);
            var operation = new FileOperation(file, "synthetic-policy-cpf.txt", ".txt", new FileInfo(file).Length,
                File.GetLastWriteTimeUtc(file), "contract-policy", Environment.ProcessId,
                Path.Combine(current.MonitoredScopes.DestinationPaths.First(), "synthetic-policy-cpf.txt"), DestinationKind.Cloud);
            var queue = new LocalQueueAuditSink(Path.Combine(root, "queue.jsonl"));
            var inspector = new InspectionService(snapshot, queue, ExtractorRegistry.CreateDefault(), new VerdictCache(), endpoint, "synthetic-policy-user");
            var inspection = await inspector.InspectStagedAsync(operation, token);
            result["cpfFixtureVerdict"] = inspection.Verdict;
            result["inspectionPolicyVersion"] = inspection.PolicyVersion;
            Check(inspection.InScope && !inspection.FromCache && inspection.PolicyVersion == version,
                "real staged inspection uses the published revision in scope");
            Check(inspection.Verdict == (expected.Contains(Category.Cpf) ? Verdict.Blocked : Verdict.Approved),
                "CPF fixture follows the explicitly selected categories");
            using var dispatcher = new HttpAgentDispatcher(queue, snapshot, agent, endpoint, TimeSpan.FromSeconds(30), NullLogger<HttpAgentDispatcher>.Instance);
            await dispatcher.RunCycleAsync(token);
            Check((await queue.ReadPendingAsync(100, token)).Count == 0, "probe heartbeat creates no synthetic transfer events");
            using var cache = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(root, "policy-cache.json"), token));
            Check(cache.RootElement.GetProperty("version").GetInt32() == version, "cache persists the current published revision");
            result["status"] = "passed";
        }
        catch (Exception exception)
        {
            result["status"] = "failed";
            result["error"] = exception.Message;
            throw;
        }
        finally
        {
            result["finishedAtUtc"] = DateTimeOffset.UtcNow;
            await File.WriteAllTextAsync(receipt, JsonSerializer.Serialize(result, json));
            Console.WriteLine(JsonSerializer.Serialize(result, json));
        }
    }
}
