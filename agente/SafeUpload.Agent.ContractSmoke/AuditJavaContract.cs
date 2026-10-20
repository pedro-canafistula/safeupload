using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Service.Dispatch;

internal static class AuditJavaContract
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    { Converters = { new JsonStringEnumConverter() } };
    private const string Endpoint = "M2-JAVA-AUDIT";
    private const string Sid = "S-1-5-21-123-456-789-1001";
    private const string Email = "m2-contract@example.com", Password = "synthetic-local-test-123";

    internal static async Task RunAsync(string[] args)
    {
        if (args.Length != 4 || args[1] is not ("online" or "offline" or "recover" or "verify"))
            throw new ArgumentException("--audit-java-contract online|offline|recover|verify temporary-directory root-URL");
        string phase = args[1], root = Path.GetFullPath(args[2]);
        string temporary = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var uri = new Uri(args[3]);
        if (!root.StartsWith(temporary, StringComparison.OrdinalIgnoreCase) || !uri.IsLoopback || uri.Scheme != "http")
            throw new ArgumentException("This probe requires a temporary directory and loopback HTTP.");
        Directory.CreateDirectory(root);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(40));
        var token = deadline.Token;
        using var client = new HttpClient { BaseAddress = uri, Timeout = TimeSpan.FromSeconds(3) };
        using var agent = new HttpClient { BaseAddress = new Uri(uri, "agent/"), Timeout = TimeSpan.FromSeconds(3) };
        var policies = new DurableHttpPolicyStore(agent, Endpoint, Path.Combine(root, "policy-cache.json"), false);
        var sink = new LocalQueueAuditSink(Path.Combine(root, "queue.jsonl"));
        string statePath = Path.Combine(root, "state.json");
        JsonArray batches = File.Exists(statePath)
            ? JsonNode.Parse(await File.ReadAllTextAsync(statePath, token))!.AsArray() : [];
        var checks = new List<string>();
        void Check(bool condition, string description)
        { if (!condition) throw new InvalidOperationException(description); checks.Add(description); }

        if (phase == "online")
        {
            Check(batches.Count == 0 && !File.Exists(sink.QueueFilePath), "fresh isolated queue");
            using var denied = await client.GetAsync("api/auditoria", token);
            Check(denied.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden, "administrative audit requires authentication");
            using var registration = await client.PostAsJsonAsync("api/auth/cadastro", new
            { nomeCompleto = "M2 Contract", username = "m2-contract", email = Email, cpf = "52998224725", senha = Password, confirmarSenha = Password }, token);
            registration.EnsureSuccessStatusCode();
            var policy = await policies.LoadCurrentAsync(token);
            Check(policies.LastSource == "remote" && File.Exists(Path.Combine(root, "policy-cache.json")), "strict remote policy persisted for legacy recovery");
            Check(!policy.MonitoredScopes.RemovableDrives && !policy.MonitoredScopes.NetworkPaths,
                "current Java defaults keep unqualified removable and network scopes disabled");
            Check(policy.MaxFileSizeMb == 20 && policy.InspectionTimeoutSeconds == 5,
                "explicit Java inspection limits survive strict M2 loading");
            string file = Path.Combine(root, "synthetic.txt");
            await File.WriteAllTextAsync(file, "CPF: 529.982.247-25", token);
            var operation = new FileOperation(file, "synthetic.txt", ".txt", new FileInfo(file).Length,
                File.GetLastWriteTimeUtc(file), "contract", Environment.ProcessId,
                Path.Combine(policy.MonitoredScopes.DestinationPaths.First(), "synthetic.txt"), DestinationKind.Cloud);
            var inspector = new InspectionService(policies, sink, ExtractorRegistry.CreateDefault(), new VerdictCache(), Endpoint, Sid);
            var result = await inspector.InspectStagedAsync(operation, token);
            Check(result.Verdict == Verdict.Blocked, "real M2 inspection blocks synthetic CPF");
            var id = Guid.NewGuid();
            await inspector.RecordTransferOutcomeAsync(operation, result, Verdict.Blocked, "synthetic blocked outcome", token, id);
            await sink.RecordOverrideAsync(new AuditOverride(id, "Synthetic authorized purpose", DateTimeOffset.UtcNow, Sid, Endpoint), token);
            await SaveBatchAsync();
            await DispatchAsync(sink, policies, agent, token);
            await CheckLocalConfirmedAsync(2);
            await VerifyServerAsync(1);
        }
        else if (phase == "offline")
        {
            var recovered = await policies.LoadAsync(token);
            Check(policies.LastSource == "disk", "new process restores legacy policy from disk while Java is stopped");
            bool refused = false;
            try { await policies.LoadCurrentAsync(token); }
            catch (HttpRequestException) { refused = true; }
            Check(refused, "strict current-policy read refuses actual connection failure");
            var id = Guid.NewGuid();
            // This is an observed/synthetic blocked outcome, not an approval or
            // a claim that content was inspected successfully while offline.
            await sink.WriteAsync(new AuditEvent(id, DateTimeOffset.UtcNow, Endpoint, Sid, "offline.txt", ".txt", 12,
                Verdict.Blocked, [], [], "contract", Environment.ProcessId, @"C:\Synthetic", "current_policy_unavailable",
                recovered.Version, 1, false), token);
            await sink.RecordOverrideAsync(new AuditOverride(id, "Offline synthetic audit only", DateTimeOffset.UtcNow, Sid, Endpoint), token);
            await SaveBatchAsync();
            bool dispatchFailed = false;
            try { await DispatchAsync(sink, policies, agent, token); }
            catch (HttpRequestException) { dispatchFailed = true; }
            Check(dispatchFailed, "real dispatcher attempted delivery while Java was stopped");
            var reopened = new LocalQueueAuditSink(sink.QueueFilePath);
            Check((await reopened.ReadPendingAsync(100, token)).Count == 1 &&
                (await reopened.ReadPendingOverridesAsync(100, token)).Count == 1, "event and justification remain pending after offline dispatch and queue reopen");
        }
        else if (phase == "recover")
        {
            await policies.LoadCurrentAsync(token);
            await DispatchAsync(sink, policies, agent, token);
            await CheckLocalConfirmedAsync(4);
            await VerifyServerAsync(2);
            var events = new JsonArray(); var overrides = new JsonArray();
            foreach (var batch in batches)
            {
                foreach (var item in batch!["events"]!.AsArray()) events.Add(item!.DeepClone());
                foreach (var item in batch["overrides"]!.AsArray()) overrides.Add(item!.DeepClone());
            }
            var replay = new JsonObject { ["events"] = events, ["overrides"] = overrides };
            using var replayResponse = await agent.PostAsJsonAsync("events", replay, Json, token);
            replayResponse.EnsureSuccessStatusCode();
            var receipt = await replayResponse.Content.ReadFromJsonAsync<JsonElement>(token);
            Check(receipt.GetProperty("acceptedEvents").GetInt32() == 2 && receipt.GetProperty("acceptedOverrides").GetInt32() == 2,
                "Java acknowledges identical UUID replay");
            await VerifyServerAsync(2);
            var changed = replay.DeepClone();
            changed["events"]![0]!["fileName"] = "different-content-same-uuid.txt";
            using var conflict = await agent.PostAsJsonAsync("events", changed, Json, token);
            Check(conflict.StatusCode == HttpStatusCode.Conflict, "same UUID with different event content returns HTTP 409");
            await VerifyServerAsync(2);
        }
        else
        {
            await VerifyServerAsync(2);
            await CheckLocalConfirmedAsync(4);
            Check((await policies.LoadCurrentAsync(token)).Version > 0, "remote policy remains readable after second backend restart");
        }
        await File.WriteAllTextAsync(statePath, batches.ToJsonString(Json), token);
        await File.WriteAllTextAsync(Path.Combine(root, phase + "-receipt.json"), JsonSerializer.Serialize(new
        { phase, status = "passed", endpoint = Endpoint, checks }, Json), token);
        Console.WriteLine($"{phase}: PASS ({checks.Count} checks); queue={sink.QueueFilePath}");

        async Task SaveBatchAsync()
        {
            batches.Add(JsonSerializer.SerializeToNode(new
            { events = await sink.ReadPendingAsync(100, token), overrides = await sink.ReadPendingOverridesAsync(100, token) }, Json));
            await File.WriteAllTextAsync(statePath, batches.ToJsonString(Json), token);
        }
        async Task CheckLocalConfirmedAsync(int lines)
        {
            Check((await sink.ReadPendingAsync(100, token)).Count == 0 &&
                (await sink.ReadPendingOverridesAsync(100, token)).Count == 0, "both local pending counts are zero");
            Check((await File.ReadAllLinesAsync(sink.QueueFilePath, token)).Length == lines, "local audit trail preserved after acknowledgement");
        }
        async Task VerifyServerAsync(int expected)
        {
            using var login = await client.PostAsJsonAsync("api/auth/login", new { email = Email, senha = Password }, token);
            login.EnsureSuccessStatusCode();
            using var response = await client.GetAsync("api/auditoria?endpoint=" + Endpoint, token);
            response.EnsureSuccessStatusCode();
            var audit = await response.Content.ReadFromJsonAsync<JsonElement>(token);
            var storedEvents = audit.GetProperty("eventos").EnumerateArray().ToArray();
            var storedOverrides = audit.GetProperty("justificativas").EnumerateArray().ToArray();
            Check(storedEvents.Length == expected && storedOverrides.Length == expected, "Java persists expected unique event and justification counts");
            var ids = batches.SelectMany(batch => batch!["events"]!.AsArray()).Select(item => Guid.Parse(item!["eventId"]!.GetValue<string>())).ToHashSet();
            Check(storedEvents.All(item => ids.Contains(item.GetProperty("eventId").GetGuid())), "persisted event UUIDs match the actual queued records");
            Check(storedOverrides.All(item => ids.Contains(item.GetProperty("eventId").GetGuid()) &&
                item.GetProperty("userName").GetString() == Sid), "justifications remain linked to original UUIDs and service-supplied identity");
            var originals = batches.SelectMany(batch => batch!["events"]!.AsArray())
                .Select(item => item!.Deserialize<AuditEvent>(Json)!).ToDictionary(item => item.EventId);
            var reasons = batches.SelectMany(batch => batch!["overrides"]!.AsArray())
                .Select(item => item!.Deserialize<AuditOverride>(Json)!).ToDictionary(item => item.EventId);
            Check(storedEvents.All(item =>
            {
                var received = item.Deserialize<AuditEvent>(Json)!;
                return JsonSerializer.Serialize(received, Json) == JsonSerializer.Serialize(originals[received.EventId], Json);
            }), "all persisted event fields match their original queued content");
            Check(storedOverrides.All(item =>
            {
                var received = item.Deserialize<AuditOverride>(Json)!;
                return JsonSerializer.Serialize(received, Json) == JsonSerializer.Serialize(reasons[received.EventId], Json);
            }), "all persisted justification fields match their original queued content");
            Check(!audit.GetRawText().Contains("529.982.247-25") && !audit.GetRawText().Contains("52998224725"), "administrative audit contains no original synthetic CPF");
            await File.WriteAllTextAsync(Path.Combine(root, phase + "-java-audit.json"), audit.GetRawText(), token);
        }
    }

    private static async Task DispatchAsync(LocalQueueAuditSink sink, IPolicyStore policies, HttpClient client, CancellationToken token)
    {
        using var dispatcher = new HttpAgentDispatcher(sink, policies, client, Endpoint, TimeSpan.FromHours(1), NullLogger<HttpAgentDispatcher>.Instance);
        await dispatcher.RunCycleAsync(token);
    }
}
