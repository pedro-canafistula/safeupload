using System.Diagnostics;
using System.Net.Http.Json;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Drive;
using SafeUpload.Agent.Service.Diagnostics;
using SafeUpload.Agent.Service.Dispatch;
using SafeUpload.Agent.Service.Drive;
using SafeUpload.Agent.Service.Gate;
using SafeUpload.Agent.Service.Notifications;
using SafeUpload.Agent.Service.Policies;

// C# filesystem callbacks + real files, policy API, dispatcher and database.
// Never mounts WinFsp, connects to the gate or qualifies installed-service/WPF delivery.
internal static class FunctionalAuditAcceptance
{
    private const string Endpoint = "SMOKE-AGENT";
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
        { Converters = { new JsonStringEnumConverter() } };
    private sealed record State(int HostId, int ControlId, int Revision, string ControlBefore, List<AuditEvent> Events,
        string ServerBase, string PublicKey);

    internal static async Task PrepareAsync(HttpClient agent, SignedAgentIdentity identity, int control, string workspace,
        Func<string, string, Task<int>> publish, Func<string, Task<JsonElement>> get, CancellationToken token)
    {
        string root = Path.Combine(workspace, "functional-audit");
        Directory.CreateDirectory(root);
        int host = identity.HostId; // Enrollment already happened explicitly; never register during a phase/restart.
        var operational = LocalPolicyStore.CreateDefault() with
        {
            MonitoredScopes = new(new HashSet<string> { ".txt", ".docx", ".zip" }, [Path.Combine(root, "backing")], false, false),
            OverrideAllowed = false
        };
        await File.WriteAllTextAsync(Path.Combine(root, "operational.json"), JsonSerializer.Serialize(PolicyDocument.FromPolicy(operational)), token);
        int blocked = await publish("bloquear", "cpf");
        var remote = Remote(agent, root, host);
        using var policies = new RefreshingPolicyStore(remote, TimeSpan.FromSeconds(30), NullLogger<RefreshingPolicyStore>.Instance);
        await policies.RefreshAsync(token);
        await ProduceAsync(root, policies, "online-clean.txt", "Clean online bytes", TransferPhase.Released, token);
        await ProduceAsync(root, policies, "online-cpf.txt", "CPF: 529.982.247-25", TransferPhase.Blocked, token);
        int alert = await publish("alertar", "cpf");
        await policies.RefreshAsync(token);
        await ProduceAsync(root, policies, "online-alert.txt", "CPF: 529.982.247-25", TransferPhase.Released, token);
        await ProduceAsync(root, policies, "online-broken.docx", "PK\u0003\u0004broken zip", TransferPhase.Blocked, token);
        var queue = Queue(root);
        var events = (await queue.ReadPendingAsync(100, token)).ToList();
        Check("real Drive component outcomes carry both central revisions", events.Count == 4 &&
            events.Count(e => e.PolicyVersion == blocked) == 2 && events.Count(e => e.PolicyVersion == alert) == 2);
        await DispatchAsync(root, agent, policies, host, token);
        var persisted = (await get("auditoria?endpoint=" + Endpoint)).GetProperty("eventos").EnumerateArray().ToArray();
        Verify(events, persisted);
        string controlBefore = (await get("endpoints")).GetProperty("itens").EnumerateArray()
            .Single(h => h.GetProperty("hostId").GetInt32() == control).GetRawText();
        await File.WriteAllTextAsync(Path.Combine(root, "state.json"), JsonSerializer.Serialize(new State(host, control, alert, controlBefore, events,
            agent.BaseAddress!.AbsoluteUri, identity.PublicKey), Json), token);
        Console.WriteLine("FUNCTIONAL_AUDIT_ROOT=" + root);
    }

    internal static async Task ContinueAsync(string phase, string root)
    {
        using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var token = budget.Token;
        var state = JsonSerializer.Deserialize<State>(await File.ReadAllTextAsync(Path.Combine(root, "state.json"), token), Json)!;
        var server = new Uri(state.ServerBase);
        if (!server.IsLoopback) throw new InvalidOperationException("Functional component fixture requires disposable loopback API.");
        using var agent = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { BaseAddress = server, Timeout = TimeSpan.FromSeconds(2) };
        string identityFile = IdentityFile(root);
        byte[] identityBefore = await File.ReadAllBytesAsync(identityFile, token);
        var identity = new SignedHostIdentityStore(identityFile, enforceAcl: false).Load(server, state.HostId);
        int host = identity.HostId;
        Check("new process restores the signed host and public key without enrollment", host == state.HostId && identity.PublicKey == state.PublicKey);
        var remote = Remote(agent, root, host);
        byte[] cacheBefore = await File.ReadAllBytesAsync(Path.Combine(root, "cache.json"), token);
        var restored = await remote.LoadCachedOrDefaultAsync(token);
        Check("new process restores the central policy from disk", restored.Version == state.Revision && remote.LastSource == "disk" && restored.AuditOnly);
        using var policies = new RefreshingPolicyStore(remote, TimeSpan.FromSeconds(30), NullLogger<RefreshingPolicyStore>.Instance);
        var queue = Queue(root);
        if (phase == "offline")
        {
            bool unreachable = false;
            try { using var response = await agent.GetAsync("api/policy?ip=10.90.0.21", token); }
            catch (HttpRequestException e) when (e.StatusCode is null) { unreachable = true; }
            catch (OperationCanceledException) when (!token.IsCancellationRequested) { unreachable = true; }
            Check("Java really stopped before offline production", unreachable);
            await policies.RefreshAsync(token);
            await ProduceAsync(root, policies, "offline-clean.txt", "Clean offline bytes", TransferPhase.Released, token);
            await ProduceAsync(root, policies, "offline-alert.txt", "CPF: 529.982.247-25", TransferPhase.Released, token);
            var pending = await queue.ReadPendingAsync(100, token);
            Check("offline outcomes persisted under recovered revision", pending.Count == 2 && pending.All(e => e.PolicyVersion == state.Revision));
            byte[] queueBefore = await File.ReadAllBytesAsync(queue.QueueFilePath, token);
            bool failed = false;
            try { await DispatchAsync(root, agent, policies, host, token); }
            catch (HttpRequestException e) when (e.StatusCode is null) { failed = true; }
            catch (OperationCanceledException) when (!token.IsCancellationRequested) { failed = true; }
            byte[] queueAfter = await File.ReadAllBytesAsync(queue.QueueFilePath, token);
            byte[] cacheAfter = await File.ReadAllBytesAsync(Path.Combine(root, "cache.json"), token);
            Check("failed real send preserves every queued byte", failed && queueBefore.SequenceEqual(queueAfter));
            Check("offline refresh preserves cache bytes", cacheBefore.SequenceEqual(cacheAfter));
            state.Events.AddRange(pending);
            await File.WriteAllTextAsync(Path.Combine(root, "state.json"), JsonSerializer.Serialize(state, Json), token);
        }
        else if (phase == "resume")
        {
            Check("second new process finds the same pending identities", (await queue.ReadPendingAsync(100, token)).Select(e => e.EventId)
                .ToHashSet().SetEquals(state.Events.TakeLast(2).Select(e => e.EventId)));
            using var admin = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
                { BaseAddress = new Uri(server.GetLeftPart(UriPartial.Authority)) };
            using var login = await admin.PostAsJsonAsync("auth/login", new { email = "contract-smoke@example.com", senha = "contract-smoke-123" }, token);
            login.EnsureSuccessStatusCode();
            await CurrentBackendContract.Heartbeat(agent, identity).SendAsync(token);
            Check("restarted process authenticates with real Ed25519 heartbeat", true);
            await DispatchAsync(root, agent, policies, host, token);
            Check("reconnection confirms the durable queue", (await queue.ReadPendingAsync(100, token)).Count == 0);
            // Simulate a lost receipt after commit: resend identical persisted events, never create new IDs.
            using var replay = await agent.PostAsJsonAsync("events", new { events = state.Events, overrides = Array.Empty<object>() }, Json, token);
            replay.EnsureSuccessStatusCode();
            Check("lost receipt replay is acknowledged", (await replay.Content.ReadFromJsonAsync<JsonElement>(token)).GetProperty("acceptedEvents").GetInt32() == state.Events.Count);
            using var auditResponse = await admin.GetAsync("auditoria?endpoint=" + Endpoint, token);
            auditResponse.EnsureSuccessStatusCode();
            var persisted = (await auditResponse.Content.ReadFromJsonAsync<JsonElement>(token)).GetProperty("eventos").EnumerateArray().ToArray();
            Verify(state.Events, persisted);
            using var hostsResponse = await admin.GetAsync("endpoints", token);
            hostsResponse.EnsureSuccessStatusCode();
            var hosts = (await hostsResponse.Content.ReadFromJsonAsync<JsonElement>(token)).GetProperty("itens").EnumerateArray().ToArray();
            Check("heartbeat keeps exactly the two registered hosts and control unchanged", hosts.Length == 2 &&
                hosts.Single(h => h.GetProperty("hostId").GetInt32() == state.ControlId).GetRawText() == state.ControlBefore &&
                hosts.Single(h => h.GetProperty("hostId").GetInt32() == host).GetProperty("policyVersion").GetInt32() == state.Revision);
        }
        else throw new ArgumentException("Expected offline or resume.");
        byte[] identityAfter = await File.ReadAllBytesAsync(identityFile, token);
        Check("persisted identity unchanged", identityBefore.SequenceEqual(identityAfter));
        Console.WriteLine("FunctionalAuditComponent=True;HeartbeatProtocol=AgentApiEd25519;IdentityAclQualified=False;NativeDriveQualified=False;InstalledServiceQualified=False;WpfInteractiveQualified=False");
    }

    private static DurableHttpPolicyStore Remote(HttpClient agent, string root, int host) =>
        new(agent, Endpoint, Path.Combine(root, "cache.json"), false, consolePolicy: new ConsolePolicyOptions(host, "10.90.0.21"),
            operationalPolicy: new LocalPolicyStore(Path.Combine(root, "operational.json")));
    private static LocalQueueAuditSink Queue(string root) => new(Path.Combine(root, "queue.jsonl"));
    private static string IdentityFile(string root) => Path.GetFullPath(Path.Combine(root, "..", "identity.dat"));

    private static async Task DispatchAsync(string root, HttpClient agent, IPolicyStore policies, int host, CancellationToken token)
    {
        using var dispatcher = new HttpAgentDispatcher(Queue(root), policies, agent, Endpoint, TimeSpan.FromSeconds(30),
            NullLogger<HttpAgentDispatcher>.Instance)
            { HeartbeatSender = CurrentBackendContract.Heartbeat(agent,
                new SignedHostIdentityStore(IdentityFile(root), enforceAcl: false).Load(agent.BaseAddress!, host)) };
        await dispatcher.RunCycleAsync(token);
    }

    private static async Task ProduceAsync(string root, IPolicyStore policies, string name, string bytes,
        TransferPhase expected, CancellationToken token)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var writer = new DriveWriter(Environment.ProcessId, "contract-smoke", (uint)Process.GetCurrentProcess().SessionId, identity.User!.Value, "synthetic-writer");
        var record = new MemoryRecord();
        var hub = new NotificationHub(record, NullLogger<NotificationHub>.Instance);
        using var subscription = hub.Subscribe(writer.SessionId, writer.UserSid);
        var queue = Queue(root);
        var engine = new InspectionService(policies, queue, ExtractorRegistry.CreateDefault(), new VerdictCache(), Endpoint);
        var observer = new Observer(writer);
        // Deliberately use callbacks without starting workers or mounting a drive.
        var fs = (DriveFileSystem)Activator.CreateInstance(typeof(DriveFileSystem), BindingFlags.Instance | BindingFlags.NonPublic,
            null, [Path.Combine(root, "backing"), Path.Combine(root, "private"), "S:", new ContentInspector(engine, policies),
                observer, DestinationKind.Cloud, "Component", (Func<int>)(() => Environment.ProcessId)], null)!;
        using var gate = new GateClient(NullLogger<GateClient>.Instance); // Never connects in this component exercise.
        using var service = new DriveService(policies, engine, hub, new DriveJustifications(), gate,
            new ConfigurationBuilder().Build(), NullLogger<DriveService>.Instance);
        try
        {
            Check(name + " create callback", fs.Create("\\" + name, 0, 0, 0, [], 0, out var node, out var handle, out _, out _) == 0);
            var data = Encoding.UTF8.GetBytes(bytes);
            var pointer = Marshal.AllocHGlobal(data.Length);
            object content;
            try
            {
                Marshal.Copy(data, 0, pointer, data.Length);
                Check(name + " write callback accepts exact bytes", fs.Write(node, handle, pointer, 0, (uint)data.Length, false, false, out var written, out _) == 0 && written == data.Length);
                var writtenNode = handle.GetType().GetField("Node")!.GetValue(handle)!;
                content = writtenNode.GetType().GetField("Content")!.GetValue(writtenNode)!;
            }
            finally { Marshal.FreeHGlobal(pointer); fs.Close(node, handle); }
            Invoke(fs, "InspectOne", content);
            var decision = observer.Decisions.Single();
            await service.HandleDecisionAsync(decision, await policies.LoadCurrentAsync(token), kind => fs.Approve(decision.VersionId, kind));
            Invoke(fs, "Reconcile");
            foreach (var publication in observer.Publications) await service.HandlePublicationAsync(publication);
            Check(name + " owner receives the expected transfer outcome", subscription.Reader.TryRead(out var notice) && notice is TransferNotification { Event: not null } transfer && transfer.Phase == expected);
            var outcome = (TransferNotification)notice!;
            var decoded = (TransferNotification)NotificationProtocol.Deserialize(NotificationProtocol.Serialize(outcome))!;
            var persisted = (await queue.ReadPendingAsync(100, token)).Single(e => e.EventId == decoded.Event!.EventId);
            Check(name + " notification correlates with durable audit", persisted.OccurredAtUtc == decoded.Event!.OccurredAtUtc && persisted.PolicyVersion == decision.Result!.PolicyVersion &&
                persisted.PublishedSha256Hex == decoded.PublishedSha256Hex);
            string target = Path.Combine(root, "backing", name);
            Check(name + " publication matches notification", expected == TransferPhase.Released
                ? File.ReadAllBytes(target).SequenceEqual(data) && persisted.PublishedSha256Hex is not null
                : !File.Exists(target) && persisted.Verdict == Verdict.Blocked);
            if (name.Contains("alert")) Check(name + " findings preserved after publication", persisted.Categories.Contains(Category.Cpf));
            if (name.EndsWith(".docx")) Check(name + " inspection failure stays blocked in Alertar", persisted.NotInspectedReason is not null && expected == TransferPhase.Blocked);
        }
        finally { fs.Stop(); }
    }

    private static void Verify(IEnumerable<AuditEvent> events, JsonElement[] persisted)
    {
        foreach (var item in events)
        {
            var found = persisted.Single(e => e.GetProperty("eventId").GetGuid() == item.EventId);
            Check(item.FileName + " correlated through Java/MySQL", found.GetProperty("endpointId").GetString() == item.EndpointId &&
                found.GetProperty("policyVersion").GetInt32() == item.PolicyVersion && found.GetProperty("verdict").GetString() == item.Verdict.ToString() &&
                found.GetProperty("occurredAtUtc").GetDateTimeOffset() == item.OccurredAtUtc &&
                found.GetProperty("publishedSha256Hex").GetString() == item.PublishedSha256Hex &&
                found.GetProperty("categories").EnumerateArray().Select(e => e.GetString()).ToHashSet().SetEquals(item.Categories.Select(c => c.ToString())));
        }
    }
    private static void Check(string name, bool passed)
    {
        if (!passed) throw new InvalidOperationException("Functional audit acceptance failed: " + name);
        Console.WriteLine("FUNCTIONAL_AUDIT_PASS=" + name);
    }
    private static void Invoke(object target, string method, params object[] args) =>
        target.GetType().GetMethod(method, BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(target, args);
    private sealed class MemoryRecord : INotificationRecord
    {
        public void Append(AgentNotification notification, uint? targetSessionId) { }
    }
    private sealed class Observer(DriveWriter writer) : IDriveObserver
    {
        public List<DriveDecision> Decisions { get; } = [];
        public List<DrivePublication> Publications { get; } = [];
        public DriveWriter IdentifyWriter(int processId) => writer;
        public void OnDecision(DriveDecision decision) => Decisions.Add(decision);
        public void OnPublication(DrivePublication publication) => Publications.Add(publication);
    }
}
