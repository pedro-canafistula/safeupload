using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Dispatch;

// Real Java/MySQL/DPAPI/Ed25519. Isolated files, no installed service/production ACL or native gate claim.
internal static class Ed25519BackendAcceptance
{
    private static readonly AgentHeartbeatHost Host = new("10.95.0.51", 24, "ED25519-SYNTHETIC", "Windows", "10.0", "001122334455");
    private sealed record State(int HostId, string PublicKey, int Revision, Guid OnlineEvent, Guid? OfflineEvent = null);

    internal static async Task RunAsync(string phase, Uri server, string workspace)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        if (!server.IsLoopback) throw new ArgumentException("Ensaio somente em loopback descartável.");
        using var handler = new HttpClientHandler { AllowAutoRedirect = false };
        using var http = new HttpClient(handler) { BaseAddress = server, Timeout = TimeSpan.FromSeconds(3) };
        var client = new AgentApiClient(http);
        string identityPath = Path.Combine(workspace, "identity.dat");
        var identities = new SignedHostIdentityStore(identityPath, enforceAcl: false);
        if (phase is "enroll" or "reject")
        {
            if (Directory.Exists(workspace)) throw new InvalidOperationException("Workspace deve ser novo.");
            Directory.CreateDirectory(workspace);
        }
        if (phase == "reject")
        {
            string testToken = (await Console.In.ReadLineAsync()) ?? "";
            await Rejected(() => identities.RegisterAsync(client, testToken, Host, default), "token rejected");
            await Pending(identities, server);
            return;
        }
        if (phase == "enroll")
        {
            using var admin = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
                { BaseAddress = new Uri(server.GetLeftPart(UriPartial.Authority)), Timeout = TimeSpan.FromSeconds(5) };
            using var anonymousToken = await admin.PostAsync("/admin/token", null);
            Check(anonymousToken.StatusCode == System.Net.HttpStatusCode.Unauthorized, "anonymous token issuance refused");
            using var decision = await admin.GetAsync("/auth/decision");
            decision.EnsureSuccessStatusCode();
            using var decisionDocument = JsonDocument.Parse(await decision.Content.ReadAsStringAsync());
            Check(!decisionDocument.RootElement.GetProperty("existemUsuarios").GetBoolean(), "disposable administrator fixture is empty");
            var address = new { cep = "70000-000", logradouro = "Rua Sintetica", numero = 1, complemento = "", bairro = "Teste", cidade = "Brasilia", estado = "DF" };
            const string email = "ed25519-contract@example.com", password = "ed25519-contract-123";
            using var registration = await admin.PostAsJsonAsync("/auth/firstregister", new {
                username = "ed25519-contract", email, cpf = "52998224725", senha = password,
                nome_completo = "Teste Ed25519", data_nascimento = "1990-01-01", endereco = address,
                empresa = new { razao_social = "Empresa Ed25519 Sintetica", nome_fantasia = "Teste",
                    cnpj = "11222333000181", email_contato = email, telefone_contato = "61999999999", endereco = address }
            });
            Check(registration.StatusCode == System.Net.HttpStatusCode.Created, "synthetic administrator created through first registration");
            using var login = await admin.PostAsJsonAsync("/auth/login", new { email, senha = password });
            login.EnsureSuccessStatusCode();
            using var tokenResponse = await admin.PostAsync("/admin/token", null);
            tokenResponse.EnsureSuccessStatusCode();
            using var tokenDocument = JsonDocument.Parse(await tokenResponse.Content.ReadAsStringAsync());
            string testToken = tokenDocument.RootElement.GetProperty("token").GetString()!;
            var identity = await identities.RegisterAsync(client, testToken, Host, default);
            Check(identity.HostId > 0, "registered using administrator token and SPKI");
            Check(!System.Text.Encoding.UTF8.GetString(await File.ReadAllBytesAsync(identityPath)).Contains(testToken), "token absent from persisted identity");
            await SignedHeartbeat(identity, http);
            await Rejected(() => client.RegisterEd25519Async(testToken, identity.PublicKey, Host, default), "consumed token rejected");
            await Rejected(() => client.HeartbeatAuthenticatedAsync(identity.HostId, Convert.ToBase64String(new byte[64]), Host, default), "incorrect signature rejected");
            using var legacy = await http.PostAsJsonAsync("heartbeat", new { id_host = identity.HostId });
            Check(!legacy.IsSuccessStatusCode, "old unsigned heartbeat refused");
            using var publication = await admin.PostAsJsonAsync("/admin/policy/set", new
            {
                versao = "1.0", nome = "Ed25519 synthetic policy", destino = new { ip = Host.Ip },
                acao = "bloquear", regras = new[] { new { tipo = "cpf", nome = "CPF" } },
                criadaEm = DateTimeOffset.UtcNow, origem = "synthetic-auth-test"
            });
            publication.EnsureSuccessStatusCode();
            var policies = Policies(http, workspace, identity.HostId);
            var policy = await policies.LoadCurrentAsync(default);
            Check(policy.ActiveCategories.SequenceEqual(new[] { Category.Cpf }) && !policy.AuditOnly, "existing central policy translated without separate auth header");
            var audit = Event(policy.Version);
            var queue = new LocalQueueAuditSink(Path.Combine(workspace, "queue.jsonl"));
            await queue.WriteAsync(audit, default);
            using var dispatcher = Dispatcher(queue, policies, http, identity);
            await dispatcher.RunCycleAsync(default);
            Check((await queue.ReadPendingAsync(100, default)).Count == 0, "signed heartbeat and existing event receipt succeed together");
            var state = new State(identity.HostId, identity.PublicKey, policy.Version, audit.EventId);
            await File.WriteAllTextAsync(Path.Combine(workspace, "state.json"), JsonSerializer.Serialize(state));
            Console.WriteLine($"AUTH_STATE hostId={identity.HostId} revision={policy.Version} eventId={audit.EventId}");
            return;
        }
        var saved = JsonSerializer.Deserialize<State>(await File.ReadAllTextAsync(Path.Combine(workspace, "state.json")))!;
        byte[] beforeIdentity = await File.ReadAllBytesAsync(identityPath);
        var restored = identities.Load(server, saved.HostId);
        Check(restored.PublicKey == saved.PublicKey, "new process restores same host and key");
        var restoredPolicies = Policies(http, workspace, restored.HostId);
        var cached = await restoredPolicies.LoadCachedOrDefaultAsync(default);
        Check(cached.Version == saved.Revision && restoredPolicies.LastSource == "disk", "new process restores central policy cache");
        var restoredQueue = new LocalQueueAuditSink(Path.Combine(workspace, "queue.jsonl"));
        if (phase == "offline")
        {
            byte[] beforeCache = await File.ReadAllBytesAsync(Path.Combine(workspace, "policy-cache.json"));
            var audit = Event(cached.Version);
            await restoredQueue.WriteAsync(audit, default);
            byte[] beforeQueue = await File.ReadAllBytesAsync(Path.Combine(workspace, "queue.jsonl"));
            using var dispatcher = Dispatcher(restoredQueue, restoredPolicies, http, restored);
            try { await dispatcher.RunCycleAsync(default); throw new InvalidOperationException("Backend deveria estar offline."); }
            catch (HttpRequestException) { }
            Check(beforeQueue.AsEnumerable().SequenceEqual(await File.ReadAllBytesAsync(Path.Combine(workspace, "queue.jsonl"))), "failed send preserves queue bytes offline");
            Check(beforeCache.AsEnumerable().SequenceEqual(await File.ReadAllBytesAsync(Path.Combine(workspace, "policy-cache.json"))), "offline cache bytes preserved");
            await File.WriteAllTextAsync(Path.Combine(workspace, "state.json"), JsonSerializer.Serialize(saved with { OfflineEvent = audit.EventId }));
        }
        else if (phase == "resume")
        {
            await SignedHeartbeat(restored, http);
            var pending = await restoredQueue.ReadPendingAsync(100, default);
            Check(pending.Single().EventId == saved.OfflineEvent, "restart preserves offline event ID");
            using var dispatcher = Dispatcher(restoredQueue, restoredPolicies, http, restored);
            await dispatcher.RunCycleAsync(default);
            Check((await restoredQueue.ReadPendingAsync(100, default)).Count == 0, "offline event confirmed after authenticated restart");
            await dispatcher.RunCycleAsync(default);
        }
        else throw new ArgumentException("Fase inválida.");
        Check(beforeIdentity.AsEnumerable().SequenceEqual(await File.ReadAllBytesAsync(identityPath)), "heartbeat never regenerates or rewrites identity");
    }

    private static async Task SignedHeartbeat(SignedAgentIdentity identity, HttpClient http)
    {
        await AgentHeartbeatConfiguration.Parse("AgentApiEd25519", null, signingIdentity: identity, host: Host)
            .CreateSender(http)!.SendAsync(default);
        Check(true, "Java verified real Ed25519 signature");
    }

    private static DurableHttpPolicyStore Policies(HttpClient http, string root, int hostId) =>
        new(http, Host.Hostname, Path.Combine(root, "policy-cache.json"), false,
            consolePolicy: new ConsolePolicyOptions(hostId, Host.Ip), operationalPolicy: new Operational());
    private sealed class Operational : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken token) => Task.FromResult(LocalPolicyStore.CreateDefault());
    }
    private static HttpAgentDispatcher Dispatcher(IAuditSink queue, IPolicyStore policy, HttpClient http, SignedAgentIdentity identity) =>
        new(queue, policy, http, Host.Hostname, TimeSpan.FromSeconds(30), NullLogger<HttpAgentDispatcher>.Instance)
        { HeartbeatSender = AgentHeartbeatConfiguration.Parse("AgentApiEd25519", null, signingIdentity: identity, host: Host).CreateSender(http) };
    private static AuditEvent Event(int revision) => new(Guid.NewGuid(), DateTimeOffset.UtcNow, Host.Hostname, "synthetic-user",
        "synthetic-auth.txt", ".txt", 10, Verdict.Blocked, [Category.Cpf], [], "synthetic.exe", 1,
        "synthetic", null, revision, 1, false);
    private static async Task Rejected(Func<Task> operation, string check)
    {
        try { await operation(); }
        catch (AgentApiException error) when (error.Code == "http_status")
        { Check(true, check + " HTTP=" + error.StatusCode); return; }
        throw new InvalidOperationException("Esperada rejeição HTTP: " + check);
    }
    private static Task Pending(SignedHostIdentityStore identities, Uri server)
    {
        try { identities.Load(server); }
        catch (AgentIdentityException error) when (error.Code == "registration_pending")
        { Check(true, "rejected enrollment preserves pending key without retry"); return Task.CompletedTask; }
        throw new InvalidOperationException("Identidade deveria permanecer pendente.");
    }
    private static void Check(bool success, string name)
    {
        if (!success) throw new InvalidOperationException("AUTH_FAILED=" + name);
        Console.WriteLine("AUTH_PASS=" + name);
    }
}
