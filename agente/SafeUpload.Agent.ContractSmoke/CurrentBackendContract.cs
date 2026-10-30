using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Clipboard;
using SafeUpload.Agent.Service.Dispatch;
using SafeUpload.Agent.Service.Policies;

// Current API acceptance, with a known local inspection fixture. It does not claim
// that the console JSON has been applied by the service's legacy policy reader.
internal static class CurrentBackendContract
{
    internal static async Task RunAsync()
    {
        using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var token = budget.Token;
        using var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
            { BaseAddress = new Uri("http://127.0.0.1:18080/"), Timeout = TimeSpan.FromSeconds(10) };
        using var agent = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
            { BaseAddress = new Uri(client.BaseAddress, "agent/"), Timeout = TimeSpan.FromSeconds(10) };
        var json = new JsonSerializerOptions(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
        void Check(string name, bool passed)
        {
            if (!passed) throw new InvalidOperationException("Current API acceptance failed: " + name);
            Console.WriteLine("CURRENT_API_PASS=" + name);
        }
        async Task<JsonElement> Get(string path)
        {
            using var response = await client.GetAsync(path, token);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadFromJsonAsync<JsonElement>(token);
        }
        async Task<JsonElement> Post(string path, object body, HttpStatusCode expected = HttpStatusCode.OK)
        {
            using var response = await client.PostAsJsonAsync(path, body, json, token);
            Check("POST " + path + " status", response.StatusCode == expected);
            return await response.Content.ReadFromJsonAsync<JsonElement>(token);
        }
        var decision = await Get("auth/decision");
        Check("disposable database is unregistered", !decision.GetProperty("existemUsuarios").GetBoolean());
        foreach (string path in new[] { "painel", "auditoria", "endpoints" })
        {
            using var anonymous = await client.GetAsync(path, token);
            Check("anonymous denied " + path, anonymous.StatusCode == HttpStatusCode.Unauthorized);
        }
        var address = new { cep = "70000-000", logradouro = "Rua Sintetica", numero = 1, complemento = "", bairro = "Teste", cidade = "Brasilia", estado = "DF" };
        const string email = "contract-smoke@example.com", password = "contract-smoke-123";
        await Post("auth/firstregister", new {
            username = "contract-smoke", email, cpf = "52998224725", senha = password, nome_completo = "Teste Contrato", data_nascimento = "1990-01-01",
            empresa = new { razao_social = "Empresa Sintetica", nome_fantasia = "Teste", cnpj = "11222333000181", email_contato = email, telefone_contato = "61999999999", endereco = address },
            endereco = address
        }, HttpStatusCode.Created);
        await Post("auth/login", new { email, senha = password });
        Check("session survives a subsequent request", (await Get("auth/me")).GetProperty("role").GetString() == "root");
        const string endpoint = "SMOKE-AGENT";
        async Task<int> Register(string name, string ip)
        {
            var result = await Post("agent/synchronize", new {
                host = new { ip, mascara = 24, hostname = name, sistema_operacional = "Windows", versao_so = "11" },
                usuarioSo = new { sid = "S-TEST-" + name, usuario_so = name, dominio = "SYNTHETIC", admin = 0 }
            }, HttpStatusCode.Created);
            return result.GetProperty("id_host").GetInt32();
        }
        int target = await Register(endpoint, "10.90.0.21");
        int control = await Register("SMOKE-CONTROL", "10.90.0.22");
        Check("explicit distinct host registration", target > 0 && control > 0 && target != control);
        var heartbeat = AgentHeartbeatConfiguration.Parse("AgentApi", target.ToString()).CreateSender(agent)!;
        await heartbeat.SendAsync(token);
        using (var invalid = await agent.PostAsJsonAsync("heartbeat", new { id_usuario_so = target }, token))
            Check("obsolete heartbeat key rejected", invalid.StatusCode == HttpStatusCode.BadRequest);

        string work = Path.Combine(Path.GetTempPath(), "safeupload-current-contract-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(work);
        var queue = new LocalQueueAuditSink(Path.Combine(work, "queue.jsonl"));
        var local = LocalPolicyStore.CreateDefault() with {
            Clipboard = new ClipboardPolicy(ClipboardMode.Audit, new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "chrome.exe" },
                new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Bitwarden.exe", "1Password.exe" }, 100_000, true)
        };
        var events = new List<AuditEvent>();
        foreach (var verdict in new[] { Verdict.Blocked, Verdict.Approved, Verdict.AllowedWithoutInspection, Verdict.Retained })
        {
            var item = new AuditEvent(Guid.NewGuid(), DateTimeOffset.UtcNow, endpoint, "teste-contrato",
                verdict == Verdict.Blocked ? @"C:\legacy\synthetic.txt" : "sintetico.txt", ".txt", 128,
                verdict, verdict == Verdict.Blocked ? [Category.Cpf, Category.Secret] : [], ["SYNTHETIC-LOCAL-ONLY-AUDIT"], "contract-smoke", 1, @"C:\synthetic",
                verdict == Verdict.Retained ? "publication_failed" : verdict == Verdict.AllowedWithoutInspection ? "inspection_timeout" : null,
                local.Version, 5, false, PublishedSha256Hex: verdict == Verdict.Approved ? new string('a', 64) : null);
            events.Add(item); await queue.WriteAsync(item, token);
        }
        var clipboard = new ClipboardInspectionService(new FixturePolicy(local), new ClipboardCopyStore(), new ClipboardMetrics());
        var copy = await clipboard.HandleAsync(ClipboardRequest.Classify("CPF: 529.982.247-25", "EXCEL"), 1, token);
        var outcome = await clipboard.HandleAsync(ClipboardRequest.Paste(copy.Response.CopyId!, "chrome"), 1, token);
        await ClipboardAudit.WriteAsync(outcome, queue, NullLogger<ClipboardInspectionService>.Instance, "teste-contrato", token, endpoint);
        var clipboardEvent = (await queue.ReadPendingAsync(100, token)).Single(e => e.Channel == AuditChannel.Clipboard);
        Check("real clipboard component produces an observation", clipboardEvent.Verdict == Verdict.AllowedWithoutInspection && clipboardEvent.Categories.Contains(Category.Cpf));
        events.Add(clipboardEvent);
        var web = new AuditEvent(Guid.NewGuid(), DateTimeOffset.UtcNow, endpoint, "teste-contrato", "", "", 18,
            Verdict.Blocked, [Category.Cpf], [], "chrome", 42, "https://example.test/legacy/path?synthetic=value#fragment", null, local.Version, 2, false, Channel: AuditChannel.Web);
        events.Add(web); await queue.WriteAsync(web, token);
        var justification = new AuditOverride(web.EventId, "Literal <b>justificativa</b>", DateTimeOffset.UtcNow, "teste-contrato", endpoint);
        await queue.RecordOverrideAsync(justification, token);
        string queueText = await File.ReadAllTextAsync(queue.QueueFilePath, token);
        Check("clipboard content is not stored", !queueText.Contains("529.982.247-25") && !queueText.Contains("52998224725"));
        Check("queue reopens with the original event identities", (await new LocalQueueAuditSink(queue.QueueFilePath).ReadPendingAsync(100, token)).Select(e => e.EventId).ToHashSet().SetEquals(events.Select(e => e.EventId)));
        // An older agent may have committed this exact batch but lost the response.
        // Seed its wire shape without confirming the local queue, then retry with the current dispatcher.
        var legacyReceipt = await Post("agent/events", new { events, overrides = new[] { justification } });
        Check("legacy request was accepted while the local batch remains pending", legacyReceipt.GetProperty("acceptedEvents").GetInt32() == 6 &&
            legacyReceipt.GetProperty("acceptedOverrides").GetInt32() == 1 && (await queue.ReadPendingAsync(100, token)).Count == 6);
        using (var dispatcher = new HttpAgentDispatcher(queue, new FixturePolicy(local), agent, endpoint, TimeSpan.FromSeconds(30), NullLogger<HttpAgentDispatcher>.Instance) { HeartbeatSender = heartbeat })
        {
            await dispatcher.StartAsync(token);
            try
            {
                while ((await queue.ReadPendingAsync(100, token)).Count != 0 || (await queue.ReadPendingOverridesAsync(100, token)).Count != 0)
                    await Task.Delay(25, token);
            }
            finally { await dispatcher.StopAsync(CancellationToken.None); }
        }
        Check("real dispatcher confirms all queued events and justification", (await queue.ReadPendingAsync(100, token)).Count == 0 && (await queue.ReadPendingOverridesAsync(100, token)).Count == 0);
        var receipt = await Post("agent/events", new { schemaVersion = 1, hostname = endpoint, agentVersion = "current-contract", events, overrides = new[] { justification } });
        Check("replay acknowledges both complete counts", receipt.GetProperty("acceptedEvents").GetInt32() == 6 && receipt.GetProperty("acceptedOverrides").GetInt32() == 1);
        var summary = (await Get("painel")).GetProperty("resumo");
        Check("persisted verdict totals are deduplicated", summary.GetProperty("total").GetInt32() == 6 && summary.GetProperty("bloqueados").GetInt32() == 2 &&
            summary.GetProperty("aprovados").GetInt32() == 1 && summary.GetProperty("retidos").GetInt32() == 1 && summary.GetProperty("liberadosSemInspecao").GetInt32() == 2);
        var audit = await Get("auditoria?endpoint=" + endpoint);
        var persisted = audit.GetProperty("eventos").EnumerateArray().ToArray();
        Check("read API preserves every event and channel", persisted.Length == 6 && persisted.Count(e => e.GetProperty("channel").GetString() == "File") == 4 &&
            persisted.Count(e => e.GetProperty("channel").GetString() == "Clipboard") == 1 && persisted.Count(e => e.GetProperty("channel").GetString() == "Web") == 1);
        Check("published hash and retained reason survive SQL", persisted.Single(e => e.GetProperty("verdict").GetString() == "Approved").GetProperty("publishedSha256Hex").GetString() == new string('a',64) &&
            persisted.Single(e => e.GetProperty("verdict").GetString() == "Retained").GetProperty("notInspectedReason").GetString() == "publication_failed");
        Check("read API never includes inspected snippets", !audit.GetRawText().Contains("maskedSnippets"));
        Check("legacy filename and Web destination remain replay-compatible", persisted.Single(e => e.GetProperty("eventId").GetGuid() == events[0].EventId).GetProperty("fileName").GetString() == events[0].FileName &&
            persisted.Single(e => e.GetProperty("eventId").GetGuid() == web.EventId).GetProperty("destinationPath").GetString() == web.DestinationPath);
        var justifications = audit.GetProperty("justificativas").EnumerateArray().ToArray();
        Check("justification is deduplicated and preserves literal text", justifications.Length == 1 && justifications[0].GetProperty("eventId").GetGuid() == web.EventId && justifications[0].GetProperty("justification").GetString() == justification.Justification);
        Check("endpoint filter does not return another endpoint", (await Get("auditoria?endpoint=OTHER")).GetProperty("eventos").GetArrayLength() == 0);
        var inventory = (await Get("endpoints")).GetProperty("itens").EnumerateArray().Single(e => e.GetProperty("endpointId").GetString() == endpoint);
        Check("current host heartbeat and audit count agree", inventory.GetProperty("status").GetString() == "online" && inventory.GetProperty("inspecoes7d").GetInt32() == 6 && inventory.GetProperty("hostId").GetInt32() == target);

        async Task<int> Publish(string action)
        {
            await Post("politicas", new { versao = "1.0", nome = "Política de contrato", destino = new { ip = "10.90.0.21" }, acao = action,
                regras = new[] { new { tipo = "cnpj", nome = "CNPJ" } }, criadaEm = DateTimeOffset.UtcNow, origem = "contract-test" }, HttpStatusCode.Created);
            var published = await Get("agent/api/policy?ip=10.90.0.21");
            Check("published policy preserves host IP and rule", published.GetProperty("destino").GetProperty("idHost").GetInt32() == target &&
                published.GetProperty("destino").GetProperty("ip").GetString() == "10.90.0.21" && published.GetProperty("acao").GetString() == action &&
                published.GetProperty("regras").GetArrayLength() == 1 && published.GetProperty("regras")[0].GetProperty("tipo").GetString() == "cnpj");
            return published.GetProperty("idPolitica").GetInt32();
        }
        int first = await Publish("alertar"), second = await Publish("bloquear");
        Check("publication creates a newer identified policy", second > first && first > 0);
        using (var other = await client.GetAsync("agent/api/policy?ip=10.90.0.22", token)) Check("policy does not leak to the control host", other.StatusCode == HttpStatusCode.NotFound);
        using var logout = await client.PostAsJsonAsync("auth/logout", new { }, token);
        Check("logout completes", logout.IsSuccessStatusCode);
        using (var loggedOut = await client.GetAsync("painel", token)) Check("logout revokes administrative reads", loggedOut.StatusCode == HttpStatusCode.Unauthorized);
        Console.WriteLine("CurrentApiContract=True;ConsolePolicyRead=True;ConsolePolicyAppliedByAgent=Pending;RemotePolicyCacheQualification=Pending;DriverQualified=False");
    }
    private sealed class FixturePolicy(Policy value) : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken token) => Task.FromResult(value);
    }
}
