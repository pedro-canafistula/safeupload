using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Dispatch;

using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
var cancellationToken = timeout.Token;
using var client = new HttpClient { BaseAddress = new Uri("http://127.0.0.1:18080/") };
using var agentClient = new HttpClient { BaseAddress = new Uri(client.BaseAddress, "agent/") };
const string endpointId = "SMOKE-AGENT";
var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
options.Converters.Add(new JsonStringEnumConverter());

using var policyResponse = await agentClient.GetAsync("policy", cancellationToken);
policyResponse.EnsureSuccessStatusCode();
var policyStore = new HttpPolicyStore(agentClient, endpointId);
var policy = await policyStore.LoadAsync(cancellationToken);
if (policy.Version != 1 || !policy.ActiveCategories.Contains(Category.Secret))
    throw new InvalidOperationException("A política Java não foi interpretada corretamente pelo agente.");

var temporaryRoot = Path.GetFullPath(Path.GetTempPath());
var workspace = Path.GetFullPath(Path.Combine(temporaryRoot, "safeupload-contract-" + Guid.NewGuid().ToString("N")));
Directory.CreateDirectory(workspace);
try
{
    var sink = new LocalQueueAuditSink(Path.Combine(workspace, "queue.jsonl"));
    var events = new List<AuditEvent>();
    foreach (var verdict in new[] { Verdict.Blocked, Verdict.Approved, Verdict.AllowedWithoutInspection })
    {
        var auditEvent = new AuditEvent(Guid.NewGuid(), DateTimeOffset.UtcNow, endpointId,
            "teste-contrato", "sintetico.txt", ".txt", 128, verdict,
            verdict == Verdict.Blocked ? new[] { Category.Cpf, Category.Secret } : [],
            [], "contract-smoke", 1, @"C:\SafeUpload\Escopo Monitorado\sintetico.txt",
            verdict == Verdict.AllowedWithoutInspection ? "inspection_timeout" : null, policy.Version, 10, false);
        events.Add(auditEvent);
        await sink.WriteAsync(auditEvent, cancellationToken);
    }

    using var dispatcher = new HttpAgentDispatcher(sink, policyStore, agentClient, endpointId,
        TimeSpan.FromMilliseconds(100), NullLogger<HttpAgentDispatcher>.Instance);
    await dispatcher.StartAsync(cancellationToken);
    try
    {
        while ((await sink.ReadPendingAsync(100, cancellationToken)).Count != 0)
            await Task.Delay(100, cancellationToken);
    }
    finally
    {
        await dispatcher.StopAsync(CancellationToken.None);
    }

    using var replay = await agentClient.PostAsJsonAsync("events", new { events, overrides = Array.Empty<object>() }, options, cancellationToken);
    replay.EnsureSuccessStatusCode();

    const string email = "contract-smoke@example.com";
    const string password = "contract-smoke-local-123";
    using var registration = await client.PostAsJsonAsync("api/auth/cadastro", new {
        nomeCompleto = "Teste Contrato", username = "contract-smoke", email,
        cpf = "52998224725", senha = password, confirmarSenha = password
    }, cancellationToken);
    registration.EnsureSuccessStatusCode();
    using var login = await client.PostAsJsonAsync("api/auth/login", new { email, senha = password }, cancellationToken);
    login.EnsureSuccessStatusCode();

    using var dashboardResponse = await client.GetAsync("api/painel", cancellationToken);
    dashboardResponse.EnsureSuccessStatusCode();
    var dashboard = await dashboardResponse.Content.ReadFromJsonAsync<JsonElement>(cancellationToken);
    var summary = dashboard.GetProperty("resumo");
    if (summary.GetProperty("total").GetInt32() != 3 || summary.GetProperty("bloqueados").GetInt32() != 1
        || summary.GetProperty("aprovados").GetInt32() != 1 || summary.GetProperty("liberadosSemInspecao").GetInt32() != 1)
        throw new InvalidOperationException("Totais incorretos após envio e reenvio pelo agente real.");

    using var inventoryResponse = await client.GetAsync("api/endpoints", cancellationToken);
    inventoryResponse.EnsureSuccessStatusCode();
    var inventory = await inventoryResponse.Content.ReadFromJsonAsync<JsonElement>(cancellationToken);
    var endpoint = inventory.GetProperty("itens").EnumerateArray().Single(item => item.GetProperty("endpointId").GetString() == endpointId);
    if (endpoint.GetProperty("inspecoes7d").GetInt32() != 3 || endpoint.GetProperty("status").GetString() != "online")
        throw new InvalidOperationException("Heartbeat ou contagem do endpoint não corresponde ao despacho.");

    Console.WriteLine("Contrato C# → Java aprovado: política, heartbeat, fila confirmada, 3 eventos, reenvio idempotente e consultas reais.");
}
finally
{
    if (!workspace.StartsWith(temporaryRoot.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar,
            StringComparison.OrdinalIgnoreCase))
        throw new InvalidOperationException("Pasta temporária fora do diretório permitido.");
    Directory.Delete(workspace, recursive: true);
}
