using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Dispatch;
using SafeUpload.Agent.Service.Clipboard;
using SafeUpload.Agent.Service.Policies;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

if (args.Length > 0 && args[0] == "--reliability-demo")
{
    await ReliabilityDemo.RunAsync(args);
    return;
}

if (args.Length > 0 && args[0] == "--protected-cache-probe")
{
    if (!OperatingSystem.IsWindows())
        throw new PlatformNotSupportedException("A validação de ACL protegida exige Windows.");
    if (args.Length != 3 || !int.TryParse(args[2], out var expectedVersion) || expectedVersion <= 0)
        throw new ArgumentException("Uso: --protected-cache-probe caminho-cache versao");
    using var probeClient = new HttpClient { BaseAddress = new Uri("http://127.0.0.1:1/agent/") };
    var probeStore = new DurableHttpPolicyStore(probeClient, Environment.MachineName, args[1]);
    var restored = await probeStore.LoadCachedOrDefaultAsync(CancellationToken.None);
    if (probeStore.LastSource != "disk" || restored.Version != expectedVersion)
        throw new InvalidOperationException("O cache protegido não foi validado e recuperado do disco.");
    Console.WriteLine($"ProtectedCacheVerified=True;Version={restored.Version};Source={probeStore.LastSource}");
    return;
}

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

var clipboardPolicy = policy.EffectiveClipboard;
if (clipboardPolicy.Mode != ClipboardMode.Off
    || !clipboardPolicy.IsEgressDestination("chrome.exe")
    || !clipboardPolicy.IsExcludedSource("Bitwarden.exe")
    || !clipboardPolicy.IsExcludedSource("1Password.exe")
    || clipboardPolicy.MaxTextLength != 100_000
    || !clipboardPolicy.OversizedTextIsDirty)
    throw new InvalidOperationException("A política de clipboard Java diverge do contrato do agente.");

var temporaryRoot = Path.GetFullPath(Path.GetTempPath());
var workspace = Path.GetFullPath(Path.Combine(temporaryRoot, "safeupload-contract-" + Guid.NewGuid().ToString("N")));
Directory.CreateDirectory(workspace);
var durablePolicies = new DurableHttpPolicyStore(agentClient, endpointId,
    Path.Combine(workspace, "server-policy-cache.json"), enforceProtectedAcl: false);
using var servicePolicies = new RefreshingPolicyStore(durablePolicies, TimeSpan.FromMilliseconds(200),
    NullLogger<RefreshingPolicyStore>.Instance);
try
{
    await servicePolicies.StartAsync(cancellationToken);
    while (durablePolicies.LastSource != "remote")
        await Task.Delay(25, cancellationToken);
    if ((await servicePolicies.LoadAsync(cancellationToken)).Version != policy.Version)
        throw new InvalidOperationException("O snapshot do serviço não recebeu a política Java.");
    var sink = new LocalQueueAuditSink(Path.Combine(workspace, "queue.jsonl"));
    var events = new List<AuditEvent>();
    foreach (var verdict in new[] { Verdict.Blocked, Verdict.Approved, Verdict.AllowedWithoutInspection, Verdict.Retained })
    {
        var auditEvent = new AuditEvent(Guid.NewGuid(), DateTimeOffset.UtcNow, endpointId,
            "teste-contrato", "sintetico.txt", ".txt", 128, verdict,
            verdict == Verdict.Blocked ? new[] { Category.Cpf, Category.Secret } : [],
            [], "contract-smoke", 1, @"C:\SafeUpload\Escopo Monitorado\sintetico.txt",
            verdict == Verdict.AllowedWithoutInspection ? "inspection_timeout" : verdict == Verdict.Retained ? "publication_failed" : null,
            policy.Version, 10, false, PublishedSha256Hex: verdict == Verdict.Approved ? new string('a', 64) : null);
        events.Add(auditEvent);
        await sink.WriteAsync(auditEvent, cancellationToken);
    }

    var clipboardService = new ClipboardInspectionService(
        new SmokePolicyStore(policy with { Clipboard = clipboardPolicy with { Mode = ClipboardMode.Audit } }),
        new ClipboardCopyStore(), new ClipboardMetrics());
    var copy = await clipboardService.HandleAsync(
        ClipboardRequest.Classify("CPF: 529.982.247-25", "EXCEL"), 1, cancellationToken);
    var outcome = await clipboardService.HandleAsync(
        ClipboardRequest.Paste(copy.Response.CopyId!, "chrome"), 1, cancellationToken);
    var observation = await ClipboardAudit.WriteAsync(outcome, sink,
        NullLogger<ClipboardInspectionService>.Instance, "teste-contrato", cancellationToken, endpointId);
    var clipboardEvent = (await sink.ReadPendingAsync(100, cancellationToken))
        .Single(item => item.EventId.ToString() == observation.EventId);
    if (clipboardEvent.Channel != AuditChannel.Clipboard || !clipboardEvent.Categories.Contains(Category.Cpf)
        || clipboardEvent.Verdict != Verdict.AllowedWithoutInspection)
        throw new InvalidOperationException("O serviço de clipboard não gerou a observação esperada.");
    events.Add(clipboardEvent);
    var webEvent = new AuditEvent(Guid.NewGuid(), DateTimeOffset.UtcNow, endpointId,
        "teste-contrato", "", "", 18, Verdict.Blocked, [Category.Cpf], [], "chrome", 42,
        "https://example.test/upload", null, policy.Version, 2, false, Channel: AuditChannel.Web);
    events.Add(webEvent);
    await sink.WriteAsync(webEvent, cancellationToken);
    await sink.RecordOverrideAsync(new AuditOverride(webEvent.EventId, "Justificativa sintética do contrato",
        DateTimeOffset.UtcNow, "teste-contrato", endpointId), cancellationToken);
    var queueText = await File.ReadAllTextAsync(sink.QueueFilePath, cancellationToken);
    if (queueText.Contains("529.982.247-25") || queueText.Contains("52998224725"))
        throw new InvalidOperationException("A fila de clipboard contém texto não mascarado.");
    var recovered = new LocalQueueAuditSink(sink.QueueFilePath);
    if (!(await recovered.ReadPendingAsync(100, cancellationToken)).Any(item => item.EventId == clipboardEvent.EventId))
        throw new InvalidOperationException("A observação não sobreviveu à reabertura da fila.");

    using var dispatcher = new HttpAgentDispatcher(sink, servicePolicies, agentClient, endpointId,
        TimeSpan.FromMilliseconds(100), NullLogger<HttpAgentDispatcher>.Instance);
    await dispatcher.StartAsync(cancellationToken);
    try
    {
        while ((await sink.ReadPendingAsync(100, cancellationToken)).Count != 0)
            await Task.Delay(100, cancellationToken);
        while ((await sink.ReadPendingOverridesAsync(100, cancellationToken)).Count != 0)
            await Task.Delay(100, cancellationToken);
    }
    finally
    {
        await dispatcher.StopAsync(CancellationToken.None);
    }

    using var replay = await agentClient.PostAsJsonAsync("events", new { events, overrides = Array.Empty<object>() }, options, cancellationToken);
    replay.EnsureSuccessStatusCode();
    var replayResult = await replay.Content.ReadFromJsonAsync<JsonElement>(cancellationToken);
    if (replayResult.GetProperty("acceptedEvents").GetInt32() != events.Count
        || replayResult.GetProperty("acceptedOverrides").GetInt32() != 0)
        throw new InvalidOperationException("O servidor não confirmou o lote completo no reenvio.");

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
    if (summary.GetProperty("total").GetInt32() != 6 || summary.GetProperty("bloqueados").GetInt32() != 2
        || summary.GetProperty("retidos").GetInt32() != 1
        || summary.GetProperty("aprovados").GetInt32() != 1 || summary.GetProperty("liberadosSemInspecao").GetInt32() != 2)
        throw new InvalidOperationException("Totais incorretos após envio e reenvio pelo agente real.");

    using var auditResponse = await client.GetAsync("api/auditoria", cancellationToken);
    auditResponse.EnsureSuccessStatusCode();
    var audit = await auditResponse.Content.ReadFromJsonAsync<JsonElement>(cancellationToken);
    var persistedEvents = audit.GetProperty("eventos").EnumerateArray().ToList();
    var persistedOverrides = audit.GetProperty("justificativas").EnumerateArray().ToList();
    if (persistedOverrides.Count != 1 || persistedOverrides[0].GetProperty("eventId").GetGuid() != webEvent.EventId ||
        persistedOverrides[0].GetProperty("justification").GetString() != "Justificativa sintética do contrato" ||
        persistedOverrides[0].GetProperty("userName").GetString() != "teste-contrato")
        throw new InvalidOperationException("A justificativa enviada pelo agente não foi preservada na consulta administrativa.");
    if (persistedEvents.Count != events.Count
        || persistedEvents.Count(item => item.GetProperty("channel").GetString() == "File") != 4
        || persistedEvents.Count(item => item.GetProperty("channel").GetString() == "Web") != 1
        || persistedEvents.Count(item => item.GetProperty("channel").GetString() == "Clipboard") != 1)
        throw new InvalidOperationException("A API administrativa não preservou os canais de auditoria.");

    var published = persistedEvents.Single(item => item.GetProperty("verdict").GetString() == "Approved");
    if (published.GetProperty("publishedSha256Hex").GetString() != new string('a', 64))
        throw new InvalidOperationException("O hash de publicação não foi preservado.");

    var persistedClipboard = persistedEvents.Single(item =>
        item.GetProperty("eventId").GetGuid() == clipboardEvent.EventId);
    if (persistedClipboard.GetProperty("channel").GetString() != "Clipboard"
        || persistedClipboard.GetProperty("fileName").GetString() != ""
        || persistedClipboard.GetProperty("extension").GetString() != ""
        || persistedClipboard.GetProperty("processName").GetString() != clipboardEvent.ProcessName
        || persistedClipboard.GetProperty("destinationPath").GetString() != clipboardEvent.DestinationPath
        || persistedClipboard.GetProperty("maskedSnippets").GetArrayLength() != 0
        || persistedClipboard.GetProperty("notInspectedReason").GetString() != "clipboard_focus_observed"
        || persistedClipboard.GetProperty("userName").GetString() != "teste-contrato")
        throw new InvalidOperationException("Os metadados do evento Clipboard foram alterados na integração.");

    using var inventoryResponse = await client.GetAsync("api/endpoints", cancellationToken);
    inventoryResponse.EnsureSuccessStatusCode();
    var inventory = await inventoryResponse.Content.ReadFromJsonAsync<JsonElement>(cancellationToken);
    var endpoint = inventory.GetProperty("itens").EnumerateArray().Single(item => item.GetProperty("endpointId").GetString() == endpointId);
    if (endpoint.GetProperty("inspecoes7d").GetInt32() != 6 || endpoint.GetProperty("status").GetString() != "online")
        throw new InvalidOperationException("Heartbeat ou contagem do endpoint não corresponde ao despacho.");

    // The console schema is translated by Java; the real C# reader must see it.
    using var publication = await client.PostAsJsonAsync("api/politicas", new {
        versao = "1.0", nome = "Política publicada pelo contrato", destino = new { endpointId },
        acao = "bloquear", regras = new[] { new { tipo = "cnpj", nome = "CNPJ" } },
        origem = "console-administrativo"
    }, cancellationToken);
    publication.EnsureSuccessStatusCode();
    while ((await servicePolicies.LoadAsync(cancellationToken)).Version != 2)
        await Task.Delay(25, cancellationToken);
    var updated = await servicePolicies.LoadAsync(cancellationToken);
    if (updated.Version != 2 || updated.AuditOnly || updated.ActiveCategories.Count != 1
        || !updated.ActiveCategories.Contains(Category.Cnpj) || durablePolicies.LastSource != "remote")
        throw new InvalidOperationException("Publicação do painel não chegou ao snapshot C#.");
    var restartedStore = new DurableHttpPolicyStore(agentClient, endpointId,
        Path.Combine(workspace, "server-policy-cache.json"), enforceProtectedAcl: false);
    var restoredPublished = await restartedStore.LoadCachedOrDefaultAsync(cancellationToken);
    if (restoredPublished.Version != 2 || restoredPublished.AuditOnly || restartedStore.LastSource != "disk")
        throw new InvalidOperationException("Política publicada não sobreviveu ao reinício do cliente.");
    var samplePath = Path.Combine(workspace, "cnpj-sintetico.txt");
    await File.WriteAllTextAsync(samplePath, "CNPJ 11.222.333/0001-81", cancellationToken);
    var sample = new FileInfo(samplePath);
    var inspector = new InspectionService(servicePolicies, sink, ExtractorRegistry.CreateDefault(),
        new VerdictCache(), endpointId, "teste-contrato");
    var decision = await inspector.InspectAsync(new FileOperation(samplePath, sample.Name, ".txt", sample.Length,
        sample.LastWriteTimeUtc, "contrato", 1, @"E:\demonstracao", DestinationKind.RemovableDrive), cancellationToken);
    if (!decision.IsBlocked || decision.PolicyVersion != 2 || !decision.Categories.Contains(Category.Cnpj))
        throw new InvalidOperationException("Motor de inspeção não utilizou a política publicada.");
    Console.WriteLine("Motor C# detectou CNPJ sintético e decidiu Blocked usando política publicada v2 (sem interceptação de SO).");
    Console.WriteLine("Publicação painel → Java → C#: versão 2, CNPJ, bloquear; reinício recuperou do disco.");
    Console.WriteLine("Contrato C# → Java aprovado: 4 File, 1 Clipboard, 1 Web, Retained, hash publicado, heartbeat, fila, justificativa consultável e reenvio idempotente.");
}

finally
{
    await servicePolicies.StopAsync(CancellationToken.None);
    if (!workspace.StartsWith(temporaryRoot.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar,
            StringComparison.OrdinalIgnoreCase))
        throw new InvalidOperationException("Pasta temporária fora do diretório permitido.");
    Directory.Delete(workspace, recursive: true);
}

sealed class SmokePolicyStore(Policy policy) : IPolicyStore
{
    public Task<Policy> LoadAsync(CancellationToken cancellationToken) => Task.FromResult(policy);
}
