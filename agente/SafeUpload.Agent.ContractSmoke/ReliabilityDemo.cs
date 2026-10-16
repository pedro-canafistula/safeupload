using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Dispatch;

internal static class ReliabilityDemo
{
    // Apenas esta ferramenta usa armazenamento temporário sem ACL de máquina.
    // O serviço continua usando exclusivamente o construtor público protegido.
    public static async Task RunAsync(string[] args)
    {
        if (args.Length != 4 || args[1] is not ("online" or "offline" or "recover"))
            throw new ArgumentException("Uso: --reliability-demo online|offline|recover pasta-temporaria URL");
        var phase = args[1];
        var root = Path.GetFullPath(args[2]);
        var temporaryRoot = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!root.StartsWith(temporaryRoot, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("A demonstração exige uma pasta temporária isolada.");
        Directory.CreateDirectory(root);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var token = timeout.Token;
        using var client = new HttpClient { BaseAddress = new Uri(args[3]), Timeout = TimeSpan.FromSeconds(2) };
        const string endpoint = "DEMO-RELIABILITY";
        var cache = Path.Combine(root, "server-policy-cache.json");
        var policies = new DurableHttpPolicyStore(client, endpoint, cache, false);
        var sink = new LocalQueueAuditSink(Path.Combine(root, "queue.jsonl"));
        if (phase == "online")
        {
            if (File.Exists(cache) || File.Exists(sink.QueueFilePath))
                throw new InvalidOperationException("Use uma pasta nova para iniciar a demonstração.");
            var policy = await policies.LoadAsync(token);
            if (!File.Exists(cache) || policies.LastSource != "remote")
                throw new InvalidOperationException("Política remota não foi persistida.");
            Console.WriteLine($"ONLINE | Política remota v{policy.Version} recebida e persistida.");
            var audit = new AuditEvent(Guid.NewGuid(), DateTimeOffset.UtcNow, endpoint, "demo",
                "dados-sinteticos.txt", ".txt", 32, Verdict.Blocked, [Category.Cpf], [], "demo", 1,
                @"E:\demonstracao", null, policy.Version, 1, false);
            await sink.WriteAsync(audit, token);
            await sink.RecordOverrideAsync(audit.EventId.ToString(), "Transferência sintética autorizada para o vídeo", token);
            Console.WriteLine("AUDITORIA | 1 evento + 1 justificativa gravados em disco.");
        }
        else if (phase == "offline")
        {
            try
            {
                using var response = await client.GetAsync("policy", token);
                throw new InvalidOperationException("O backend precisa estar parado nesta etapa.");
            }
            catch (HttpRequestException) { Console.WriteLine("OFFLINE | Falha de conexão real confirmada."); }
            catch (OperationCanceledException) when (!token.IsCancellationRequested)
                { Console.WriteLine("OFFLINE | Timeout de conexão real confirmado."); }
            var cached = await File.ReadAllTextAsync(cache, token);
            using var document = JsonDocument.Parse(cached);
            var expected = document.RootElement.GetProperty("version").GetInt32();
            var policy = await policies.LoadAsync(token);
            if (policy.Version != expected || policies.LastSource != "disk")
                throw new InvalidOperationException("Cache não foi recuperado.");
            Console.WriteLine($"REINÍCIO OFFLINE | Última política válida v{policy.Version} recuperada do disco.");
            await DispatchAsync(sink, policies, client, endpoint, token);
            if ((await sink.ReadPendingAsync(100, token)).Count != 1 ||
                (await sink.ReadPendingOverridesAsync(100, token)).Count != 1)
                throw new InvalidOperationException("A falha de envio perdeu registros.");
            Console.WriteLine("PRESERVADO | 1 evento + 1 justificativa continuam pendentes após falha de envio.");
        }
        else
        {
            await DispatchAsync(sink, policies, client, endpoint, token);
            if ((await sink.ReadPendingAsync(100, token)).Count != 0 ||
                (await sink.ReadPendingOverridesAsync(100, token)).Count != 0)
                throw new InvalidOperationException("Registros não foram confirmados pelo backend.");
            if ((await File.ReadAllLinesAsync(sink.QueueFilePath, token)).Length != 2)
                throw new InvalidOperationException("A trilha de auditoria não foi preservada.");
            Console.WriteLine("RECONECTADO | Backend Java confirmou 1 evento + 1 justificativa.");
            Console.WriteLine("CONCLUÍDO | 0 pendências; evento e justificativa permanecem na trilha local.");
        }
        Console.WriteLine($"EVIDÊNCIA | {sink.QueueFilePath}");
    }

    private static async Task DispatchAsync(LocalQueueAuditSink sink, DurableHttpPolicyStore policies,
        HttpClient client, string endpoint, CancellationToken token)
    {
        using var dispatcher = new HttpAgentDispatcher(sink, policies, client, endpoint,
            TimeSpan.FromMilliseconds(100), NullLogger<HttpAgentDispatcher>.Instance);
        await dispatcher.StartAsync(token);
        try
        {
            await Task.Delay(500, token);
            while ((await sink.ReadPendingAsync(100, token)).Count != 0 ||
                (await sink.ReadPendingOverridesAsync(100, token)).Count != 0)
            {
                if (client.BaseAddress is not null)
                {
                    try { using var probe = await client.GetAsync("policy", token); }
                    catch (HttpRequestException) { return; }
                    catch (OperationCanceledException) when (!token.IsCancellationRequested) { return; }
                }
                await Task.Delay(100, token);
            }
        }
        finally { await dispatcher.StopAsync(CancellationToken.None); }
    }
}
