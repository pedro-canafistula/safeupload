using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Diagnostics;
using SafeUpload.Agent.Service.Dispatch;

// Test-only process: uses the real queue/client/dispatcher, never starts the service host or driver.
return await MeetingSmoke.RunAsync(args);

internal static class MeetingSmoke
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() }
    };

    internal static async Task<int> RunAsync(string[] args)
    {
        try
        {
            bool network = args.Length == 6 && args[0] is "send" or "replay" &&
                args[2] == "--base-url" && args[4] == "--registered-host-id";
            if (!(network || args.Length == 2 && args[0] is "prepare" or "status"))
                throw new ArgumentException();
            string mode = args[0];
            string root = Path.GetFullPath(args[1]);
            RejectProductDirectory(root);
            using var handler = new HttpClientHandler { AllowAutoRedirect = false };
            using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
            var health = new CommunicationHealth(network);
            IAgentHeartbeat? sender = null;
            if (network)
            {
                http.BaseAddress = new Uri(args[3], UriKind.Absolute);
                sender = AgentHeartbeatConfiguration.Parse("AgentApi", args[5]).CreateSender(http, health);
            }

            if (mode == "prepare")
            {
                if (Directory.Exists(root) && Directory.EnumerateFileSystemEntries(root).Any())
                    throw new ArgumentException();
                Directory.CreateDirectory(root);
            }
            if (!Directory.Exists(root)) throw new ArgumentException();
            // Do not follow directory junctions into another installation or workspace.
            for (var directory = new DirectoryInfo(root); directory is not null; directory = directory.Parent)
                if ((directory.Attributes & FileAttributes.ReparsePoint) != 0) throw new ArgumentException();
            using var workspaceLock = new FileStream(Path.Combine(root, "meeting.lock"),
                FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            string stateFile = Path.Combine(root, "meeting-event.json");
            string queueFile = Path.Combine(root, mode == "replay" ? "meeting-replay.jsonl" : "meeting-queue.jsonl");
            AuditEvent audit;
            if (mode == "prepare")
            {
                audit = SyntheticEvent(Guid.NewGuid(), DateTimeOffset.UtcNow);
                await new LocalQueueAuditSink(queueFile).WriteAsync(audit, CancellationToken.None);
                await using var stateStream = new FileStream(stateFile, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                await JsonSerializer.SerializeAsync(stateStream, audit, Json);
            }
            else
            {
                var state = await File.ReadAllBytesAsync(stateFile);
                if (state.Length > 16384) throw new ArgumentException();
                audit = JsonSerializer.Deserialize<AuditEvent>(state, Json) ?? throw new ArgumentException();
                if (audit.EventId == Guid.Empty || !Same(audit, SyntheticEvent(audit.EventId, audit.OccurredAtUtc)))
                    throw new ArgumentException();
                if (mode == "replay" && !File.Exists(queueFile))
                {
                    // Explicit duplicate transmission uses another test queue, preserving the first one.
                    await using (var created = new FileStream(queueFile, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { }
                    await new LocalQueueAuditSink(queueFile).WriteAsync(audit, CancellationToken.None);
                }
            }
            if (!File.Exists(queueFile)) throw new ArgumentException();
            var queue = new LocalQueueAuditSink(queueFile);
            var pending = await queue.ReadPendingAsync(2, CancellationToken.None);
            if (pending.Count > 1 || pending.Any(value => !Same(value, audit)) ||
                (await queue.ReadPendingOverridesAsync(1, CancellationToken.None)).Count != 0)
                throw new ArgumentException();
            int before = pending.Count;
            string? dispatchFailure = null;
            if (network)
            {
                using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(15));
                using var dispatcher = new HttpAgentDispatcher(queue, new NoRemotePolicy(), http,
                    audit.EndpointId, TimeSpan.FromSeconds(30), NullLogger<HttpAgentDispatcher>.Instance, health)
                { HeartbeatSender = sender };
                try { await dispatcher.RunCycleAsync(budget.Token); }
                catch (Exception) { dispatchFailure = "dispatch_failed"; }
            }
            int after = (await queue.ReadPendingAsync(2, CancellationToken.None)).Count;
            var snapshot = health.Read();
            var heartbeat = snapshot.Operations.Single(value => value.Operation == "Heartbeat");
            var auditResult = snapshot.Operations.Single(value => value.Operation == "Audit");
            bool passed = !network || dispatchFailure is null && heartbeat.State == "Success" &&
                after == 0 && (before == 0 || auditResult.State == "Success");
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                mode, eventId = audit.EventId, endpointId = audit.EndpointId, occurredAtUtc = audit.OccurredAtUtc,
                pendingBefore = before, pendingAfter = after,
                result = !network ? "local_only" : before == 0 ? "already_confirmed" : passed ? "receipt_confirmed" : "not_confirmed",
                dispatchFailure, communication = snapshot,
                centralPersistenceVerified = false, installedServiceTested = false, driverTested = false
            }, Json));
            return passed ? 0 : 1;
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or JsonException)
        {
            Console.Error.WriteLine("Configuração inválida. Uso: prepare PASTA_VAZIA | status PASTA | send/replay PASTA --base-url URL/agent/ --registered-host-id ID_HOST.");
            return 2;
        }
        catch (Exception)
        {
            Console.Error.WriteLine("Ensaio não concluído. Confira acesso e arquivos da pasta exclusiva de teste; nenhum conteúdo de erro foi registrado.");
            return 1;
        }
    }

    private static bool Same(AuditEvent first, AuditEvent second) =>
        JsonSerializer.Serialize(first, Json) == JsonSerializer.Serialize(second, Json);

    private static AuditEvent SyntheticEvent(Guid id, DateTimeOffset occurred) => new(
        id, occurred, "SAFEUPLOAD-ENSAIO-" + id.ToString("N"), "usuario-sintetico", "ensaio-sintetico.txt", ".txt",
        10, Verdict.Blocked, [Category.Cpf], [], "processo-sintetico", 1, "destino-sintetico", null, 1, 1, false);

    private static void RejectProductDirectory(string root)
    {
        foreach (string productPath in new[] { AgentPaths.RootDirectory, AgentPaths.WorkRootDirectory })
        {
            string product = Path.TrimEndingDirectorySeparator(Path.GetFullPath(productPath));
            if (root.Equals(product, StringComparison.OrdinalIgnoreCase) ||
                root.StartsWith(product + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException();
        }
    }

    private sealed class NoRemotePolicy : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken token) =>
            throw new InvalidOperationException("O ensaio de heartbeat/auditoria não consulta nem aplica políticas.");
    }
}
