using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Dispatch;

namespace SafeUpload.Agent.Tests;

public sealed class AgentHttpLoopbackTests
{
    private const string PolicyJson = """{"version":7,"activeCategories":["Cpf","Secret"]}""";
    private const string Receipt = """{"acceptedEvents":1,"acceptedOverrides":1}""";

    [Fact]
    public async Task Http_real_preserva_politica_e_fila_apos_503_e_reinicio_com_heartbeat_404()
    {
        using var workspace = new TestWorkspace();
        var available = true;
        await using var api = new LoopbackHttpFixture(request => request.Target switch
        {
            var path when path.StartsWith("/agent/policy?") => available
                ? new(200, PolicyJson) : new(404, "{}"),
            "/agent/heartbeat" => new(404, "{}"),
            "/agent/events" => available ? new(503, "{}") : new(200, Receipt),
            _ => throw new InvalidOperationException("Unexpected route.")
        });
        using var client = api.CreateClient();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var token = timeout.Token;
        var cache = Path.Combine(Path.GetDirectoryName(workspace.QueueFile)!, "policy-cache.json");
        var policies = new DurableHttpPolicyStore(client, "PC SINTETICO/01", cache, enforceProtectedAcl: false);
        var policy = await policies.LoadAsync(token);
        Assert.Equal("remote", policies.LastSource);
        Assert.Equal(7, policy.Version);
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        var audit = Event();
        await SeedAsync(sink, audit, token);
        using (var dispatcher = Dispatcher(sink, policy, client)) await dispatcher.RunCycleAsync(token);
        Assert.Single(await sink.ReadPendingAsync(100, token));
        Assert.Single(await sink.ReadPendingOverridesAsync(100, token));

        available = false;
        var restartedPolicies = new DurableHttpPolicyStore(client, "PC SINTETICO/01", cache, enforceProtectedAcl: false);
        var restoredPolicy = await restartedPolicies.LoadAsync(token);
        Assert.Equal("disk", restartedPolicies.LastSource);
        Assert.Equal(7, restoredPolicy.Version);
        Assert.Equal(policy.ActiveCategories.Order(), restoredPolicy.ActiveCategories.Order());
        var reopened = new LocalQueueAuditSink(workspace.QueueFile);
        var pending = Assert.Single(await reopened.ReadPendingAsync(100, token));
        Assert.Equal(audit.EventId, pending.EventId);
        Assert.Equal(audit.OccurredAtUtc, pending.OccurredAtUtc);
        using (var dispatcher = Dispatcher(reopened, restoredPolicy, client)) await dispatcher.RunCycleAsync(token);
        Assert.Empty(await reopened.ReadPendingAsync(100, token));
        Assert.Empty(await reopened.ReadPendingOverridesAsync(100, token));

        var requests = api.Requests.ToArray();
        Assert.Equal(new[] { "GET", "POST", "POST", "GET", "POST", "POST" }, requests.Select(x => x.Method));
        Assert.Equal("/agent/policy?endpointId=PC%20SINTETICO%2F01", requests[0].Target);
        var batches = requests.Where(x => x.Target == "/agent/events").ToArray();
        Assert.Equal(2, batches.Length);
        Assert.Equal(batches[0].Body, batches[1].Body);
        Assert.DoesNotContain("SYNTHETIC_LOCAL_ONLY", batches[1].Body);
        using var payload = JsonDocument.Parse(batches[1].Body);
        Assert.Equal(audit.EventId, payload.RootElement.GetProperty("events")[0].GetProperty("eventId").GetGuid());
    }

    [Fact]
    public async Task Resposta_perdida_em_socket_reenvia_mesmo_lote_apos_reabrir_fila()
    {
        using var workspace = new TestWorkspace();
        var deliveries = 0;
        await using var api = new LoopbackHttpFixture(request =>
        {
            Assert.Equal("POST", request.Method);
            Assert.Equal("/agent/events", request.Target);
            // The peer accepts the first batch but its receipt never reaches the
            // sender. Repeated rows are counted as received in the next receipt.
            return Interlocked.Increment(ref deliveries) == 1 ? null : new(200, Receipt);
        });
        using var client = api.CreateClient();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var token = timeout.Token;
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        await SeedAsync(sink, Event(), token);
        using (var dispatcher = Dispatcher(sink, LocalPolicyStore.CreateDefault(), client))
            await Assert.ThrowsAsync<HttpRequestException>(() => dispatcher.DispatchPendingAsync(token));

        var reopened = new LocalQueueAuditSink(workspace.QueueFile);
        Assert.Single(await reopened.ReadPendingAsync(100, token));
        Assert.Single(await reopened.ReadPendingOverridesAsync(100, token));
        using (var dispatcher = Dispatcher(reopened, LocalPolicyStore.CreateDefault(), client))
            await dispatcher.DispatchPendingAsync(token);
        Assert.Empty(await reopened.ReadPendingAsync(100, token));
        Assert.Empty(await reopened.ReadPendingOverridesAsync(100, token));
        var requests = api.Requests.ToArray();
        Assert.Equal(2, requests.Length);
        Assert.Equal(requests[0].Body, requests[1].Body);
    }

    private static AuditEvent Event() => new(Guid.NewGuid(),
        new DateTimeOffset(2026, 10, 21, 12, 0, 0, TimeSpan.FromHours(-3)),
        "PC SINTETICO/01", "usuario-sintetico", "arquivo-sintetico.txt", ".txt", 42,
        Verdict.Blocked, [Category.Cpf], ["SYNTHETIC_LOCAL_ONLY"], "processo-sintetico", 123,
        @"C:\DestinoSintetico", null, 7, 15, false);

    private static async Task SeedAsync(LocalQueueAuditSink sink, AuditEvent audit, CancellationToken token)
    {
        await sink.WriteAsync(audit, token);
        await sink.RecordOverrideAsync(audit.EventId.ToString(), "Revisão sintética", token);
    }

    private static HttpAgentDispatcher Dispatcher(LocalQueueAuditSink sink, Policy policy, HttpClient client) =>
        new(sink, new FixedPolicy(policy), client, "PC SINTETICO/01", TimeSpan.FromSeconds(30),
            NullLogger<HttpAgentDispatcher>.Instance);

    private sealed class FixedPolicy(Policy policy) : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken token) => Task.FromResult(policy);
    }
}
