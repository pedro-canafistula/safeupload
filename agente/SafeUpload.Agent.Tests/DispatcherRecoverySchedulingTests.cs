using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Diagnostics;
using SafeUpload.Agent.Service.Dispatch;

namespace SafeUpload.Agent.Tests;

public sealed class DispatcherRecoverySchedulingTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Persisted_batch_with_missing_headers_or_body_times_out_and_retries_serially(bool stallBody)
    {
        using var work = new TestWorkspace();
        var queue = new LocalQueueAuditSink(work.QueueFile);
        var audit = await Seed(queue);
        using var backend = new Backend(stallBody);
        var health = new CommunicationHealth(true);
        using var client = Client(backend, TimeSpan.FromMilliseconds(750));
        using var dispatcher = Dispatcher(queue, client, health);
        await dispatcher.StartAsync(default);
        try
        {
            await backend.Persisted.Task.WaitAsync(TimeSpan.FromSeconds(5));
            await WaitForEmpty(queue);
        }
        finally { await Stop(dispatcher); }

        AssertRecovery(backend, health, expectedFailures: "Timeout");
        Assert.Equal(2, backend.Payloads.Count);
        var local = Assert.Single(await queue.ReadRecentAsync(10, default));
        Assert.Equal(audit.EventId, local.EventId);
        Assert.Equal(audit.OccurredAtUtc, local.OccurredAtUtc);
        Assert.True(local.Dispatched);
        Assert.Empty(await queue.ReadPendingOverridesAsync(10, default));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Stop_cancels_persisted_inflight_batch_and_restart_replays_it_after_backend_recovers(bool stallBody)
    {
        using var work = new TestWorkspace();
        var queue = new LocalQueueAuditSink(work.QueueFile);
        await Seed(queue);
        var before = await File.ReadAllBytesAsync(work.QueueFile);
        using var backend = new Backend(stallBody);
        var initialHealth = new CommunicationHealth(true);
        using (var client = Client(backend, Timeout.InfiniteTimeSpan))
        using (var dispatcher = Dispatcher(queue, client, initialHealth))
        {
            await dispatcher.StartAsync(default);
            try
            {
                await backend.Persisted.Task.WaitAsync(TimeSpan.FromSeconds(5));
                await backend.ThreeHeartbeats.Task.WaitAsync(TimeSpan.FromSeconds(5));
                Assert.Single(backend.Payloads);
            }
            finally { await Stop(dispatcher); }
        }
        var initial = initialHealth.Read().Operations.Single(x => x.Operation == "Audit");
        Assert.Equal(1, initial.Cancellations);
        Assert.Equal(0, initial.Failures);
        Assert.Equal(0, initial.InFlight);
        Assert.Equal(0, backend.Active);
        Assert.Equal(before, await File.ReadAllBytesAsync(work.QueueFile));

        backend.Offline = true;
        var reopened = new LocalQueueAuditSink(work.QueueFile);
        var health = new CommunicationHealth(true);
        using (var client = Client(backend, TimeSpan.FromSeconds(2)))
        using (var dispatcher = Dispatcher(reopened, client, health))
        {
            await dispatcher.StartAsync(default);
            try
            {
                await backend.Rejected.Task.WaitAsync(TimeSpan.FromSeconds(5));
                Assert.Equal(before, await File.ReadAllBytesAsync(work.QueueFile));
                backend.Offline = false;
                await WaitForEmpty(reopened);
            }
            finally { await Stop(dispatcher); }
        }
        AssertRecovery(backend, health, expectedFailures: "HttpRejected");
        Assert.Empty(await reopened.ReadPendingOverridesAsync(10, default));
    }

    private static void AssertRecovery(Backend backend, CommunicationHealth health, string expectedFailures)
    {
        Assert.Equal(1, backend.MaxActive);
        Assert.Equal(0, backend.Active);
        Assert.Single(backend.Events);
        Assert.Single(backend.Overrides);
        Assert.Single(backend.Payloads.Distinct()); // IDs, UTC instants and all projected metadata stay identical.
        Assert.True(backend.HeartbeatCalls >= 3);
        var audit = health.Read().Operations.Single(x => x.Operation == "Audit");
        Assert.True(audit.Failures >= 1, expectedFailures);
        Assert.Equal(expectedFailures, audit.LastFailureKind);
        Assert.Equal(1, audit.Successes);
        Assert.Equal(0, audit.InFlight);
    }

    private static async Task<AuditEvent> Seed(LocalQueueAuditSink queue)
    {
        var audit = new AuditEvent(Guid.NewGuid(), DateTimeOffset.UtcNow, "PC-SYNTHETIC", "synthetic-user",
            "synthetic.txt", ".txt", 29, Verdict.Approved, [Category.Cpf], [], "test", 1,
            "synthetic", null, 7, 5, false) { PublishedSha256Hex = new string('a', 64) };
        await queue.WriteAsync(audit, default);
        await queue.RecordOverrideAsync(audit.EventId.ToString(), "Synthetic reason", default);
        return audit;
    }

    private static HttpClient Client(Backend backend, TimeSpan timeout) => new(backend, disposeHandler: false)
        { BaseAddress = new Uri("http://localhost/agent/"), Timeout = timeout };

    private static HttpAgentDispatcher Dispatcher(LocalQueueAuditSink queue, HttpClient client, CommunicationHealth health) =>
        new(queue, new Policies(), client, "PC-SYNTHETIC", TimeSpan.FromMilliseconds(30),
            NullLogger<HttpAgentDispatcher>.Instance, health)
        { HeartbeatSender = new RegisteredAgentHeartbeat(new AgentApiClient(client), 7) };

    private static async Task WaitForEmpty(LocalQueueAuditSink queue)
    {
        using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while ((await queue.ReadPendingAsync(10, limit.Token)).Count != 0 ||
               (await queue.ReadPendingOverridesAsync(10, limit.Token)).Count != 0)
            await Task.Delay(10, limit.Token);
    }

    private static async Task Stop(HttpAgentDispatcher dispatcher)
    {
        using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await dispatcher.StopAsync(limit.Token);
        Assert.True(dispatcher.ExecuteTask!.IsCompletedSuccessfully);
    }

    private sealed class Policies : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken token) => throw new InvalidOperationException("Heartbeat must use the registered sender.");
    }

    // Controlled HTTP peer: persistence happens before the first response stalls.
    // The ledgers model the existing API's idempotency; they do not qualify a new Java implementation.
    private sealed class Backend(bool stallBody) : HttpMessageHandler
    {
        private int _calls, _active, _maxActive, _heartbeats;
        public volatile bool Offline;
        public int Active => Volatile.Read(ref _active);
        public int MaxActive => Volatile.Read(ref _maxActive);
        public int HeartbeatCalls => Volatile.Read(ref _heartbeats);
        public ConcurrentBag<string> Payloads { get; } = [];
        public ConcurrentDictionary<Guid, string> Events { get; } = new();
        public ConcurrentDictionary<Guid, string> Overrides { get; } = new();
        public TaskCompletionSource Persisted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ThreeHeartbeats { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Rejected { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            if (request.RequestUri!.AbsolutePath == "/agent/heartbeat")
            {
                if (Interlocked.Increment(ref _heartbeats) >= 3) ThreeHeartbeats.TrySetResult();
                return new(HttpStatusCode.OK) { Content = new StringContent("{\"status\":\"OK\"}") };
            }
            Assert.Equal("/agent/events", request.RequestUri.AbsolutePath);
            int active = Interlocked.Increment(ref _active);
            UpdateMaxActive(active);
            int call = Interlocked.Increment(ref _calls);
            string body = await request.Content!.ReadAsStringAsync(token);
            Payloads.Add(body);
            if (Offline)
            {
                Interlocked.Decrement(ref _active);
                Rejected.TrySetResult();
                return new(HttpStatusCode.ServiceUnavailable);
            }
            using (var json = JsonDocument.Parse(body))
            {
                Store(json.RootElement.GetProperty("events"), Events);
                Store(json.RootElement.GetProperty("overrides"), Overrides);
            }
            if (call == 1)
            {
                Persisted.TrySetResult();
                if (!stallBody)
                {
                    try { await Task.Delay(Timeout.InfiniteTimeSpan, token); }
                    finally { Interlocked.Decrement(ref _active); }
                }
            }
            return new(HttpStatusCode.OK)
            {
                Content = new StreamContent(new ReceiptStream(call == 1 && stallBody,
                    () => Interlocked.Decrement(ref _active)))
            };
        }

        private void UpdateMaxActive(int value)
        {
            int seen;
            do { seen = Volatile.Read(ref _maxActive); if (seen >= value) return; }
            while (Interlocked.CompareExchange(ref _maxActive, value, seen) != seen);
        }

        private static void Store(JsonElement items, ConcurrentDictionary<Guid, string> ledger)
        {
            foreach (var item in items.EnumerateArray())
            {
                var id = item.GetProperty("eventId").GetGuid();
                string json = item.GetRawText();
                Assert.Equal(json, ledger.GetOrAdd(id, json));
            }
        }
    }

    private sealed class ReceiptStream(bool stall, Action closed) : MemoryStream(
        Encoding.UTF8.GetBytes("{\"acceptedEvents\":1,\"acceptedOverrides\":1}"))
    {
        private int _closed;
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
        {
            if (stall) await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return await base.ReadAsync(buffer, token);
        }
        protected override void Dispose(bool disposing)
        {
            if (Interlocked.Exchange(ref _closed, 1) == 0) closed();
            base.Dispose(disposing);
        }
    }
}
