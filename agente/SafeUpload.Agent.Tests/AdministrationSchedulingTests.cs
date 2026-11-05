using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Dispatch;

namespace SafeUpload.Agent.Tests;

public sealed class AdministrationSchedulingTests
{
    [Fact]
    public async Task Slow_heartbeat_does_not_delay_initial_or_following_audit_batches()
    {
        using var workspace = new TestWorkspace();
        var queue = new LocalQueueAuditSink(workspace.QueueFile);
        await queue.WriteAsync(Event(), CancellationToken.None);
        var handler = new SlowOperationHandler(blockHeartbeat: true);
        using var client = Client(handler);
        using var dispatcher = Dispatcher(queue, client);
        await dispatcher.StartAsync(CancellationToken.None);
        try
        {
            await handler.Blocked.Task.WaitAsync(TimeSpan.FromSeconds(5));
            await WaitForEmpty(queue);
            await queue.WriteAsync(Event(), CancellationToken.None);
            await WaitForEmpty(queue);
            Assert.Equal(1, handler.HeartbeatCalls);
            Assert.Equal(2, handler.AuditCalls);
        }
        finally { await Stop(dispatcher); }
        Assert.True(handler.BlockedCancelled);
    }

    [Fact]
    public async Task Slow_audit_does_not_delay_following_heartbeats_and_stop_preserves_pending_batch()
    {
        using var workspace = new TestWorkspace();
        var queue = new LocalQueueAuditSink(workspace.QueueFile);
        var audit = Event();
        await queue.WriteAsync(audit, CancellationToken.None);
        byte[] before = await File.ReadAllBytesAsync(workspace.QueueFile);
        var handler = new SlowOperationHandler(blockHeartbeat: false);
        using var client = Client(handler);
        using var dispatcher = Dispatcher(queue, client);
        await dispatcher.StartAsync(CancellationToken.None);
        try
        {
            await handler.Blocked.Task.WaitAsync(TimeSpan.FromSeconds(5));
            await handler.ThreeHeartbeats.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(1, handler.AuditCalls); // No overlapping retry of the in-flight batch.
            Assert.Equal(before, await File.ReadAllBytesAsync(workspace.QueueFile));
        }
        finally { await Stop(dispatcher); }
        Assert.True(handler.BlockedCancelled);
        var reopened = new LocalQueueAuditSink(workspace.QueueFile);
        var pending = Assert.Single(await reopened.ReadPendingAsync(100, CancellationToken.None));
        Assert.Equal(audit.EventId, pending.EventId);
        Assert.Equal(audit.OccurredAtUtc, pending.OccurredAtUtc);
        Assert.Equal(before, await File.ReadAllBytesAsync(workspace.QueueFile));

        var recovered = new SlowOperationHandler(blockHeartbeat: null);
        using var recoveredClient = Client(recovered);
        using var retry = Dispatcher(reopened, recoveredClient);
        await retry.StartAsync(CancellationToken.None);
        try { await WaitForEmpty(reopened); }
        finally { await Stop(retry); }
        Assert.Equal(handler.AuditPayload, recovered.AuditPayload);
    }

    private static async Task WaitForEmpty(LocalQueueAuditSink queue)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while ((await queue.ReadPendingAsync(100, timeout.Token)).Count != 0)
            await Task.Delay(10, timeout.Token);
    }

    private static async Task Stop(HttpAgentDispatcher dispatcher)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await dispatcher.StopAsync(timeout.Token);
        Assert.True(dispatcher.ExecuteTask!.IsCompleted);
    }

    private static AuditEvent Event() => new(Guid.NewGuid(), DateTimeOffset.UtcNow, "PC-SYNTHETIC", "user",
        "synthetic.txt", ".txt", 10, Verdict.Blocked, [], [], "test", 1, "synthetic", null, 7, 1, false);

    private static HttpClient Client(HttpMessageHandler handler) => new(handler)
    {
        BaseAddress = new Uri("http://localhost/agent/"), Timeout = TimeSpan.FromSeconds(30)
    };

    private static HttpAgentDispatcher Dispatcher(LocalQueueAuditSink queue, HttpClient client) =>
        new(queue, new Policies(), client, "PC-SYNTHETIC", TimeSpan.FromMilliseconds(30),
            NullLogger<HttpAgentDispatcher>.Instance)
        {
            HeartbeatSender = new RegisteredAgentHeartbeat(new AgentApiClient(client), 7)
        };

    private sealed class Policies : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken token) =>
            throw new InvalidOperationException("Registered heartbeat must not query policy.");
    }

    private sealed class SlowOperationHandler(bool? blockHeartbeat) : HttpMessageHandler
    {
        private int _heartbeats, _audits;
        public int HeartbeatCalls => Volatile.Read(ref _heartbeats);
        public int AuditCalls => Volatile.Read(ref _audits);
        public bool BlockedCancelled { get; private set; }
        public string? AuditPayload { get; private set; }
        public TaskCompletionSource Blocked { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ThreeHeartbeats { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            bool heartbeat = request.RequestUri!.AbsolutePath == "/agent/heartbeat";
            if (heartbeat)
            {
                Assert.Equal("{\"id_host\":7}", await request.Content!.ReadAsStringAsync(token));
                if (Interlocked.Increment(ref _heartbeats) >= 3) ThreeHeartbeats.TrySetResult();
            }
            else
            {
                Assert.Equal("/agent/events", request.RequestUri.AbsolutePath);
                Interlocked.Increment(ref _audits);
                AuditPayload = await request.Content!.ReadAsStringAsync(token);
                using var payload = JsonDocument.Parse(AuditPayload);
                Assert.Single(payload.RootElement.GetProperty("events").EnumerateArray());
            }

            if (blockHeartbeat == heartbeat)
            {
                Blocked.TrySetResult();
                try { await Task.Delay(Timeout.InfiniteTimeSpan, token); }
                catch (OperationCanceledException) { BlockedCancelled = true; throw; }
            }
            return new(HttpStatusCode.OK)
            {
                Content = new StringContent(heartbeat ? "{\"status\":\"OK\"}" :
                    "{\"acceptedEvents\":1,\"acceptedOverrides\":0}")
            };
        }
    }
}
