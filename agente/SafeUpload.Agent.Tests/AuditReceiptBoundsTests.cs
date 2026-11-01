using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Dispatch;

namespace SafeUpload.Agent.Tests;

public sealed class AuditReceiptBoundsTests
{
    private const string Receipt = "{\"acceptedEvents\":1,\"acceptedOverrides\":1}";

    [Theory]
    [InlineData("advertised")]
    [InlineData("streamed")]
    [InlineData("deep")]
    [InlineData("truncated")]
    public async Task Invalid_receipt_keeps_queue_and_reconnect_sends_identical_batch(string mode)
    {
        using var work = new TestWorkspace();
        var queue = await Queue(work);
        var before = await File.ReadAllBytesAsync(work.QueueFile);
        string body = mode switch
        {
            "deep" => "{\"future\":" + new string('[', 20) + "0" + new string(']', 20) + "}",
            "truncated" => Receipt[..^1],
            _ => Receipt.PadRight(HttpAgentDispatcher.MaximumReceiptBytes + 1)
        };
        var stream = new ResponseStream(body);
        var wire = new Wire(() => mode == "advertised" ? new StringContent(body) : new StreamContent(stream));
        using (var client = Client(wire))
        using (var dispatcher = Dispatcher(queue, client))
            await Assert.ThrowsAnyAsync<JsonException>(() => dispatcher.DispatchPendingAsync(default));
        Assert.True(stream.BytesRead <= HttpAgentDispatcher.MaximumReceiptBytes + 1);
        Assert.Equal(before, await File.ReadAllBytesAsync(work.QueueFile));
        var reopened = new LocalQueueAuditSink(work.QueueFile);
        Assert.Single(await reopened.ReadPendingAsync(100, default));
        Assert.Single(await reopened.ReadPendingOverridesAsync(100, default));
        var recovered = new Wire(() => new StringContent(Receipt));
        using (var client = Client(recovered))
        using (var dispatcher = Dispatcher(reopened, client))
            await dispatcher.DispatchPendingAsync(default);
        Assert.Equal(wire.Payload, recovered.Payload);
        Assert.Empty(await reopened.ReadPendingAsync(100, default));
        Assert.Empty(await reopened.ReadPendingOverridesAsync(100, default));
    }

    [Fact]
    public async Task Exact_limit_with_fragmented_reads_is_accepted()
    {
        using var work = new TestWorkspace();
        var queue = await Queue(work);
        var stream = new ResponseStream(Receipt.PadRight(HttpAgentDispatcher.MaximumReceiptBytes), fragment: 7);
        using var client = Client(new Wire(() => new StreamContent(stream)));
        using var dispatcher = Dispatcher(queue, client);
        await dispatcher.DispatchPendingAsync(default);
        Assert.Equal(HttpAgentDispatcher.MaximumReceiptBytes, stream.BytesRead);
        Assert.Empty(await queue.ReadPendingAsync(100, default));
        Assert.Empty(await queue.ReadPendingOverridesAsync(100, default));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Stalled_body_obeys_http_deadline_or_caller_cancellation(bool callerCancellation)
    {
        using var work = new TestWorkspace();
        var queue = await Queue(work);
        var before = await File.ReadAllBytesAsync(work.QueueFile);
        using var stop = new CancellationTokenSource();
        var stream = new ResponseStream(Receipt, stall: true);
        using var client = Client(new Wire(() => new StreamContent(stream)));
        client.Timeout = callerCancellation ? Timeout.InfiniteTimeSpan : TimeSpan.FromMilliseconds(150);
        using var dispatcher = Dispatcher(queue, client);
        var send = dispatcher.DispatchPendingAsync(stop.Token);
        await stream.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        if (callerCancellation) stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => send.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(before, await File.ReadAllBytesAsync(work.QueueFile));
    }

    private static async Task<LocalQueueAuditSink> Queue(TestWorkspace work)
    {
        var queue = new LocalQueueAuditSink(work.QueueFile);
        var audit = new AuditEvent(Guid.NewGuid(), DateTimeOffset.UtcNow, "PC-SYNTHETIC", "synthetic-user",
            "synthetic.txt", ".txt", 10, Verdict.Blocked, [], [], "test", 1, "synthetic", null, 7, 1, false);
        await queue.WriteAsync(audit, default);
        await queue.RecordOverrideAsync(audit.EventId.ToString(), "Synthetic reason", default);
        return queue;
    }

    private static HttpClient Client(Wire wire) => new(wire) { BaseAddress = new Uri("https://example.test/agent/") };
    private static HttpAgentDispatcher Dispatcher(LocalQueueAuditSink queue, HttpClient client) =>
        new(queue, new Policies(), client, "PC-SYNTHETIC", TimeSpan.FromSeconds(30), NullLogger<HttpAgentDispatcher>.Instance);
    private sealed class Policies : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken token) => Task.FromResult(LocalPolicyStore.CreateDefault());
    }
    private sealed class Wire(Func<HttpContent> response) : HttpMessageHandler
    {
        public string? Payload;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            Payload = await request.Content!.ReadAsStringAsync(token);
            return new(HttpStatusCode.OK) { Content = response() };
        }
    }
    private sealed class ResponseStream(string body, int fragment = int.MaxValue, bool stall = false)
        : MemoryStream(Encoding.UTF8.GetBytes(body))
    {
        public override bool CanSeek => false;
        public int BytesRead;
        public TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
        {
            Started.TrySetResult();
            if (stall) await Task.Delay(Timeout.InfiniteTimeSpan, token);
            int read = await base.ReadAsync(buffer[..Math.Min(buffer.Length, fragment)], token);
            BytesRead += read;
            return read;
        }
    }
}

