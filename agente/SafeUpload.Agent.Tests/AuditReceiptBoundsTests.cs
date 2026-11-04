using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Dispatch;
using SafeUpload.Agent.Service.Diagnostics;

namespace SafeUpload.Agent.Tests;

public sealed class AuditReceiptBoundsTests
{
    private const int MaximumReceiptBytes = 16 * 1024;
    private const string Receipt = "{\"acceptedEvents\":1,\"acceptedOverrides\":1}";

    [Theory]
    [InlineData("advertised")]
    [InlineData("streamed")]
    [InlineData("underreported")]
    [InlineData("deep")]
    [InlineData("truncated")]
    public async Task Invalid_receipt_keeps_queue_and_reconnect_sends_identical_batch(string mode)
    {
        using var work = new TestWorkspace();
        var queue = await Queue(work);
        var before = await File.ReadAllBytesAsync(work.QueueFile);
        string body = mode switch
        {
            "deep" => Receipt[..^1] + ",\"future\":" + new string('[', 20) + "0" + new string(']', 20) + "}",
            "truncated" => Receipt[..^1],
            _ => Receipt.PadRight(MaximumReceiptBytes * 4)
        };
        var stream = new ResponseStream(body);
        var health = new CommunicationHealth(true);
        var wire = new Wire(() =>
        {
            var content = new StreamContent(stream);
            if (mode == "advertised") content.Headers.ContentLength = Encoding.UTF8.GetByteCount(body);
            if (mode == "underreported") content.Headers.ContentLength = 1;
            return content;
        });
        using (var client = Client(wire))
        using (var dispatcher = Dispatcher(queue, client, health))
            await Assert.ThrowsAnyAsync<JsonException>(() => dispatcher.DispatchPendingAsync(default));
        Assert.True(stream.BytesRead <= MaximumReceiptBytes + 1);
        if (mode == "advertised") Assert.Equal(0, stream.BytesRead);
        Assert.True(stream.Disposed);
        AssertFailure(health, "InvalidResponse");
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
        var stream = new ResponseStream(Receipt.PadRight(MaximumReceiptBytes), fragment: 7);
        using var client = Client(new Wire(() => new StreamContent(stream)));
        using var dispatcher = Dispatcher(queue, client);
        await dispatcher.DispatchPendingAsync(default);
        Assert.Equal(MaximumReceiptBytes, stream.BytesRead);
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
        var health = new CommunicationHealth(true);
        using var client = Client(new Wire(() => new StreamContent(stream)));
        client.Timeout = callerCancellation ? Timeout.InfiniteTimeSpan : TimeSpan.FromMilliseconds(150);
        using var dispatcher = Dispatcher(queue, client, health);
        var send = dispatcher.DispatchPendingAsync(stop.Token);
        await stream.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        if (callerCancellation) stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => send.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(before, await File.ReadAllBytesAsync(work.QueueFile));
        if (callerCancellation)
        {
            var state = health.Read().Operations.Single(x => x.Operation == "Audit");
            Assert.Equal(1, state.Cancellations);
            Assert.Equal(0, state.Failures);
            Assert.Equal(0, state.Successes);
        }
        else AssertFailure(health, "Timeout");
    }

    [Theory]
    [InlineData(16)]
    [InlineData(17)]
    public async Task Json_depth_boundary_is_enforced(int depth)
    {
        using var work = new TestWorkspace();
        var queue = await Queue(work);
        string body = Receipt[..^1] + ",\"future\":" + new string('[', depth - 1) + "0" + new string(']', depth - 1) + "}";
        using var client = Client(new Wire(() => new StringContent(body)));
        using var dispatcher = Dispatcher(queue, client);
        if (depth == 16) await dispatcher.DispatchPendingAsync(default);
        else await Assert.ThrowsAnyAsync<JsonException>(() => dispatcher.DispatchPendingAsync(default));
        Assert.Equal(depth == 16 ? 0 : 1, (await queue.ReadPendingAsync(100, default)).Count);
        Assert.Equal(depth == 16 ? 0 : 1, (await queue.ReadPendingOverridesAsync(100, default)).Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Cancellation_winning_at_end_of_body_cannot_confirm_queue(bool callerCancellation)
    {
        using var work = new TestWorkspace();
        var queue = await Queue(work);
        var before = await File.ReadAllBytesAsync(work.QueueFile);
        using var stop = new CancellationTokenSource();
        var stream = new ResponseStream(Receipt, waitAtEof: true);
        using var client = Client(new Wire(() => new StreamContent(stream)));
        client.Timeout = callerCancellation ? Timeout.InfiniteTimeSpan : TimeSpan.FromMilliseconds(150);
        using var dispatcher = Dispatcher(queue, client);
        var send = dispatcher.DispatchPendingAsync(stop.Token);
        await stream.Ended.Task.WaitAsync(TimeSpan.FromSeconds(5));
        if (callerCancellation) stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => send.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.True(stream.Disposed);
        Assert.Equal(before, await File.ReadAllBytesAsync(work.QueueFile));
    }

    [Fact]
    public async Task Rejected_http_status_does_not_read_body_or_confirm_queue()
    {
        using var work = new TestWorkspace();
        var queue = await Queue(work);
        var before = await File.ReadAllBytesAsync(work.QueueFile);
        var stream = new ResponseStream(Receipt, stall: true);
        var health = new CommunicationHealth(true);
        using var client = Client(new Wire(() => new StreamContent(stream), HttpStatusCode.ServiceUnavailable));
        using var dispatcher = Dispatcher(queue, client, health);
        await dispatcher.DispatchPendingAsync(default).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(0, stream.BytesRead);
        Assert.False(stream.Started.Task.IsCompleted);
        Assert.True(stream.Disposed);
        Assert.Equal(before, await File.ReadAllBytesAsync(work.QueueFile));
        AssertFailure(health, "HttpRejected", 503);
    }

    private static void AssertFailure(CommunicationHealth health, string kind, int status = 200)
    {
        var state = health.Read().Operations.Single(x => x.Operation == "Audit");
        Assert.Equal(kind, state.LastFailureKind);
        Assert.Equal(status, state.LastHttpStatus);
        Assert.Equal(1, state.Failures);
        Assert.Equal(0, state.Successes);
        Assert.Equal(0, state.InFlight);
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
    private static HttpAgentDispatcher Dispatcher(LocalQueueAuditSink queue, HttpClient client, ICommunicationObserver? observer = null) =>
        new(queue, new Policies(), client, "PC-SYNTHETIC", TimeSpan.FromSeconds(30), NullLogger<HttpAgentDispatcher>.Instance, observer);
    private sealed class Policies : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken token) => Task.FromResult(LocalPolicyStore.CreateDefault());
    }
    private sealed class Wire(Func<HttpContent> response, HttpStatusCode status = HttpStatusCode.OK) : HttpMessageHandler
    {
        public string? Payload;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            Payload = await request.Content!.ReadAsStringAsync(token);
            return new(status) { Content = response() };
        }
    }
    private sealed class ResponseStream(string body, int fragment = int.MaxValue, bool stall = false, bool waitAtEof = false)
        : MemoryStream(Encoding.UTF8.GetBytes(body))
    {
        public override bool CanSeek => false;
        // Make buffering use the same instrumented reads as a network stream; MemoryStream.CopyToAsync bypasses them.
        public override async Task CopyToAsync(Stream destination, int bufferSize, CancellationToken token)
        {
            var buffer = new byte[Math.Min(bufferSize, 4096)];
            int count;
            while ((count = await ReadAsync(buffer, token)) != 0)
                await destination.WriteAsync(buffer.AsMemory(0, count), token);
        }
        public int BytesRead;
        public bool Disposed;
        public TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Ended = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
        {
            Started.TrySetResult();
            if (stall) await Task.Delay(Timeout.InfiniteTimeSpan, token);
            int read = await base.ReadAsync(buffer[..Math.Min(buffer.Length, fragment)], token);
            if (read == 0 && waitAtEof)
            {
                Ended.TrySetResult();
                try { await Task.Delay(Timeout.InfiniteTimeSpan, token); }
                catch (OperationCanceledException) when (token.IsCancellationRequested) { }
                // A completed EOF can race cancellation without the stream throwing.
            }
            BytesRead += read;
            return read;
        }
    }
}

