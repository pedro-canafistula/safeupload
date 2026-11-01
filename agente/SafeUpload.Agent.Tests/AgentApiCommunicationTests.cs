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

public sealed class AgentApiCommunicationTests
{
    private const string Sensitive = "SENSITIVE-SYNTHETIC";

    [Theory]
    [InlineData(200, "{\"status\":\"OK\"}", null)]
    [InlineData(200, "{\"status\":\"WRONG\"}", "InvalidResponse")]
    [InlineData(200, "{\"status\":\"OK\",\"status\":\"OK\"}", "InvalidResponse")]
    [InlineData(200, Sensitive, "InvalidResponse")]
    [InlineData(401, Sensitive, "HttpRejected")]
    [InlineData(503, Sensitive, "HttpRejected")]
    public async Task Current_host_sender_observes_one_attempt_and_never_exposes_identity_or_body(int status, string body, string? failure)
    {
        var health = new CommunicationHealth(true);
        var handler = new Handler(_ => Reply(status, body));
        using var http = Client(handler);
        var sender = AgentHeartbeatConfiguration.Parse("AgentApi", "7").CreateSender(http, health)!;
        var error = await Record.ExceptionAsync(() => sender.SendAsync(CancellationToken.None));
        Assert.Equal(failure is null, error is null);
        Assert.Equal("/SENSITIVE-SYNTHETIC/agent/heartbeat", handler.Path);
        Assert.Equal("{\"id_host\":7}", handler.Body);
        var state = State(health, CommunicationOperation.Heartbeat);
        Assert.Equal(1, state.Attempts);
        Assert.Equal(0, state.InFlight);
        Assert.Equal(status, state.LastHttpStatus);
        Assert.Equal(failure, state.LastFailureKind);
        Assert.Equal(failure is null ? 1 : 0, state.Successes);
        Assert.Equal(failure is null ? 0 : 1, state.Failures);
        Assert.Equal(0, State(health, CommunicationOperation.Policy).Attempts);
        Assert.Equal(0, State(health, CommunicationOperation.Audit).Attempts);
        Assert.DoesNotContain(Sensitive, JsonSerializer.Serialize(health.Read()));
    }

    [Theory]
    [InlineData("transport", "TransportError")]
    [InlineData("timeout", "Timeout")]
    [InlineData("size", "InvalidResponse")]
    [InlineData("cancel", null)]
    public async Task Current_sender_distinguishes_transport_timeout_size_and_caller_cancellation(string mode, string? failure)
    {
        var health = new CommunicationHealth(true);
        using var cancel = new CancellationTokenSource();
        if (mode == "cancel") cancel.Cancel();
        using var http = Client(new Handler(_ => mode switch
        {
            "transport" => throw new HttpRequestException(Sensitive),
            "timeout" => throw new TaskCanceledException(Sensitive),
            _ => Reply(200, new string('x', 16385))
        }));
        var client = new AgentApiClient(http, health);
        Assert.NotNull(await Record.ExceptionAsync(() => client.HeartbeatAsync(7, cancel.Token)));
        var state = State(health, CommunicationOperation.Heartbeat);
        Assert.Equal(1, state.Attempts);
        Assert.Equal(0, state.InFlight);
        Assert.Equal(mode == "cancel" ? 1 : 0, state.Cancellations);
        Assert.Equal(mode == "cancel" ? 0 : 1, state.Failures);
        Assert.Equal(failure, state.LastFailureKind);
        Assert.Equal(mode == "size" ? (int?)200 : null, state.LastHttpStatus);
        Assert.DoesNotContain(Sensitive, JsonSerializer.Serialize(health.Read()));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Broken_monitor_does_not_change_current_heartbeat_result(bool failOnStart)
    {
        using var http = Client(new Handler(_ => Reply(200, "{\"status\":\"OK\"}")));
        await new AgentApiClient(http, new BrokenObserver(failOnStart)).HeartbeatAsync(7, CancellationToken.None);
    }

    [Fact]
    public async Task Invalid_host_does_not_invent_a_network_attempt()
    {
        var health = new CommunicationHealth(true);
        var handler = new Handler(_ => throw new InvalidOperationException("No network expected"));
        using var http = Client(handler);
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => new AgentApiClient(http, health).HeartbeatAsync(0, CancellationToken.None));
        Assert.Null(handler.Path);
        Assert.Equal(0, State(health, CommunicationOperation.Heartbeat).Attempts);
    }

    [Fact]
    public async Task Dispatcher_counts_modern_heartbeat_once_and_keeps_audit_failure_and_recovery_separate()
    {
        using var workspace = new TestWorkspace();
        var queue = new LocalQueueAuditSink(workspace.QueueFile);
        await queue.WriteAsync(new AuditEvent(Guid.NewGuid(), DateTimeOffset.UtcNow, "PC", "synthetic",
            "synthetic.txt", ".txt", 1, Verdict.Blocked, [Category.Cpf], [], "synthetic", 1,
            "synthetic", null, 1, 1, false), CancellationToken.None);
        var before = await File.ReadAllBytesAsync(workspace.QueueFile);
        var health = new CommunicationHealth(true);
        bool recover = false;
        using var http = Client(new Handler(request => request.RequestUri!.AbsolutePath.EndsWith("heartbeat")
            ? Reply(recover ? 200 : 503, recover ? "{\"status\":\"OK\"}" : Sensitive)
            : Reply(200, recover ? "{\"acceptedEvents\":1,\"acceptedOverrides\":0}"
                : "{\"acceptedEvents\":0,\"acceptedEvents\":1,\"acceptedOverrides\":0}")));
        using var dispatcher = new HttpAgentDispatcher(queue, new UnavailablePolicy(), http, "PC",
            TimeSpan.FromSeconds(30), NullLogger<HttpAgentDispatcher>.Instance, health)
        {
            HeartbeatSender = AgentHeartbeatConfiguration.Parse("AgentApi", "7").CreateSender(http, health)
        };
        await dispatcher.RunCycleAsync(CancellationToken.None);
        Assert.Equal(before, await File.ReadAllBytesAsync(workspace.QueueFile));
        Assert.Equal("HttpRejected", State(health, CommunicationOperation.Heartbeat).LastFailureKind);
        Assert.Equal("InvalidResponse", State(health, CommunicationOperation.Audit).LastFailureKind);
        recover = true;
        await dispatcher.RunCycleAsync(CancellationToken.None);
        Assert.Empty(await queue.ReadPendingAsync(100, CancellationToken.None));
        foreach (var operation in new[] { CommunicationOperation.Heartbeat, CommunicationOperation.Audit })
        {
            var state = State(health, operation);
            Assert.Equal(2, state.Attempts);
            Assert.Equal(1, state.Failures);
            Assert.Equal(1, state.Successes);
            Assert.Equal(0, state.InFlight);
            Assert.Equal("Success", state.State);
        }
        await dispatcher.DispatchPendingAsync(CancellationToken.None);
        Assert.Equal(2, State(health, CommunicationOperation.Audit).Attempts);
        Assert.Equal(0, State(health, CommunicationOperation.Policy).Attempts);
        Assert.DoesNotContain(Sensitive, JsonSerializer.Serialize(health.Read()));
    }

    private static CommunicationOperationHealth State(CommunicationHealth health, CommunicationOperation operation) =>
        health.Read().Operations.Single(value => value.Operation == operation.ToString());
    private static HttpClient Client(HttpMessageHandler handler) => new(handler)
        { BaseAddress = new Uri("http://localhost/" + Sensitive + "/agent/") };
    private static HttpResponseMessage Reply(int status, string body) => new((HttpStatusCode)status)
        { Content = new StringContent(body, Encoding.UTF8, "application/json") };
    private sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> action) : HttpMessageHandler
    {
        public string? Path { get; private set; }
        public string? Body { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Path = request.RequestUri!.AbsolutePath;
            Body = await request.Content!.ReadAsStringAsync(token);
            return action(request);
        }
    }
    private sealed class UnavailablePolicy : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken token) => throw new InvalidOperationException("Modern heartbeat must not read policy");
    }
    private sealed class BrokenObserver(bool failOnStart) : ICommunicationObserver
    {
        public long Started(CommunicationOperation operation) => failOnStart ? throw new IOException(Sensitive) : 1;
        public void Completed(CommunicationOperation operation, long attempt, CommunicationOutcome outcome,
            CommunicationFailure? failure, int? httpStatus, PolicyLoadSource? source, bool? persisted) => throw new IOException(Sensitive);
    }
}
