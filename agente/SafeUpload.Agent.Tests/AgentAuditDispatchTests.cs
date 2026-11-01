using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Dispatch;

namespace SafeUpload.Agent.Tests;

public sealed class AgentAuditDispatchTests
{
    [Fact]
    public async Task Wire_omits_inspected_snippets_and_reports_actual_host_build_without_changing_local_history()
    {
        using var work = new TestWorkspace();
        var queue = new LocalQueueAuditSink(work.QueueFile);
        var audit = Event() with { MaskedSnippets = ["SYNTHETIC-CONTENT-NEVER-SEND"], OwnerSid = "S-1-5-21-1-2-3-1001" };
        await queue.WriteAsync(audit, CancellationToken.None);
        var wire = new Wire(); await Cycle(queue, wire);
        using var parsed = JsonDocument.Parse(wire.Body!);
        var root = parsed.RootElement;
        Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal(Environment.MachineName, root.GetProperty("hostname").GetString());
        Assert.Equal(typeof(HttpAgentDispatcher).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion,
            root.GetProperty("agentVersion").GetString());
        Assert.Empty(root.GetProperty("events")[0].GetProperty("maskedSnippets").EnumerateArray());
        Assert.DoesNotContain("SYNTHETIC-CONTENT-NEVER-SEND", wire.Body!);
        Assert.DoesNotContain("ownerSid", wire.Body!, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(audit.OwnerSid, wire.Body!);
        var local = Assert.Single(await queue.ReadRecentAsync(5, CancellationToken.None));
        Assert.Equal(audit.MaskedSnippets, local.MaskedSnippets);
        Assert.Equal(audit.EventId, local.EventId);
        Assert.Equal(audit.OwnerSid, local.OwnerSid);
        Assert.Equal(audit.OccurredAtUtc.Offset, local.OccurredAtUtc.Offset);
        Assert.True(local.Dispatched);
    }

    [Theory]
    [InlineData(AuditChannel.File, Verdict.Blocked)]
    [InlineData(AuditChannel.File, Verdict.Approved)]
    [InlineData(AuditChannel.Clipboard, Verdict.AllowedWithoutInspection)]
    [InlineData(AuditChannel.Web, Verdict.Retained)]
    public async Task Wire_preserves_authoritative_metadata_for_all_channels_and_does_not_rewrite_legacy_destinations(AuditChannel channel, Verdict verdict)
    {
        using var work = new TestWorkspace();
        var queue = new LocalQueueAuditSink(work.QueueFile);
        var audit = Event() with { Channel = channel, Verdict = verdict, FileName = @"C:\legacy\synthetic.txt",
            DestinationPath = channel == AuditChannel.Web ? "https://example.test/legacy/path?synthetic=value#fragment" : @"E:\legacy\destination",
            PublishedSha256Hex = new string('a', 64), NotInspectedReason = "synthetic_reason" };
        await queue.WriteAsync(audit, CancellationToken.None);
        var wire = new Wire(); await Cycle(queue, wire);
        using var parsed = JsonDocument.Parse(wire.Body!);
        var item = parsed.RootElement.GetProperty("events")[0];
        Assert.Equal(audit.EventId, item.GetProperty("eventId").GetGuid());
        Assert.Equal(audit.EndpointId, item.GetProperty("endpointId").GetString());
        Assert.Equal(audit.UserName, item.GetProperty("userName").GetString());
        Assert.Equal(audit.FileName, item.GetProperty("fileName").GetString());
        Assert.Equal(audit.Extension, item.GetProperty("extension").GetString());
        Assert.Equal(audit.SizeBytes, item.GetProperty("sizeBytes").GetInt64());
        Assert.Equal(verdict.ToString(), item.GetProperty("verdict").GetString());
        Assert.Equal(channel.ToString(), item.GetProperty("channel").GetString());
        Assert.Equal(new[] { "Cpf" }, item.GetProperty("categories").EnumerateArray().Select(c => c.GetString()));
        Assert.Equal(audit.ProcessName, item.GetProperty("processName").GetString());
        Assert.Equal(audit.ProcessId, item.GetProperty("processId").GetInt32());
        Assert.Equal(audit.DestinationPath, item.GetProperty("destinationPath").GetString());
        Assert.Equal(audit.PolicyVersion, item.GetProperty("policyVersion").GetInt32());
        Assert.Equal(audit.ElapsedMs, item.GetProperty("elapsedMs").GetInt64());
        Assert.Equal(audit.PublishedSha256Hex, item.GetProperty("publishedSha256Hex").GetString());
        Assert.Equal(audit.NotInspectedReason, item.GetProperty("notInspectedReason").GetString());
        Assert.Equal(audit.OccurredAtUtc, item.GetProperty("occurredAtUtc").GetDateTimeOffset());
        Assert.Equal(TimeSpan.Zero, item.GetProperty("occurredAtUtc").GetDateTimeOffset().Offset);
        Assert.False(item.GetProperty("dispatched").GetBoolean());
        Assert.Equal(19, item.EnumerateObject().Count());
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"acceptedEvents\":1,\"acceptedOverrides\":0}")]
    public async Task Incomplete_receipt_preserves_event_and_justification_with_original_local_bytes(string reply)
    {
        using var work = new TestWorkspace();
        var queue = new LocalQueueAuditSink(work.QueueFile);
        var audit = Event() with { MaskedSnippets = ["SYNTHETIC-LOCAL-ONLY"] };
        var justification = new AuditOverride(audit.EventId,"Literal <b>reason</b>",audit.OccurredAtUtc,"synthetic-user","PC-SYNTHETIC");
        await queue.WriteAsync(audit, CancellationToken.None);
        await queue.RecordOverrideAsync(justification, CancellationToken.None);
        string before = await File.ReadAllTextAsync(work.QueueFile);
        var wire = new Wire(reply); await Cycle(queue, wire);
        Assert.Equal(before, await File.ReadAllTextAsync(work.QueueFile));
        Assert.Single(await queue.ReadPendingAsync(100, CancellationToken.None));
        Assert.Equal(justification, Assert.Single(await queue.ReadPendingOverridesAsync(100, CancellationToken.None)));
        using var parsed = JsonDocument.Parse(wire.Body!);
        var item = parsed.RootElement.GetProperty("overrides")[0];
        Assert.Equal(justification.EventId, item.GetProperty("eventId").GetGuid());
        Assert.Equal(justification.Justification, item.GetProperty("justification").GetString());
        Assert.Equal(justification.OccurredAtUtc, item.GetProperty("occurredAtUtc").GetDateTimeOffset());
        Assert.Equal(TimeSpan.Zero, item.GetProperty("occurredAtUtc").GetDateTimeOffset().Offset);
        Assert.DoesNotContain("SYNTHETIC-LOCAL-ONLY", wire.Body!);
    }

    [Fact]
    public async Task Lost_response_reopens_queue_and_replays_the_same_projected_request()
    {
        using var work = new TestWorkspace();
        var queue = new LocalQueueAuditSink(work.QueueFile);
        await queue.WriteAsync(Event(), CancellationToken.None);
        var failed = new Wire(fail: true);
        await Assert.ThrowsAsync<HttpRequestException>(() => Cycle(queue, failed));
        var reopened = new LocalQueueAuditSink(work.QueueFile);
        Assert.Single(await reopened.ReadPendingAsync(100, CancellationToken.None));
        var accepted = new Wire(); await Cycle(reopened, accepted);
        Assert.Equal(failed.Body, accepted.Body);
        Assert.Empty(await reopened.ReadPendingAsync(100, CancellationToken.None));
    }

    [Fact]
    public async Task Projection_confirms_only_the_transmitted_batch()
    {
        using var work = new TestWorkspace();
        var queue = new LocalQueueAuditSink(work.QueueFile);
        for (int i=0; i<101; i++) await queue.WriteAsync(Event(), CancellationToken.None);
        var wire = new Wire(); await Cycle(queue, wire);
        using var parsed = JsonDocument.Parse(wire.Body!);
        Assert.Equal(100, parsed.RootElement.GetProperty("events").GetArrayLength());
        Assert.Single(await queue.ReadPendingAsync(100, CancellationToken.None));
    }

    [Fact]
    public async Task Override_only_batch_has_both_arrays_and_preserves_justification_identity()
    {
        using var work = new TestWorkspace();
        var queue = new LocalQueueAuditSink(work.QueueFile);
        var value = new AuditOverride(Guid.NewGuid(),"Synthetic reason",Event().OccurredAtUtc,"synthetic-user","PC-SYNTHETIC");
        await queue.RecordOverrideAsync(value, CancellationToken.None);
        var wire = new Wire(); await Cycle(queue, wire);
        using var parsed = JsonDocument.Parse(wire.Body!);
        Assert.Empty(parsed.RootElement.GetProperty("events").EnumerateArray());
        Assert.Equal(value.EventId, parsed.RootElement.GetProperty("overrides")[0].GetProperty("eventId").GetGuid());
        Assert.Empty(await queue.ReadPendingOverridesAsync(100, CancellationToken.None));
    }

    private static AuditEvent Event() => new(Guid.NewGuid(),new DateTimeOffset(2026,10,30,12,30,0,TimeSpan.FromHours(-3)),
        "PC-SYNTHETIC","synthetic-user","synthetic.txt",".txt",42,Verdict.Blocked,[Category.Cpf],[],"editor.exe",12,@"E:\synthetic",null,7,3,false);
    private static async Task Cycle(LocalQueueAuditSink queue, Wire handler)
    {
        using var client = new HttpClient(handler) { BaseAddress = new Uri("http://127.0.0.1/agent/") };
        using var dispatcher = new HttpAgentDispatcher(queue,new Policies(),client,"PC-SYNTHETIC",TimeSpan.FromSeconds(30),NullLogger<HttpAgentDispatcher>.Instance);
        await dispatcher.RunCycleAsync(CancellationToken.None);
    }
    private sealed class Policies : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken token) => Task.FromResult(LocalPolicyStore.CreateDefault());
    }
    private sealed class Wire(string? reply=null,bool fail=false) : HttpMessageHandler
    {
        public string? Body { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("heartbeat")) return new(HttpStatusCode.OK);
            Body = await request.Content!.ReadAsStringAsync(token);
            if (fail) throw new HttpRequestException("Synthetic lost response");
            using var parsed = JsonDocument.Parse(Body);
            string result = reply ?? JsonSerializer.Serialize(new { acceptedEvents=parsed.RootElement.GetProperty("events").GetArrayLength(),
                acceptedOverrides=parsed.RootElement.GetProperty("overrides").GetArrayLength() });
            return new(HttpStatusCode.OK) { Content=new StringContent(result,Encoding.UTF8,"application/json") };
        }
    }
}
