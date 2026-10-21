using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Service.Policies;
using System.Text;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// Exercises the real HTTP provider and staged decision engine together.
/// No service, filter port, protected destination or network listener is started.
/// </summary>
public sealed class AdaptedRemotePolicyAuthorityTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    private readonly List<IDisposable> _decorators = [];
    public void Dispose()
    {
        foreach (var decorator in _decorators) decorator.Dispose();
        _workspace.Dispose();
    }
    private static readonly string[] Providers = ["durable", "cached", "refreshing", "nested"];
    public static IEnumerable<object[]> FailureCases()
    {
        foreach (var provider in Providers)
        foreach (var decision in new[] { "inspection", "approval", "justification" })
        foreach (var failure in new[] { "network", "server", "json", "null", "timeout" })
            yield return [provider, decision, failure];
    }
    public static IEnumerable<object[]> ChangeCases()
    {
        foreach (var provider in Providers)
        foreach (var decision in new[] { "approval", "justification" })
        foreach (var sameRevision in new[] { false, true })
            yield return [provider, decision, sameRevision];
    }
    public static IEnumerable<object[]> CancellationCases()
    {
        foreach (var provider in Providers)
        foreach (var decision in new[] { "inspection", "approval", "justification" })
            yield return [provider, decision];
    }
    private IPolicyStore Provider(string provider, HttpClient client)
    {
        var durable = new DurableHttpPolicyStore(client, "POLICY-AUTHORITY-TEST",
            Path.Combine(_workspace.Root, "cache.json"), enforceProtectedAcl: false);
        if (provider == "durable") return durable;
        if (provider == "cached") return new CachedPolicyStore(durable, TimeSpan.FromHours(1));
        var refreshing = new RefreshingPolicyStore(durable, TimeSpan.FromHours(1),
            NullLogger<RefreshingPolicyStore>.Instance);
        _decorators.Add(refreshing);
        return provider == "refreshing" ? refreshing
            : new CachedPolicyStore(refreshing, TimeSpan.FromHours(1));
    }

    [Theory]
    [MemberData(nameof(FailureCases))]
    public async Task A_previous_remote_success_and_legacy_fallback_cannot_authorize_a_staged_decision(
        string provider, string decision, string failure)
    {
        using var handler = new ControlledHandler();
        using var client = CreateClient(handler);
        var store = Provider(provider, client);
        var service = CreateService(store);
        var operation = CreateOperation(decision);
        var inspected = await service.InspectStagedAsync(operation, CancellationToken.None);
        Assert.Equal(7, inspected.PolicyVersion);
        Assert.Equal(decision == "justification" ? Verdict.Blocked : Verdict.Approved, inspected.Verdict);
        Assert.True(await RevalidateAsync(service, operation, inspected, decision, CancellationToken.None));

        handler.Response = _ => failure switch
        {
            "network" => throw new HttpRequestException("controlled network failure"),
            "server" => Task.FromResult(Response("unavailable", HttpStatusCode.InternalServerError)),
            "json" => Task.FromResult(Response("<html>not a policy</html>")),
            "null" => Task.FromResult(Response("null")),
            "timeout" => throw new TaskCanceledException("controlled HTTP deadline"),
            _ => throw new ArgumentOutOfRangeException(nameof(failure))
        };

        // The legacy API is deliberately available; it must not become staged authority.
        Assert.Equal(7,
            (await store.LoadAsync(CancellationToken.None)).Version);
        Func<Task> attempt = decision == "inspection"
            ? async () => { await service.InspectStagedAsync(operation, CancellationToken.None); }
            : async () => { await RevalidateAsync(service, operation, inspected, decision, CancellationToken.None); };
        if (failure is "network" or "server")
            await Assert.ThrowsAsync<HttpRequestException>(attempt);
        else if (failure == "json")
            await Assert.ThrowsAsync<System.Text.Json.JsonException>(attempt);
        else if (failure == "null")
            await Assert.ThrowsAsync<InvalidPolicyException>(attempt);
        else
            await Assert.ThrowsAnyAsync<OperationCanceledException>(attempt);
        Assert.Equal(0, service.ActiveInspectionWorkers);
        Assert.Empty(await new LocalQueueAuditSink(_workspace.QueueFile).ReadRecentAsync(10, CancellationToken.None));
    }

    [Theory]
    [MemberData(nameof(ChangeCases))]
    public async Task Remote_revision_or_same_revision_content_change_revokes_the_previous_decision(
        string provider, string decision, bool sameRevision)
    {
        using var handler = new ControlledHandler();
        using var client = CreateClient(handler);
        var service = CreateService(Provider(provider, client));
        var operation = CreateOperation(decision);
        var inspected = await service.InspectStagedAsync(operation, CancellationToken.None);
        Assert.Equal(decision == "justification" ? Verdict.Blocked : Verdict.Approved, inspected.Verdict);
        Assert.True(await RevalidateAsync(service, operation, inspected, decision, CancellationToken.None));

        handler.Response = _ => Task.FromResult(Response(PolicyJson(sameRevision ? 7 : 8, sameRevision ? 21 : 20)));
        Assert.False(await RevalidateAsync(service, operation, inspected, decision, CancellationToken.None));

        handler.Response = _ => Task.FromResult(Response(PolicyJson()));
        Assert.True(await RevalidateAsync(service, operation, inspected, decision, CancellationToken.None));
    }

    [Theory]
    [MemberData(nameof(CancellationCases))]
    public async Task In_flight_caller_cancellation_reaches_HTTP_and_cannot_authorize_a_staged_decision(string provider, string decision)
    {
        using var handler = new ControlledHandler();
        using var client = CreateClient(handler);
        var service = CreateService(Provider(provider, client));
        var operation = CreateOperation(decision);
        var inspected = await service.InspectStagedAsync(operation, CancellationToken.None);
        Assert.Equal(decision == "justification" ? Verdict.Blocked : Verdict.Approved, inspected.Verdict);
        using var cancellation = new CancellationTokenSource();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var cancelled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        handler.Response = async token =>
        {
            entered.SetResult();
            try { await Task.Delay(Timeout.InfiniteTimeSpan, token); }
            catch (OperationCanceledException) { cancelled.SetResult(); throw; }
            throw new InvalidOperationException("The pending HTTP fixture must only finish by cancellation.");
        };
        Task attempt = decision == "inspection"
            ? service.InspectStagedAsync(operation, cancellation.Token)
            : RevalidateAsync(service, operation, inspected, decision, cancellation.Token);
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            cancellation.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => attempt.WaitAsync(TimeSpan.FromSeconds(5)));
            await cancelled.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(0, service.ActiveInspectionWorkers);
            handler.Response = _ => Task.FromResult(Response(PolicyJson()));
            Assert.True(await RevalidateAsync(service, operation, inspected, decision, CancellationToken.None));
        }
        finally
        {
            cancellation.Cancel();
            // Drain the outstanding fixture even if an assertion fails.
            try { await attempt.WaitAsync(TimeSpan.FromSeconds(5)); }
            catch (OperationCanceledException) { }
        }
    }

    private InspectionService CreateService(IPolicyStore store) => new(store,
        new LocalQueueAuditSink(_workspace.QueueFile), ExtractorRegistry.CreateDefault(), new VerdictCache());

    private FileOperation CreateOperation(string decision) => TestWorkspace.Operation(
        _workspace.WriteText("private-snapshot.txt", decision == "justification" ? "CPF: 529.982.247-25" : "Clean private bytes."),
        // Cloud is the existing domain enum for a local path selected by policy;
        // this is not a cloud-sync or removable-media qualification test.
        destination: DestinationKind.Cloud, destinationPath: @"C:\PolicyAuthorityProtected\result.txt");

    private static Task<bool> RevalidateAsync(InspectionService service, FileOperation operation,
        InspectionResult result, string decision, CancellationToken token) => decision == "justification"
        ? service.IsCurrentStagedJustificationAllowedAsync(operation, result, token)
        : service.IsCurrentStagedApprovalAsync(operation, result, token);

    private static HttpClient CreateClient(ControlledHandler handler) => new(handler, disposeHandler: false)
    { BaseAddress = new Uri("http://policy-authority.invalid/agent/") };

    private static HttpResponseMessage Response(string json, HttpStatusCode status = HttpStatusCode.OK) => new(status)
    { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    private static string PolicyJson(int version = 7, int size = 20) => $$"""
        { "version": {{version}}, "activeCategories": ["Cpf"],
          "monitoredScopes": { "extensions": [".txt"],
            "destinationPaths": ["C:\\PolicyAuthorityProtected"],
            "removableDrives": false, "networkPaths": false },
          "maxFileSizeMb": {{size}}, "inspectionTimeoutSeconds": 5,
          "overrideAllowed": true, "failOpen": true, "excludedProcesses": [] }
        """;

    private sealed class ControlledHandler : HttpMessageHandler
    {
        public Func<CancellationToken, Task<HttpResponseMessage>> Response { get; set; } =
            _ => Task.FromResult(AdaptedRemotePolicyAuthorityTests.Response(PolicyJson()));

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            Assert.Equal("/agent/policy", request.RequestUri!.AbsolutePath);
            Assert.Equal("?endpointId=POLICY-AUTHORITY-TEST", request.RequestUri.Query);
            return Response(token);
        }
    }
}
