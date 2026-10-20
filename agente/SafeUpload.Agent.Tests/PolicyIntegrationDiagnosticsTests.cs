using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Configuration;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Policies;

namespace SafeUpload.Agent.Tests;

public sealed class PolicyIntegrationDiagnosticsTests
{
    private static Policy Policy(int version) => LocalPolicyStore.CreateDefault() with { Version = version };
    private static PolicyIntegrationDiagnostics Diagnostics() => new(NullLogger<PolicyIntegrationDiagnostics>.Instance);

    [Fact]
    public async Task Durable_provider_reports_remote_memory_and_disk_without_claiming_driver_acceptance()
    {
        using var workspace = new TestWorkspace();
        using var handler = new PolicyResponse();
        using var client = new HttpClient(handler) { BaseAddress = new Uri("http://policy.invalid/") };
        var remote = new DurableHttpPolicyStore(client, "SYNTHETIC", workspace.PolicyFile, false);
        var diagnostic = Diagnostics();
        using var store = new RefreshingPolicyStore(remote, TimeSpan.FromSeconds(30),
            NullLogger<RefreshingPolicyStore>.Instance, diagnostic);
        await store.LoadAsync(default);
        Assert.Equal("default", diagnostic.Read().SnapshotSource);
        await store.RefreshAsync(default);
        Assert.Equal("remote", diagnostic.Read().SnapshotSource);
        Assert.Equal(3, diagnostic.Read().SnapshotVersion);
        handler.Offline = true;
        await store.RefreshAsync(default);
        Assert.Equal("memory", diagnostic.Read().SnapshotSource);
        Assert.Equal(3, diagnostic.Read().SnapshotVersion);
        await Assert.ThrowsAsync<HttpRequestException>(() => store.LoadCurrentAsync(default));
        Assert.Null(diagnostic.Read().LastAcceptedVersion);
        var reopenedDiagnostic = Diagnostics();
        var reopened = new DurableHttpPolicyStore(client, "SYNTHETIC", workspace.PolicyFile, false);
        using var restored = new RefreshingPolicyStore(reopened, TimeSpan.FromSeconds(30),
            NullLogger<RefreshingPolicyStore>.Instance, reopenedDiagnostic);
        Assert.Equal(3, (await restored.LoadAsync(default)).Version);
        Assert.Equal("disk", reopenedDiagnostic.Read().SnapshotSource);
        Assert.False(reopenedDiagnostic.Read().DriverScopeRecorded);
    }

    [Fact]
    public async Task Snapshot_refresh_never_records_driver_acceptance()
    {
        var diagnostic = Diagnostics();
        using var store = Store(new Remote { Current = Policy(2) }, diagnostic);
        await store.RefreshAsync(default);
        Assert.Equal(2, diagnostic.Read().SnapshotVersion);
        Assert.Null(diagnostic.Read().StrictVersion);
        Assert.Null(diagnostic.Read().LastAcceptedVersion);
        Assert.False(diagnostic.Read().DriverScopeRecorded);
    }

    [Fact]
    public async Task Strict_read_reports_the_candidate_without_changing_legacy_snapshot_or_accepted_scope()
    {
        var diagnostic = Diagnostics();
        var accepted = Policy(1);
        diagnostic.RecordDriverScopeAccepted(accepted);
        var remote = new Remote { Current = Policy(2) };
        using var store = Store(remote, diagnostic);
        var candidate = await store.LoadCurrentAsync(default);
        Assert.Same(remote.Current, candidate);
        Assert.Equal(1, (await store.LoadAsync(default)).Version);
        var state = diagnostic.Read();
        Assert.Equal(2, state.StrictVersion);
        Assert.Equal(1, state.LastAcceptedVersion);
        Assert.Equal(PolicyContentFingerprint.Compute(accepted), state.LastAcceptedFingerprint);
        Assert.NotEqual(state.LastAcceptedFingerprint, state.StrictFingerprint);
    }

    [Fact]
    public async Task Failed_strict_read_keeps_last_receipt_and_exposes_failure_without_exception_content()
    {
        var diagnostic = Diagnostics();
        var remote = new Remote { Current = Policy(2) };
        using var store = Store(remote, diagnostic);
        await store.LoadCurrentAsync(default);
        diagnostic.RecordDriverScopeAccepted(remote.Current);
        var error = new HttpRequestException("secret URL must not be copied into diagnostics");
        remote.Error = error;
        Assert.Same(error, await Assert.ThrowsAsync<HttpRequestException>(() => store.LoadCurrentAsync(default)));
        var failed = diagnostic.Read();
        Assert.Equal(nameof(HttpRequestException), failed.StrictReadError);
        Assert.Equal(2, failed.StrictVersion);
        Assert.True(failed.DriverScopeRecorded); // Historical scope receipt; never protection readiness.
        remote.Error = null;
        await store.LoadCurrentAsync(default);
        Assert.Null(diagnostic.Read().StrictReadError);
    }

    [Fact]
    public async Task Caller_cancellation_does_not_erase_or_fabricate_an_observation()
    {
        var diagnostic = Diagnostics();
        using var store = Store(new Remote { Current = Policy(2) }, diagnostic);
        await store.LoadCurrentAsync(default);
        var before = diagnostic.Read();
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.LoadCurrentAsync(cancelled.Token));
        Assert.Equal(before, diagnostic.Read());
    }

    [Fact]
    public void Same_version_with_different_content_is_distinguishable()
    {
        var diagnostic = Diagnostics();
        var first = Policy(7);
        diagnostic.RecordDriverScopeAccepted(first);
        diagnostic.RecordStrictRead(first with { ActiveCategories = new HashSet<Category> { Category.Secret } });
        var state = diagnostic.Read();
        Assert.Equal(state.StrictVersion, state.LastAcceptedVersion);
        Assert.NotEqual(state.StrictFingerprint, state.LastAcceptedFingerprint);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Disconnect_or_failed_application_invalidates_current_scope_receipt_but_keeps_history(bool failure)
    {
        var diagnostic = Diagnostics();
        diagnostic.RecordDriverScopeAccepted(Policy(1));
        if (failure) diagnostic.RecordApplyFailure(new IOException("private path"));
        else diagnostic.RecordDriverDisconnected();
        var state = diagnostic.Read();
        Assert.False(state.DriverScopeRecorded);
        Assert.Equal(1, state.LastAcceptedVersion);
        Assert.Equal(failure ? nameof(IOException) : null, state.ApplyError);
        diagnostic.RecordDriverScopeAccepted(Policy(2));
        Assert.True(diagnostic.Read().DriverScopeRecorded);
        Assert.Null(diagnostic.Read().ApplyError);
        Assert.Equal(2, diagnostic.Read().LastAcceptedVersion);
    }

    [Fact]
    public void Repeated_observations_do_not_flood_logs()
    {
        var logger = new CapturingLogger();
        var diagnostic = new PolicyIntegrationDiagnostics(logger);
        for (int index = 0; index < 100; index++) diagnostic.RecordStrictRead(Policy(1));
        Assert.Single(logger.Messages);
        Assert.Contains("Acceptance is not protection readiness", logger.Messages[0]);
    }

    [Fact]
    public async Task Broken_log_provider_cannot_change_a_policy_read_result()
    {
        var diagnostic = new PolicyIntegrationDiagnostics(new CapturingLogger { Fail = true });
        var remote = new Remote { Current = Policy(2) };
        using var store = Store(remote, diagnostic);
        Assert.Same(remote.Current, await store.LoadCurrentAsync(default));
        Assert.Equal(2, diagnostic.Read().StrictVersion);
        diagnostic.RecordDriverScopeAccepted(remote.Current);
        Assert.True(diagnostic.Read().DriverScopeRecorded);
    }

    [Fact]
    public void Fingerprint_failure_stays_diagnostic_and_does_not_create_a_fake_hash()
    {
        var diagnostic = Diagnostics();
        diagnostic.RecordStrictRead(Policy(1) with { ExcludedProcesses = new HashSet<string> { "\ud800" } });
        Assert.Equal(1, diagnostic.Read().StrictVersion);
        Assert.Null(diagnostic.Read().StrictFingerprint);
        Assert.Null(diagnostic.Read().LastAcceptedVersion);
    }

    [Fact]
    public void Policy_composition_registers_one_shared_diagnostic_without_starting_the_host()
    {
        var services = new ServiceCollection().AddLogging();
        services.AddAgentPolicies(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        { ["CentroAdministracao:BaseUrl"] = "http://policy.invalid/agent/" }).Build(), "DIAGNOSTIC-TEST", false);
        using var provider = services.BuildServiceProvider();
        Assert.Same(provider.GetRequiredService<PolicyIntegrationDiagnostics>(), provider.GetRequiredService<PolicyIntegrationDiagnostics>());
        Assert.IsType<RefreshingPolicyStore>(provider.GetRequiredService<IPolicyStore>());
        Assert.Empty(provider.GetServices<Microsoft.Extensions.Hosting.IHostedService>());
    }

    private static RefreshingPolicyStore Store(Remote remote, PolicyIntegrationDiagnostics diagnostic) =>
        new(remote, _ => Task.FromResult(Policy(1)), TimeSpan.FromSeconds(30),
            NullLogger<RefreshingPolicyStore>.Instance, diagnostic);

    private sealed class Remote : IPolicyStore
    {
        public required Policy Current { get; init; }
        public Exception? Error { get; set; }
        public Task<Policy> LoadAsync(CancellationToken token) => Task.FromResult(Current);
        public Task<Policy> LoadCurrentAsync(CancellationToken token) => Error is { } error
            ? Task.FromException<Policy>(error) : Task.FromResult(Current);
    }

    private sealed class CapturingLogger : ILogger<PolicyIntegrationDiagnostics>
    {
        public bool Fail { get; init; }
        public List<string> Messages { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => true;
        public void Log<TState>(LogLevel level, EventId eventId, TState state, Exception? error, Func<TState, Exception?, string> formatter)
        {
            if (Fail) throw new IOException("log provider failure");
            Messages.Add(formatter(state, error));
        }
    }

    private sealed class PolicyResponse : HttpMessageHandler
    {
        public bool Offline { get; set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            if (Offline) throw new HttpRequestException("synthetic offline");
            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            { Content = new StringContent("""
                {"version":3,"activeCategories":["Cpf"],"maxFileSizeMb":20,"inspectionTimeoutSeconds":5,
                 "monitoredScopes":{"extensions":[".pptx",".zip"],"destinationPaths":[],"removableDrives":false,"networkPaths":false}}
                """) });
        }
    }
}
