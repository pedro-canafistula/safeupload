using System.IO.Pipes;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Diagnostics;
using SafeUpload.Agent.Service.Gate;
using SafeUpload.Agent.Service.Policies;

namespace SafeUpload.Agent.Tests;

public sealed class PolicyDiagnosticsTests
{
    private static Policy Policy(int version) => LocalPolicyStore.CreateDefault() with { Version = version };

    [Fact]
    public async Task Consulta_atual_nao_substitui_snapshot_e_diagnostico_nao_faz_IO()
    {
        using var workspace = new TestWorkspace();
        var handler = new Handler();
        using var http = Client(handler);
        var remote = new DurableHttpPolicyStore(http, "PRIVATE-HOST", workspace.PolicyFile, false);
        using var refresh = new RefreshingPolicyStore(remote, TimeSpan.FromHours(1), NullLogger<RefreshingPolicyStore>.Instance);
        var observed = new PolicyDiagnosticsStore(refresh, "LegacyRemote", remote);
        Assert.Null(observed.Read(new()).SnapshotRead.LastSuccess);
        Assert.Equal(0, handler.Calls);
        await refresh.RefreshAsync(default);
        Assert.Equal(7, (await observed.LoadAsync(default)).Version);
        handler.Version = 8;
        Assert.Equal(8, (await observed.LoadCurrentAsync(default)).Version);
        var state = observed.Read(new());
        Assert.Equal(7, state.SnapshotRead.LastSuccess!.Version);
        Assert.Equal(8, state.CurrentOriginRead.LastSuccess!.Version);
        Assert.Equal(8, state.Remote!.LastValidatedRemoteVersion);
        Assert.Equal(8, state.Remote.LastWrittenCacheVersion);
        Assert.Null(state.Remote.LastReadCacheVersion);
        int calls = handler.Calls;
        var before = await File.ReadAllBytesAsync(workspace.PolicyFile);
        for (int i = 0; i < 10; i++) Assert.Equal(state, observed.Read(new()));
        Assert.Equal(calls, handler.Calls);
        Assert.Equal(before, await File.ReadAllBytesAsync(workspace.PolicyFile));
        Assert.Equal(7, (await observed.LoadAsync(default)).Version);
        handler.Reject = true;
        await Assert.ThrowsAsync<HttpRequestException>(() => observed.LoadCurrentAsync(default));
        state = observed.Read(new());
        Assert.Equal("failure", state.CurrentOriginRead.State);
        Assert.Equal(8, state.CurrentOriginRead.LastSuccess!.Version);
        Assert.Equal("HttpRejected", state.CurrentOriginRead.LastFailureKind);
        string json = JsonSerializer.Serialize(state);
        Assert.DoesNotContain("PRIVATE", json);
        Assert.DoesNotContain(workspace.Root, json);
    }

    [Fact]
    public async Task Cache_escrito_lido_e_remoto_validado_sao_marcos_distintos()
    {
        using var workspace = new TestWorkspace();
        var handler = new Handler();
        using var http = Client(handler);
        var first = new DurableHttpPolicyStore(http, "PC", workspace.PolicyFile, false);
        await first.LoadAsync(default);
        handler.Reject = true;
        var offline = new DurableHttpPolicyStore(http, "PC", workspace.PolicyFile, false);
        Assert.Equal(7, (await offline.LoadCachedOrDefaultAsync(default)).Version);
        Assert.Equal(new RemotePolicyStatus(LastReadCacheVersion: 7), offline.ReadStatus());
        // The remote policy is valid, but the same-volume cache replacement cannot overwrite a directory.
        string blocked = Path.Combine(workspace.Root, "cache-is-directory");
        Directory.CreateDirectory(blocked);
        handler.Reject = false;
        handler.Version = 9;
        var unwritable = new DurableHttpPolicyStore(http, "PC", blocked, false);
        Assert.Equal(9, (await unwritable.LoadAsync(default)).Version);
        Assert.Equal(new RemotePolicyStatus(LastValidatedRemoteVersion: 9), unwritable.ReadStatus());
        handler.Invalid = true;
        Assert.Equal(9, (await unwritable.LoadAsync(default)).Version);
        Assert.Equal(new RemotePolicyStatus(LastValidatedRemoteVersion: 9), unwritable.ReadStatus());
    }

    [Fact]
    public async Task Mesma_versao_conteudo_distinto_e_cancelamento_nao_viram_sucesso_atual()
    {
        var inner = new Mutable { Snapshot = Policy(7), Current = Policy(7) with { AuditOnly = true } };
        var observed = new PolicyDiagnosticsStore(inner, "Local");
        Assert.Same(inner.Snapshot, await observed.LoadAsync(default));
        Assert.Same(inner.Current, await observed.LoadCurrentAsync(default));
        var before = observed.Read(new());
        Assert.NotEqual(before.SnapshotRead.LastSuccess!.ContentFingerprint,
            before.CurrentOriginRead.LastSuccess!.ContentFingerprint);
        using var cancel = new CancellationTokenSource();
        cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => observed.LoadCurrentAsync(cancel.Token));
        var after = observed.Read(new());
        Assert.Equal("cancelled", after.CurrentOriginRead.State);
        Assert.Equal(before.CurrentOriginRead.LastSuccess, after.CurrentOriginRead.LastSuccess);
        Assert.Equal(before.CurrentOriginRead.LastSuccessUtc, after.CurrentOriginRead.LastSuccessUtc);
        Assert.Null(after.Remote);
    }

    [Fact]
    public async Task Leitura_antiga_concluida_depois_nao_sobrepoe_mais_nova()
    {
        var inner = new Delayed();
        var observed = new PolicyDiagnosticsStore(inner, "Local");
        var old = observed.LoadAsync(default);
        Assert.Equal(9, (await observed.LoadAsync(default)).Version);
        inner.Old.SetResult(Policy(7));
        Assert.Equal(7, (await old).Version);
        Assert.Equal(9, observed.Read(new()).SnapshotRead.LastSuccess!.Version);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Pipe_policy_status_sem_driver_nao_carrega_origem_e_monitor_ausente_e_explicito(bool available)
    {
        var inner = new Mutable { Snapshot = Policy(7), Current = Policy(9) };
        var observed = new PolicyDiagnosticsStore(inner, "Local");
        using var gate = new GateClient(NullLogger<GateClient>.Instance);
        string pipeName = "SafeUpload.PolicyDiagnostics.Test." + Guid.NewGuid().ToString("N");
        using var server = new DiagnosticsPipeServer(gate, NullLogger<DiagnosticsPipeServer>.Instance,
            pipeName, policyDiagnostics: available ? observed : null);
        await server.StartAsync(default);
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await using var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            await client.ConnectAsync(timeout.Token);
            await client.WriteAsync(Encoding.UTF8.GetBytes("{\"query\":\"policy-status\"}\n"), timeout.Token);
            await client.FlushAsync(timeout.Token);
            using var reader = new StreamReader(client);
            var reply = JsonNode.Parse((await reader.ReadLineAsync(timeout.Token))!)!;
            Assert.Equal(available, reply["ok"]!.GetValue<bool>());
            if (available)
            {
                Assert.Equal("not_attempted", reply["data"]!["snapshotRead"]!["state"]!.GetValue<string>());
                Assert.Equal("not_attempted", reply["data"]!["gate"]!["lastApplyOutcome"]!.GetValue<string>());
            }
            Assert.Equal(0, inner.Calls);
            Assert.False(gate.IsConnected);
            Assert.Null(gate.ReadPolicyStatus().LastAcceptedScope);
        }
        finally { await server.StopAsync(default); }
    }

    [Fact]
    public void Escopo_recusado_antes_de_conectar_nao_produz_recibo_de_aplicacao()
    {
        using var gate = new GateClient(NullLogger<GateClient>.Instance);
        Assert.Throws<InvalidPolicyException>(() => gate.Apply(Enumerable.Repeat(@"C:\PRIVATE", 17).ToArray(), false, false));
        Assert.Equal("invalid_scope", gate.ReadPolicyStatus().LastApplyOutcome);
        Assert.False(gate.IsConnected);
        Assert.False(gate.ReadPolicyStatus().ConnectionHasAcceptedScope);
        Assert.Null(gate.ReadPolicyStatus().LastAcceptedScope);
    }

    private static HttpClient Client(Handler handler) => new(handler) { BaseAddress = new("https://PRIVATE.invalid/agent/") };
    private sealed class Handler : HttpMessageHandler
    {
        public int Calls, Version = 7;
        public bool Reject, Invalid;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            Calls++;
            return Task.FromResult(new HttpResponseMessage(Reject ? HttpStatusCode.Forbidden : HttpStatusCode.OK)
            { Content = new StringContent(Invalid ? "{}" : "{\"version\":" + Version + ",\"activeCategories\":[\"Cpf\"]}") });
        }
    }
    private sealed class Mutable : IPolicyStore
    {
        public required Policy Snapshot, Current;
        public int Calls;
        public Task<Policy> LoadAsync(CancellationToken token) { Calls++; token.ThrowIfCancellationRequested(); return Task.FromResult(Snapshot); }
        public Task<Policy> LoadCurrentAsync(CancellationToken token) { Calls++; token.ThrowIfCancellationRequested(); return Task.FromResult(Current); }
    }
    private sealed class Delayed : IPolicyStore
    {
        private int _calls;
        public TaskCompletionSource<Policy> Old { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task<Policy> LoadAsync(CancellationToken token) => ++_calls == 1 ? Old.Task : Task.FromResult(Policy(9));
    }
}
