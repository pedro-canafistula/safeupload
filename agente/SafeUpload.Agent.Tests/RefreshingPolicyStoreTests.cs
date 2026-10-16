using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Policies;

namespace SafeUpload.Agent.Tests;

public sealed class RefreshingPolicyStoreTests
{
    private static Policy Policy(int version) => LocalPolicyStore.CreateDefault() with { Version = version };

    [Fact]
    public async Task Inicializacao_carrega_disco_uma_vez_sem_consultar_rede()
    {
        var reads = 0;
        var remote = new ControlledRemote();
        using var store = new RefreshingPolicyStore(remote,
            _ => { Interlocked.Increment(ref reads); return Task.FromResult(Policy(7)); },
            TimeSpan.FromSeconds(30), NullLogger<RefreshingPolicyStore>.Instance);
        var loaded = await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => store.LoadAsync(CancellationToken.None)));
        Assert.All(loaded, policy => Assert.Equal(7, policy.Version));
        Assert.Equal(1, reads);
        Assert.Equal(0, remote.Calls);
    }

    [Fact]
    public async Task Inspecoes_nao_esperam_atualizacao_remota_e_recebem_novo_snapshot_depois()
    {
        var remote = new ControlledRemote();
        using var store = Store(remote);
        var refresh = store.RefreshAsync(CancellationToken.None);
        await remote.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.False(refresh.IsCompleted);
        for (var i = 0; i < 100; i++)
        {
            var read = store.LoadAsync(CancellationToken.None);
            Assert.True(read.IsCompletedSuccessfully); // Não depende de medir milissegundos.
            Assert.Equal(7, (await read).Version);
        }
        remote.Result.SetResult(Policy(9));
        await refresh;
        Assert.Equal(9, (await store.LoadAsync(CancellationToken.None)).Version);
        Assert.Equal(1, remote.Calls);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Falha_ou_politica_invalida_nao_substitui_snapshot(bool networkFailure)
    {
        var remote = new ControlledRemote();
        using var store = Store(remote);
        if (networkFailure) remote.Result.SetException(new HttpRequestException("offline"));
        else remote.Result.SetResult(Policy(9) with { MaxFileSizeMb = 0 });
        await Assert.ThrowsAnyAsync<Exception>(() => store.RefreshAsync(CancellationToken.None));
        Assert.Equal(7, (await store.LoadAsync(CancellationToken.None)).Version);
    }

    [Fact]
    public async Task Cancelamento_de_uma_inspecao_nao_cancela_atualizacao_compartilhada()
    {
        var remote = new ControlledRemote();
        using var store = Store(remote);
        var refresh = store.RefreshAsync(CancellationToken.None);
        await remote.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.LoadAsync(cancelled.Token));
        Assert.False(refresh.IsCompleted);
        remote.Result.SetResult(Policy(9));
        await refresh;
        Assert.Equal(9, (await store.LoadAsync(CancellationToken.None)).Version);
    }

    [Fact]
    public async Task Parada_do_servico_cancela_rede_pendente_e_preserva_snapshot()
    {
        var remote = new ControlledRemote();
        using var store = Store(remote);
        await store.StartAsync(CancellationToken.None);
        await remote.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await store.StopAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(remote.Cancelled);
        Assert.Equal(7, (await store.LoadAsync(CancellationToken.None)).Version);
    }

    private static RefreshingPolicyStore Store(ControlledRemote remote) => new(remote,
        _ => Task.FromResult(Policy(7)), TimeSpan.FromHours(1), NullLogger<RefreshingPolicyStore>.Instance);

    private sealed class ControlledRemote : IPolicyStore
    {
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<Policy> Result { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int Calls;
        public bool Cancelled;
        public async Task<Policy> LoadAsync(CancellationToken token)
        {
            Interlocked.Increment(ref Calls);
            Started.TrySetResult();
            try { return await Result.Task.WaitAsync(token); }
            catch (OperationCanceledException) { Cancelled = true; throw; }
        }
    }
}
