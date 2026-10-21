using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// O cache de política que fica na frente do <see cref="IPolicyStore"/>: guarda
/// a política pelo intervalo, não guarda falha e faz uma carga por vez.
/// </summary>
public class CachedPolicyStoreTests
{
    private static readonly TimeSpan Intervalo = TimeSpan.FromSeconds(30);

    private static Policy Politica(int versao) =>
        new(
            Version: versao,
            ActiveCategories: new HashSet<Category> { Category.Cpf },
            MonitoredScopes: new MonitoredScopes(
                new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".txt" },
                [],
                RemovableDrives: true,
                NetworkPaths: true),
            MaxFileSizeMb: 20,
            InspectionTimeoutSeconds: 5,
            FailOpen: true,
            ExcludedProcesses: new HashSet<string>(StringComparer.OrdinalIgnoreCase));

    /// <summary>Relógio que só anda quando o teste manda.</summary>
    private sealed class Relogio : TimeProvider
    {
        public DateTimeOffset Agora { get; set; } = new(2026, 10, 12, 12, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => Agora;
    }

    /// <summary>Loja que conta as cargas e devolve uma versão nova a cada uma.</summary>
    private sealed class LojaContada : IPolicyStore
    {
        private int _cargas;

        public int Cargas => Volatile.Read(ref _cargas);

        public Func<int, Task<Policy>>? Comportamento { get; set; }

        public TimeSpan Demora { get; set; } = TimeSpan.Zero;

        public Task<Policy> LoadCurrentAsync(CancellationToken cancellationToken) => LoadAsync(cancellationToken);

        public async Task<Policy> LoadAsync(CancellationToken cancellationToken)
        {
            int n = Interlocked.Increment(ref _cargas);

            if (Demora > TimeSpan.Zero)
            {
                await Task.Delay(Demora, cancellationToken);
            }

            return Comportamento is null ? Politica(n) : await Comportamento(n);
        }
    }

    [Fact]
    public async Task Dentro_do_intervalo_devolve_a_mesma_politica_sem_carregar_de_novo()
    {
        var loja = new LojaContada();
        var relogio = new Relogio();
        var cache = new CachedPolicyStore(loja, Intervalo, relogio);

        var primeira = await cache.LoadAsync(CancellationToken.None);
        relogio.Agora += TimeSpan.FromSeconds(29);
        var segunda = await cache.LoadAsync(CancellationToken.None);

        Assert.Same(primeira, segunda);
        Assert.Equal(1, loja.Cargas);
    }

    [Fact]
    public async Task Vencido_o_intervalo_carrega_de_novo()
    {
        var loja = new LojaContada();
        var relogio = new Relogio();
        var cache = new CachedPolicyStore(loja, Intervalo, relogio);

        await cache.LoadAsync(CancellationToken.None);
        relogio.Agora += Intervalo;
        var depois = await cache.LoadAsync(CancellationToken.None);

        Assert.Equal(2, loja.Cargas);
        Assert.Equal(2, depois.Version);
    }

    [Fact]
    public async Task Falha_nao_fica_guardada_e_a_proxima_carga_tenta_de_novo()
    {
        var loja = new LojaContada
        {
            Comportamento = n => n == 1
                ? throw new InvalidPolicyException("primeira carga falha")
                : Task.FromResult(Politica(n))
        };
        var cache = new CachedPolicyStore(loja, Intervalo, new Relogio());

        await Assert.ThrowsAsync<InvalidPolicyException>(() => cache.LoadAsync(CancellationToken.None));
        var depois = await cache.LoadAsync(CancellationToken.None);

        Assert.Equal(2, loja.Cargas);
        Assert.Equal(2, depois.Version);
    }

    [Fact]
    public async Task Pedidos_simultaneos_com_o_cache_vazio_fazem_uma_carga_so()
    {
        var loja = new LojaContada { Demora = TimeSpan.FromMilliseconds(150) };
        var cache = new CachedPolicyStore(loja, Intervalo, new Relogio());

        var pedidos = Enumerable.Range(0, 20).Select(_ => cache.LoadAsync(CancellationToken.None)).ToArray();
        var politicas = await Task.WhenAll(pedidos);

        Assert.Equal(1, loja.Cargas);
        Assert.All(politicas, p => Assert.Same(politicas[0], p));
    }

    [Fact]
    public void Intervalo_precisa_ser_positivo()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new CachedPolicyStore(new LojaContada(), TimeSpan.Zero));
    }
}
