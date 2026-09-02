using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// O cache de vereditos, isolado do motor. O relógio é injetado para que a
/// validade possa ser exercitada sem o teste esperar um minuto de verdade.
/// </summary>
public class VerdictCacheTests
{
    private static readonly FileOperation Operacao = new(
        @"C:\dados\cadastro.txt",
        "cadastro.txt",
        ".txt",
        1024,
        new DateTimeOffset(2026, 1, 15, 10, 0, 0, TimeSpan.Zero),
        "explorer.exe",
        4242,
        @"E:\pendrive",
        DestinationKind.RemovableDrive);

    private static readonly InspectionResult Bloqueado = new(
        Verdict.Blocked,
        [new Finding(Category.Cpf, "•••••••••25")],
        Reason: null,
        ElapsedMs: 12,
        FromCache: false,
        PolicyVersion: 1,
        InScope: true);

    [Fact]
    public void Validade_padrao_e_de_sessenta_segundos() =>
        Assert.Equal(TimeSpan.FromSeconds(60), VerdictCache.DefaultTimeToLive);

    [Fact]
    public void Entrada_gravada_e_encontrada()
    {
        var cache = new VerdictCache();
        cache.Set(Operacao, Bloqueado);

        Assert.True(cache.TryGet(Operacao, policyVersion: 1, out var encontrado));
        Assert.Equal(Verdict.Blocked, encontrado!.Verdict);
    }

    [Fact]
    public void Cache_vazio_nao_encontra_nada() =>
        Assert.False(new VerdictCache().TryGet(Operacao, policyVersion: 1, out _));

    [Fact]
    public void Entrada_expira_ao_fim_da_validade()
    {
        var relogio = new RelogioControlado(new DateTimeOffset(2026, 1, 15, 10, 0, 0, TimeSpan.Zero));
        var cache = new VerdictCache(TimeSpan.FromSeconds(60), relogio);

        cache.Set(Operacao, Bloqueado);

        relogio.Avancar(TimeSpan.FromSeconds(59));
        Assert.True(cache.TryGet(Operacao, policyVersion: 1, out _));

        relogio.Avancar(TimeSpan.FromSeconds(2));
        Assert.False(cache.TryGet(Operacao, policyVersion: 1, out _));
    }

    /// <summary>
    /// Cada componente da chave precisa ser suficiente para separar entradas.
    /// Tamanho e data de modificação são os que impedem o erro perigoso: o
    /// arquivo editado para incluir um CPF não reaproveita o veredito anterior.
    /// </summary>
    [Fact]
    public void Cada_componente_da_chave_separa_entradas()
    {
        var cache = new VerdictCache();
        cache.Set(Operacao, Bloqueado);

        Assert.False(cache.TryGet(Operacao with { FilePath = @"C:\outro\cadastro.txt" }, 1, out _));
        Assert.False(cache.TryGet(Operacao with { SizeBytes = 2048 }, 1, out _));
        Assert.False(cache.TryGet(Operacao with { LastWriteUtc = Operacao.LastWriteUtc.AddSeconds(1) }, 1, out _));
        Assert.False(cache.TryGet(Operacao with { ProcessName = "winword.exe" }, 1, out _));

        // O destino não faz parte da chave: quem decide se ele importa é a
        // política, antes de o cache ser consultado.
        Assert.True(cache.TryGet(Operacao with { DestinationPath = @"F:\outro" }, 1, out _));
    }

    /// <summary>
    /// Entrada gravada sob outra versão de política conta como ausente, para
    /// que uma mudança no painel valha na hora e não daqui a um minuto.
    /// </summary>
    [Fact]
    public void Entrada_de_outra_versao_de_politica_e_ignorada()
    {
        var cache = new VerdictCache();
        cache.Set(Operacao, Bloqueado);

        Assert.False(cache.TryGet(Operacao, policyVersion: 2, out _));
        Assert.False(cache.TryGet(Operacao, policyVersion: 1, out _));
    }

    [Fact]
    public void Limpar_esvazia_o_cache()
    {
        var cache = new VerdictCache();
        cache.Set(Operacao, Bloqueado);
        cache.Clear();

        Assert.False(cache.TryGet(Operacao, policyVersion: 1, out _));
    }

    [Fact]
    public void Validade_nao_positiva_e_rejeitada() =>
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new VerdictCache(TimeSpan.Zero, TimeProvider.System));

    /// <summary>Relógio de teste, avançado à mão.</summary>
    private sealed class RelogioControlado(DateTimeOffset inicio) : TimeProvider
    {
        private DateTimeOffset _agora = inicio;

        public void Avancar(TimeSpan intervalo) => _agora += intervalo;

        public override DateTimeOffset GetUtcNow() => _agora;
    }
}
