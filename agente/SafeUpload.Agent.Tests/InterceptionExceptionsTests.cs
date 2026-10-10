using SafeUpload.Agent.Network.Bypass;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// As exceções de interceptação (Fase 4): que hosts passam por túnel, e o
/// aprendizado automático de programas com pinning.
/// </summary>
public sealed class InterceptionExceptionsTests
{
    private static InterceptionExceptions Exceptions(params string[] domains) =>
        new([new("teste", domains)]);

    [Theory]
    [InlineData("bb.com.br")]
    [InlineData("www2.bb.com.br")]
    [InlineData("a.b.c.bb.com.br")]
    [InlineData("WWW.BB.COM.BR")]
    [InlineData("bb.com.br.")]
    public void Dominio_e_subdominios_casam(string host)
    {
        Assert.Equal("teste", Exceptions("bb.com.br").Match(host));
    }

    /// <summary>
    /// O limite do rótulo: um domínio que só termina com as mesmas letras não
    /// é subdomínio, e não ganha túnel.
    /// </summary>
    [Theory]
    [InlineData("fakebb.com.br")]
    [InlineData("com.br")]
    [InlineData("bb.com.br.evil.example")]
    [InlineData("bb.com")]
    public void Dominio_parecido_nao_casa(string host)
    {
        Assert.Null(Exceptions("bb.com.br").Match(host));
    }

    [Theory]
    [InlineData("*.exemplo.com.br")]
    [InlineData(".exemplo.com.br")]
    [InlineData("  Exemplo.COM.br  ")]
    public void Entrada_e_normalizada(string entry)
    {
        Assert.Equal("teste", Exceptions(entry).Match("portal.exemplo.com.br"));
    }

    [Fact]
    public void Entrada_que_nao_e_dominio_e_descartada_e_relatada()
    {
        InterceptionExceptions exceptions = Exceptions("https://exemplo.com.br/login", "10.0.0.1", " ", "valido.com.br");

        Assert.Equal(1, exceptions.Count);
        Assert.Equal(3, exceptions.Ignored.Count);
        Assert.Null(exceptions.Match("exemplo.com.br"));
    }

    [Fact]
    public void Endereco_IP_nunca_casa()
    {
        Assert.Null(Exceptions("0.1").Match("10.0.0.1"));
    }

    [Fact]
    public void Dominio_com_acento_casa_com_a_forma_punycode()
    {
        Assert.Equal("teste", Exceptions("saúde.example").Match("www.xn--sade-rra.example"));
    }

    [Fact]
    public void Sem_excecoes_nada_casa()
    {
        Assert.Null(InterceptionExceptions.None.Match("bb.com.br"));
    }

    [Theory]
    [InlineData("internetbanking.caixa.gov.br", DefaultExceptionLists.Government)]
    [InlineData("www.tjsp.jus.br", DefaultExceptionLists.Government)]
    [InlineData("www.itau.com.br", DefaultExceptionLists.Banks)]
    [InlineData("banco.bradesco", DefaultExceptionLists.Banks)]
    [InlineData("www.unimed.coop.br", DefaultExceptionLists.Health)]
    public void Listas_iniciais_cobrem_bancos_saude_e_governo(string host, string category)
    {
        var exceptions = new InterceptionExceptions(
            DefaultExceptionLists.Categories.Select(pair => new KeyValuePair<string, IEnumerable<string>>(pair.Key, pair.Value)));

        Assert.Equal(category, exceptions.Match(host));
        Assert.Empty(exceptions.Ignored);
        Assert.Null(exceptions.Match("drive.google.com"));
    }

    [Fact]
    public void Pinning_e_aprendido_depois_de_recusas_seguidas()
    {
        var detector = new PinningDetector();

        Assert.False(detector.RecordRejection(@"C:\app\cliente.exe", "api.example"));
        Assert.False(detector.IsPinned(@"C:\app\cliente.exe", "api.example"));

        Assert.True(detector.RecordRejection(@"C:\app\cliente.exe", "api.example"));
        Assert.True(detector.IsPinned(@"C:\app\cliente.exe", "api.example"));
    }

    /// <summary>
    /// A recusa de um programa não tira o site da inspeção para os outros.
    /// </summary>
    [Fact]
    public void Pinning_vale_so_para_o_programa_e_o_host_que_recusaram()
    {
        var detector = new PinningDetector();
        detector.RecordRejection(@"C:\app\cliente.exe", "api.example");
        detector.RecordRejection(@"C:\app\cliente.exe", "api.example");

        Assert.False(detector.IsPinned(@"C:\Program Files\Edge\msedge.exe", "api.example"));
        Assert.False(detector.IsPinned(@"C:\app\cliente.exe", "outro.example"));
    }

    [Fact]
    public void Handshake_concluido_zera_a_contagem()
    {
        var detector = new PinningDetector();

        detector.RecordRejection("app.exe", "site.example");
        detector.RecordSuccess("app.exe", "site.example");

        Assert.False(detector.RecordRejection("app.exe", "site.example"));
        Assert.False(detector.IsPinned("app.exe", "site.example"));
    }

    [Fact]
    public void Recusas_distantes_no_tempo_nao_se_somam()
    {
        var clock = new RelogioControlado(DateTimeOffset.UnixEpoch);
        var detector = new PinningDetector(clock);

        detector.RecordRejection("app.exe", "site.example");
        clock.Avancar(detector.Window + TimeSpan.FromSeconds(1));

        Assert.False(detector.RecordRejection("app.exe", "site.example"));
    }

    [Fact]
    public void O_aprendido_expira_e_o_par_volta_a_ser_interceptado()
    {
        var clock = new RelogioControlado(DateTimeOffset.UnixEpoch);
        var detector = new PinningDetector(clock);
        detector.RecordRejection("app.exe", "site.example");
        detector.RecordRejection("app.exe", "site.example");

        clock.Avancar(detector.Lifetime + TimeSpan.FromSeconds(1));

        Assert.False(detector.IsPinned("app.exe", "site.example"));
    }

    [Fact]
    public void Programa_desconhecido_nunca_e_aprendido()
    {
        var detector = new PinningDetector();

        Assert.False(detector.RecordRejection(null, "site.example"));
        Assert.False(detector.RecordRejection(null, "site.example"));
        Assert.False(detector.IsPinned(null, "site.example"));
    }

    /// <summary>Relógio de teste, avançado à mão.</summary>
    private sealed class RelogioControlado(DateTimeOffset inicio) : TimeProvider
    {
        private DateTimeOffset _agora = inicio;

        public void Avancar(TimeSpan intervalo) => _agora += intervalo;

        public override DateTimeOffset GetUtcNow() => _agora;
    }
}
