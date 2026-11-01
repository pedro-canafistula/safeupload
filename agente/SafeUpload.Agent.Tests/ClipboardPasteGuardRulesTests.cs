using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// As regras do proxy da colagem (Fase 3). Cada caso é um comportamento medido
/// na Fase 2 (<c>docs/clipboard/FASE-2-TESTES.md</c>).
/// </summary>
public class ClipboardPasteGuardRulesTests
{
    private const string Agente = "SafeUpload.Agent.App";

    [Theory]
    [InlineData(null, "chrome", "chrome")]          // Chrome, Edge: quem lê aparece como ninguém
    [InlineData(null, "ms-teams", "ms-teams")]      // Teams (WebView2)
    [InlineData(null, "WhatsApp.Root", "WhatsApp.Root")]
    [InlineData("", "msedge", "msedge")]
    [InlineData("WINWORD", "explorer", "WINWORD")]  // quem lê aponta outro processo: vale ele
    [InlineData("WINWORD.exe", "explorer", "WINWORD")]
    public void Colagem_decide_pelo_destino_e_reinstala(string? leitor, string primeiroPlano, string destino)
    {
        var decisao = ClipboardPasteGuardRules.DecideRead(leitor, primeiroPlano, Agente);

        Assert.Equal(ClipboardReadAction.AskForDestination, decisao.Action);
        Assert.Equal(destino, decisao.Destination);
        Assert.True(decisao.ReinstallAfter);
    }

    [Theory]
    [InlineData("SafeUpload.Agent.App")]
    [InlineData("safeupload.agent.app.exe")]
    public void Leitura_do_proprio_agente_entrega_o_original_sem_reinstalar(string leitor)
    {
        // O OLE lê descritores pelo proxy a cada instalação; reinstalar por isso
        // foi o laço de 41 reinstalações em 6 s da Fase 2.
        var decisao = ClipboardPasteGuardRules.DecideRead(leitor, "chrome", Agente);

        Assert.Equal(ClipboardReadAction.DeliverOriginal, decisao.Action);
        Assert.False(decisao.ReinstallAfter);
    }

    [Theory]
    [InlineData("chrome")]
    [InlineData("claude")]
    public void Historico_do_windows_e_negado_sem_reinstalar_qualquer_que_seja_a_janela(string primeiroPlano)
    {
        // Entregar ao svchost fez o Teams colar o original sem consultar o proxy;
        // reinstalar por causa dele foi o laço de 40 reinstalações.
        var decisao = ClipboardPasteGuardRules.DecideRead("svchost", primeiroPlano, Agente);

        Assert.Equal(ClipboardReadAction.Deny, decisao.Action);
        Assert.False(decisao.ReinstallAfter);
    }

    [Fact]
    public void Sem_leitor_e_sem_janela_a_colagem_vai_com_destino_desconhecido()
    {
        // O serviço decide; destino desconhecido não é saída, e libera (RN-013).
        var decisao = ClipboardPasteGuardRules.DecideRead(null, null, Agente);

        Assert.Equal(ClipboardReadAction.AskForDestination, decisao.Action);
        Assert.Null(decisao.Destination);
    }

    [Fact]
    public void Destino_desconhecido_nao_e_bloqueado_pela_politica()
    {
        var politica = new ClipboardPolicy(
            ClipboardMode.Block,
            new HashSet<string>(["chrome"], StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            1000,
            true);

        Assert.Equal(ClipboardPasteVerdict.Allow, ClipboardRules.DecidePaste(true, "EXCEL", null, politica));
    }

    // ------------------------------------------------------------- memória

    private sealed class Relogio : TimeProvider
    {
        public DateTimeOffset Agora { get; set; } = new(2026, 10, 20, 12, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => Agora;
    }

    [Fact]
    public void Pedidos_da_mesma_colagem_reusam_a_decisao()
    {
        var relogio = new Relogio();
        var memo = new ClipboardPasteMemo(relogio);

        memo.Remember("c1", "chrome", ClipboardPasteVerdict.Block);
        relogio.Agora += TimeSpan.FromMilliseconds(30);

        Assert.Equal(ClipboardPasteVerdict.Block, memo.TryGet("c1", "CHROME"));
    }

    [Fact]
    public void Outra_copia_outro_destino_ou_depois_da_janela_pergunta_de_novo()
    {
        var relogio = new Relogio();
        var memo = new ClipboardPasteMemo(relogio);
        memo.Remember("c1", "chrome", ClipboardPasteVerdict.Block);

        Assert.Null(memo.TryGet("c2", "chrome"));
        Assert.Null(memo.TryGet("c1", "WINWORD"));

        relogio.Agora += ClipboardPasteMemo.Window + TimeSpan.FromMilliseconds(1);
        Assert.Null(memo.TryGet("c1", "chrome"));
    }

    [Fact]
    public void Esquecer_apaga_a_decisao()
    {
        var memo = new ClipboardPasteMemo(new Relogio());
        memo.Remember("c1", "chrome", ClipboardPasteVerdict.AuditOnly);

        memo.Clear();

        Assert.Null(memo.TryGet("c1", "chrome"));
    }
}
