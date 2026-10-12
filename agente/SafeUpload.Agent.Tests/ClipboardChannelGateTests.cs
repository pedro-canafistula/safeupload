using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// A porta do aplicativo: o texto copiado só vai ao serviço quando se sabe que
/// o canal está ligado.
/// </summary>
public class ClipboardChannelGateTests
{
    private static ClipboardResponse Estado(bool? ligado) =>
        new(ClipboardProtocol.StateType, Enabled: ligado);

    private static ClipboardResponse Classificacao(bool? ligado) =>
        new(ClipboardProtocol.ClassifyType, CopyId: "c1", Enabled: ligado);

    [Fact]
    public void No_inicio_pergunta_antes_de_mandar_texto()
    {
        Assert.True(new ClipboardChannelGate().MustAskFirst);
    }

    [Fact]
    public void Canal_ligado_libera_o_texto_e_dispensa_a_pergunta_seguinte()
    {
        var porta = new ClipboardChannelGate();

        Assert.True(porta.OnStateResponse(Estado(true)));
        Assert.False(porta.MustAskFirst);
    }

    [Fact]
    public void Canal_desligado_segura_o_texto_e_continua_perguntando()
    {
        var porta = new ClipboardChannelGate();

        Assert.False(porta.OnStateResponse(Estado(false)));
        Assert.True(porta.MustAskFirst);
    }

    [Fact]
    public void Sem_resposta_a_pergunta_o_texto_nao_vai()
    {
        var porta = new ClipboardChannelGate();

        Assert.False(porta.OnStateResponse(null));
        Assert.True(porta.MustAskFirst);
    }

    [Fact]
    public void Resposta_de_outro_tipo_nao_vale_como_estado()
    {
        var porta = new ClipboardChannelGate();

        Assert.False(porta.OnStateResponse(Classificacao(true)));
    }

    [Fact]
    public void Classificacao_dizendo_desligado_volta_a_perguntar()
    {
        var porta = new ClipboardChannelGate();
        porta.OnStateResponse(Estado(true));

        porta.OnClassifyResponse(Classificacao(false));

        Assert.True(porta.MustAskFirst);
    }

    [Fact]
    public void Servico_antigo_sem_o_campo_conta_como_ligado()
    {
        var porta = new ClipboardChannelGate();
        porta.OnStateResponse(Estado(true));

        porta.OnClassifyResponse(Classificacao(null));

        Assert.False(porta.MustAskFirst);
    }

    [Fact]
    public void Classificacao_sem_resposta_nao_muda_o_que_se_sabia()
    {
        var porta = new ClipboardChannelGate();
        porta.OnStateResponse(Estado(true));

        porta.OnClassifyResponse(null);

        Assert.False(porta.MustAskFirst);
    }
}
