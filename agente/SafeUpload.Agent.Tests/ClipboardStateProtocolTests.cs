using SafeUpload.Agent.Core.Contracts;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// A pergunta "o canal está ligado?" no protocolo, e o campo de estado nas
/// respostas.
/// </summary>
public class ClipboardStateProtocolTests
{
    [Fact]
    public void Pergunta_de_estado_vai_e_volta_sem_texto()
    {
        var linha = ClipboardProtocol.Serialize(ClipboardRequest.State());
        var lido = ClipboardProtocol.DeserializeRequest(linha);

        Assert.NotNull(lido);
        Assert.Equal(ClipboardProtocol.StateType, lido.Type);
        Assert.Null(lido.Text);
        Assert.DoesNotContain("\"text\"", linha, StringComparison.Ordinal);
    }

    [Fact]
    public void Resposta_de_estado_vai_e_volta()
    {
        var linha = ClipboardProtocol.Serialize(new ClipboardResponse(ClipboardProtocol.StateType, Enabled: false));
        var lida = ClipboardProtocol.DeserializeResponse(linha);

        Assert.NotNull(lida);
        Assert.Equal(ClipboardProtocol.StateType, lida.Type);
        Assert.False(lida.Enabled);
    }

    [Fact]
    public void Campo_de_estado_nulo_fica_fora_da_linha()
    {
        // Resposta de um serviço que não sabe do campo: o aplicativo a lê como antes.
        var linha = ClipboardProtocol.Serialize(new ClipboardResponse(ClipboardProtocol.ClassifyType, CopyId: "c1"));

        Assert.DoesNotContain("enabled", linha, StringComparison.Ordinal);
        Assert.Null(ClipboardProtocol.DeserializeResponse(linha)!.Enabled);
    }

    [Fact]
    public void Colagem_de_verdade_vai_e_volta_com_o_campo_attempt()
    {
        var linha = ClipboardProtocol.Serialize(ClipboardRequest.PasteAttempt("c1", "chrome"));
        var lido = ClipboardProtocol.DeserializeRequest(linha);

        Assert.Contains("\"attempt\":true", linha, StringComparison.Ordinal);
        Assert.NotNull(lido);
        Assert.True(lido.IsPasteAttempt);
        Assert.Equal("chrome", lido.DestinationProcess);
    }

    [Fact]
    public void Sonda_de_foco_nao_leva_o_campo_e_nao_e_colagem()
    {
        var linha = ClipboardProtocol.Serialize(ClipboardRequest.Paste("c1", "chrome"));

        Assert.DoesNotContain("attempt", linha, StringComparison.Ordinal);
        Assert.False(ClipboardProtocol.DeserializeRequest(linha)!.IsPasteAttempt);
        // Pedido de um aplicativo antigo, sem o campo: continua sendo sonda.
        Assert.False(ClipboardProtocol.DeserializeRequest("{\"type\":\"paste\",\"copyId\":\"c1\",\"destinationProcess\":\"chrome\"}")!.IsPasteAttempt);
    }

    [Fact]
    public void Resposta_antiga_sem_o_campo_continua_sendo_lida()
    {
        var lida = ClipboardProtocol.DeserializeResponse("{\"type\":\"classify\",\"copyId\":\"c1\",\"dirty\":true}");

        Assert.NotNull(lida);
        Assert.True(lida.Dirty);
        Assert.Null(lida.Enabled);
    }
}
