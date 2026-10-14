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
    public void Resposta_antiga_sem_o_campo_continua_sendo_lida()
    {
        var lida = ClipboardProtocol.DeserializeResponse("{\"type\":\"classify\",\"copyId\":\"c1\",\"dirty\":true}");

        Assert.NotNull(lida);
        Assert.True(lida.Dirty);
        Assert.Null(lida.Enabled);
    }
}
