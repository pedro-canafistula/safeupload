using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// O formato do pipe <c>SafeUpload.Agent.Clipboard</c>. A regra geral: linha
/// que não serve vira <c>null</c>, nunca exceção, e o App trata null como
/// "cola normalmente" (RN-013).
/// </summary>
public class ClipboardProtocolTests
{
    [Fact]
    public void Pedido_de_classificacao_vai_e_volta_com_acentos()
    {
        var pedido = ClipboardRequest.Classify("Cliente José, CPF 529.982.247-25", "EXCEL.EXE");

        var lido = ClipboardProtocol.DeserializeRequest(ClipboardProtocol.Serialize(pedido));

        Assert.Equal(pedido, lido);
        Assert.Equal(ClipboardProtocol.ClassifyType, lido!.Type);
    }

    [Fact]
    public void Pedido_de_colagem_vai_e_volta_sem_texto()
    {
        var pedido = ClipboardRequest.Paste(Guid.NewGuid().ToString("N"), "chrome.exe");

        var linha = ClipboardProtocol.Serialize(pedido);
        var lido = ClipboardProtocol.DeserializeRequest(linha);

        Assert.Equal(pedido, lido);
        Assert.DoesNotContain("\"text\"", linha, StringComparison.Ordinal);
    }

    /// <summary>
    /// Texto maior que o teto do protocolo é cortado, mas o tamanho real viaja
    /// junto: é ele que faz o serviço aplicar a regra de texto grande demais.
    /// </summary>
    [Fact]
    public void Texto_acima_do_teto_e_cortado_e_leva_o_tamanho_real()
    {
        var texto = new string('x', ClipboardProtocol.MaxTextChars + 10);

        var pedido = ClipboardRequest.Classify(texto, "notepad");

        Assert.Equal(ClipboardProtocol.MaxTextChars, pedido.Text!.Length);
        Assert.Equal(texto.Length, pedido.TextLength);
        Assert.NotNull(ClipboardProtocol.DeserializeRequest(ClipboardProtocol.Serialize(pedido)));
    }

    /// <summary>
    /// Um texto cheio de aspas e quebras é o pior caso de escape no JSON e
    /// ainda tem de caber numa linha.
    /// </summary>
    [Fact]
    public void Pior_caso_de_escape_cabe_na_linha()
    {
        var pedido = ClipboardRequest.Classify(new string('\u0001', ClipboardProtocol.MaxTextChars), "notepad");

        var linha = ClipboardProtocol.Serialize(pedido);

        Assert.True(linha.Length <= ClipboardProtocol.MaxLineLength, $"linha com {linha.Length} caracteres");
        Assert.NotNull(ClipboardProtocol.DeserializeRequest(linha));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("não é json")]
    [InlineData("{}")]
    [InlineData("""{ "type": "outro" }""")]
    [InlineData("""{ "type": "classify" }""")]
    [InlineData("""{ "type": "classify", "text": "abc", "textLength": 1 }""")]
    [InlineData("""{ "type": "paste" }""")]
    [InlineData("""{ "type": "paste", "copyId": "   " }""")]
    public void Pedido_que_nao_serve_vira_null(string? linha)
    {
        Assert.Null(ClipboardProtocol.DeserializeRequest(linha));
    }

    [Fact]
    public void Linha_acima_do_teto_vira_null_sem_ser_interpretada()
    {
        var linha = new string(' ', ClipboardProtocol.MaxLineLength + 1);

        Assert.Null(ClipboardProtocol.DeserializeRequest(linha));
        Assert.Null(ClipboardProtocol.DeserializeResponse(linha));
    }

    [Fact]
    public void Nome_de_processo_absurdo_vira_null()
    {
        var pedido = ClipboardRequest.Paste("abc", new string('p', ClipboardProtocol.MaxProcessNameLength + 1));

        Assert.Null(ClipboardProtocol.DeserializeRequest(ClipboardProtocol.Serialize(pedido)));
    }

    [Fact]
    public void Resposta_de_classificacao_vai_e_volta_com_categorias_por_nome()
    {
        var resposta = new ClipboardResponse(
            ClipboardProtocol.ClassifyType,
            CopyId: "c1",
            Dirty: true,
            Categories: [Category.Cpf, Category.Secret],
            Findings: ["•••••••••25"]);

        var linha = ClipboardProtocol.Serialize(resposta);
        var lida = ClipboardProtocol.DeserializeResponse(linha);

        Assert.NotNull(lida);
        Assert.True(lida.Dirty);
        Assert.Equal("c1", lida.CopyId);
        Assert.Equal(new[] { Category.Cpf, Category.Secret }, lida.Categories);
        Assert.Equal(new[] { "•••••••••25" }, lida.Findings);
        Assert.Contains("\"Cpf\"", linha, StringComparison.Ordinal);
    }

    [Fact]
    public void Resposta_de_colagem_vai_e_volta_com_o_veredito_por_nome()
    {
        var resposta = new ClipboardResponse(
            ClipboardProtocol.PasteType,
            Verdict: ClipboardPasteVerdict.Block,
            EventId: Guid.NewGuid().ToString());

        var linha = ClipboardProtocol.Serialize(resposta);
        var lida = ClipboardProtocol.DeserializeResponse(linha);

        Assert.Equal(ClipboardPasteVerdict.Block, lida!.Verdict);
        Assert.Equal(resposta.EventId, lida.EventId);
        Assert.Contains("\"Block\"", linha, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("lixo")]
    [InlineData("""{ "type": "outro", "verdict": "Block" }""")]
    [InlineData("""{ "type": "paste", "verdict": "Explodir" }""")]
    public void Resposta_que_nao_serve_vira_null(string? linha)
    {
        Assert.Null(ClipboardProtocol.DeserializeResponse(linha));
    }
}
