using SafeUpload.Agent.Core.Domain.Validators;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// RN-001 a RN-004 — os validadores, isolados de qualquer varredura.
/// Os vetores marcados como "vetor do projeto" são os que a especificação
/// exige; os demais cobrem os modos de falha que a regra descreve.
/// </summary>
public class ValidatorTests
{
    [Theory]
    // Vetores do projeto (RN-001).
    [InlineData("52998224725", true)]
    [InlineData("11144477735", true)]
    [InlineData("52998224724", false)]
    [InlineData("11111111111", false)]
    // Sequências repetidas: várias satisfazem o cálculo e precisam cair antes dele.
    [InlineData("00000000000", false)]
    [InlineData("99999999999", false)]
    // Comprimento errado.
    [InlineData("5299822472", false)]
    [InlineData("529982247250", false)]
    [InlineData("", false)]
    // Segundo dígito verificador errado, primeiro certo.
    [InlineData("52998224720", false)]
    public void Cpf_segue_a_RN001(string digits, bool expected) =>
        Assert.Equal(expected, CpfValidator.IsValid(digits));

    [Theory]
    // Vetor do projeto (RN-002).
    [InlineData("11222333000181", true)]
    // Dígito verificador alterado.
    [InlineData("11222333000182", false)]
    [InlineData("11222333000191", false)]
    // Repetição: 00000000000000 passa nos dois dígitos verificadores, por isso
    // a rejeição de sequências repetidas também vale para o CNPJ.
    [InlineData("00000000000000", false)]
    [InlineData("11111111111111", false)]
    // Comprimento errado: um CPF válido não pode passar por CNPJ.
    [InlineData("52998224725", false)]
    [InlineData("112223330001810", false)]
    public void Cnpj_segue_a_RN002(string digits, bool expected) =>
        Assert.Equal(expected, CnpjValidator.IsValid(digits));

    [Theory]
    // Vetores do projeto (RN-003).
    [InlineData("4111111111111111", true)]
    [InlineData("4111111111111112", false)]
    // Outros números que satisfazem Luhn com 16 dígitos.
    [InlineData("5555555555554444", true)]
    [InlineData("6011111111111117", true)]
    // A RN-003 fixa o comprimento em 16: 15 dígitos que passam em Luhn
    // (Amex) ficam de fora por decisão de escopo.
    [InlineData("378282246310005", false)]
    [InlineData("", false)]
    public void Cartao_segue_a_RN003(string digits, bool expected) =>
        Assert.Equal(expected, LuhnValidator.IsValid(digits));

    [Theory]
    // Os quatro rótulos previstos, com os dois separadores.
    [InlineData("senha: hunter22", 1)]
    [InlineData("password=Abc12345", 1)]
    [InlineData("passwd : segredo", 1)]
    [InlineData("PWD = Trocar123", 1)]
    // Menos de quatro caracteres no valor não conta.
    [InlineData("senha: abc", 0)]
    // Sem separador não conta.
    [InlineData("a senha ficou fraca", 0)]
    // Duas ocorrências no mesmo texto.
    [InlineData("senha: primeira\npassword: segunda", 2)]
    public void Senha_segue_a_RN004(string text, int expected) =>
        Assert.Equal(expected, PasswordHeuristic.Find(text).Count);

    /// <summary>
    /// A RN-004 é sintática e assume falsos positivos. O teste registra isso
    /// como comportamento esperado, e não como defeito: uma frase comum de
    /// documentação dispara a regra, e portanto o bloqueio.
    /// </summary>
    [Fact]
    public void Senha_produz_falso_positivo_documentado()
    {
        var findings = PasswordHeuristic.Find("Instrução: senha: siga o padrão corporativo.");
        Assert.Single(findings);
    }

    /// <summary>
    /// A heurística não devolve o valor da senha em nenhuma assinatura, só
    /// posições. É o que impede que exista um caminho no código capaz de
    /// entregar o segredo em claro a quem chama.
    /// </summary>
    [Fact]
    public void Senha_expoe_apenas_posicoes()
    {
        const string text = "senha: hunter22";
        var match = Assert.Single(PasswordHeuristic.Find(text));

        Assert.Equal("hunter22", text.Substring(match.SecretStart, match.SecretLength));
        Assert.Equal(0, match.Start);
    }
}
