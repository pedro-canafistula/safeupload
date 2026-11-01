using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Domain.Validators;

namespace SafeUpload.Agent.Tests;

/// <summary>As regras da console web sem dígito verificador próprio: precisam de rótulo ou de formato validável.</summary>
public sealed class ContextDetectorsTests
{
    private static readonly IReadOnlySet<Category> All = Enum.GetValues<Category>().ToHashSet();

    private static IReadOnlyList<Category> Scan(string text) =>
        [.. ContentScanner.Scan(text, All).Select(finding => finding.Category)];

    [Theory]
    [InlineData("RG: 12.345.678-2", Category.Rg)]
    [InlineData("RG nº 4.123.456", Category.Rg)]
    [InlineData("Carteira de identidade 1234567-8", Category.Rg)]
    [InlineData("documento 24.678.131-2 anexo", Category.Rg)]
    [InlineData("documento 10.000.006-X anexo", Category.Rg)]
    [InlineData("Agência 1234-5, conta corrente 98765-4", Category.BankData)]
    [InlineData("Ag. 0001 C/C 123456-7", Category.BankData)]
    [InlineData("IBAN GB82 WEST 1234 5698 7654 32", Category.BankData)]
    [InlineData("BR1800360305000010009795493C1", Category.BankData)]
    [InlineData("CID F32.1", Category.HealthData)]
    [InlineData("CID-10: J45", Category.HealthData)]
    [InlineData("Cartão SUS: 898 0010 0000 0003", Category.HealthData)]
    [InlineData("Diagnóstico: hipertensão", Category.HealthData)]
    [InlineData("Tipo sanguíneo: O+", Category.HealthData)]
    [InlineData("CONFIDENCIAL - não circular", Category.ConfidentialDocument)]
    [InlineData("Documento sigiloso", Category.ConfidentialDocument)]
    [InlineData("Internal use only", Category.ConfidentialDocument)]
    [InlineData("contato: maria.silva@example.com", Category.PersonalData)]
    [InlineData("ligue (11) 98765-4321", Category.PersonalData)]
    [InlineData("+55 61 3333-4444", Category.PersonalData)]
    [InlineData("Data de nascimento: 03/04/1990", Category.PersonalData)]
    public void Dado_com_rotulo_ou_formato_validavel_e_encontrado(string text, Category expected)
    {
        Assert.Equal([expected], Scan(text));
    }

    [Theory]
    [InlineData("cabo RG-45 e conector RG-6")]                  // RG sem número de documento
    [InlineData("versão 12.345.678-0")]                          // formato de RG com dígito errado
    [InlineData("agência 1234 fica no centro")]                  // agência sem conta
    [InlineData("GB82 WEST 1234 5698 7654 33")]                  // IBAN com dígito errado
    [InlineData("Cartão SUS: 898 0010 0000 0004")]               // CNS inválido
    [InlineData("o diagnóstico do sistema mostrou lentidão")]   // sem campo de formulário
    [InlineData("termo de confidencialidade em anexo")]          // palavra derivada, não marcação
    [InlineData("pedido 1234 5678 e nota 2024-11-01")]           // números soltos
    [InlineData("nascimento do projeto em 2019")]                // sem data
    public void Texto_comum_nao_e_achado(string text)
    {
        Assert.Empty(Scan(text));
    }

    [Fact]
    public void Categoria_inativa_nao_e_procurada()
    {
        var onlyCpf = new HashSet<Category> { Category.Cpf };
        Assert.Empty(ContentScanner.Scan("RG: 12.345.678-2, CONFIDENCIAL, maria@example.com", onlyCpf));
    }

    [Fact]
    public void Marcacao_de_classificacao_conta_uma_vez()
    {
        Finding finding = Assert.Single(ContentScanner.Scan("CONFIDENCIAL\npágina 1\nCONFIDENCIAL\npágina 2", All));
        Assert.Equal("CONFIDENCIAL", finding.MaskedSnippet);
    }

    [Fact]
    public void Achados_nao_revelam_o_valor()
    {
        var findings = ContentScanner.Scan(
            "RG: 12.345.678-2\nAgência 1234-5 conta 98765-4\nCID F32.1\nmaria.silva@example.com\nData de nascimento: 03/04/1990", All);
        Assert.Equal(5, findings.Count);
        string all = string.Join('\n', findings.Select(f => f.MaskedSnippet));
        foreach (string secret in new[] { "12.345.678", "1234-5", "98765", "F32", "maria", "03/04/1990" })
            Assert.DoesNotContain(secret, all, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Cpf_continua_cpf_mesmo_com_rotulo_de_documento_proximo()
    {
        Assert.Equal([Category.Cpf], Scan("documento: 529.982.247-25"));
    }

    [Fact]
    public void Texto_digitado_na_web_tambem_usa_as_regras_de_contexto()
    {
        Assert.Equal([Category.HealthData],
            TypedTextScanner.Scan("CID F32.1", All).Select(f => f.Category).ToArray());
    }

    [Theory]
    [InlineData("12.345.678-2", true)]
    [InlineData("10.000.006-X", true)]
    [InlineData("12.345.678-3", false)]
    [InlineData("11.111.111-1", false)]
    public void Digito_do_rg_de_sp(string value, bool valid) => Assert.Equal(valid, ContextDetectors.IsSaoPauloRg(value));
}
