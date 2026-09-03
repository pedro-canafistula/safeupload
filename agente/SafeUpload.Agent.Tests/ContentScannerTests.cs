using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Domain.Validators;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// A varredura e o mascaramento (RN-007), com atenção especial à sobreposição
/// entre padrões numéricos de comprimentos diferentes.
/// </summary>
public class ContentScannerTests
{
    private static readonly IReadOnlySet<Category> Todas = new HashSet<Category>
    {
        Category.Cpf,
        Category.Cnpj,
        Category.PaymentCard,
        Category.Password
    };

    /// <summary>
    /// O teste que a especificação exige.
    ///
    /// Uma sequência de 14 dígitos contém quatro sequências de 11. Se o CPF
    /// fosse testado antes do CNPJ, este texto produziria achados de CPF em
    /// cima de um CNPJ legítimo, e o bloqueio apontaria a categoria errada.
    /// </summary>
    [Fact]
    public void Cnpj_produz_exatamente_um_achado_e_nao_vira_cpf()
    {
        var findings = ContentScanner.Scan("CNPJ 11.222.333/0001-81", Todas);

        var finding = Assert.Single(findings);
        Assert.Equal(Category.Cnpj, finding.Category);
        Assert.DoesNotContain(findings, f => f.Category == Category.Cpf);
    }

    /// <summary>
    /// O mesmo cuidado do lado do cartão: 16 dígitos contêm sequências de 14
    /// e de 11.
    /// </summary>
    [Fact]
    public void Cartao_produz_exatamente_um_achado()
    {
        var findings = ContentScanner.Scan("Cartao 4111 1111 1111 1111", Todas);

        var finding = Assert.Single(findings);
        Assert.Equal(Category.PaymentCard, finding.Category);
    }

    [Fact]
    public void Cpf_formatado_e_sem_formatacao_sao_reconhecidos()
    {
        Assert.Equal(Category.Cpf, Assert.Single(ContentScanner.Scan("CPF 529.982.247-25", Todas)).Category);
        Assert.Equal(Category.Cpf, Assert.Single(ContentScanner.Scan("CPF 52998224725", Todas)).Category);
    }

    [Fact]
    public void Cada_categoria_aparece_uma_vez_num_texto_com_todas()
    {
        const string texto = """
            Cliente: Maria
            CPF: 529.982.247-25
            CNPJ 11.222.333/0001-81
            Cartao 4111111111111111
            senha: Trocar123
            """;

        var findings = ContentScanner.Scan(texto, Todas);

        Assert.Equal(4, findings.Count);
        Assert.Equal(
            [Category.Cpf, Category.Cnpj, Category.PaymentCard, Category.Password],
            findings.Select(f => f.Category));
    }

    /// <summary>
    /// Os achados saem na ordem em que aparecem no texto, não na ordem em que
    /// as regras foram avaliadas. É o que a notificação de bloqueio mostra.
    /// </summary>
    [Fact]
    public void Achados_saem_na_ordem_do_texto()
    {
        var findings = ContentScanner.Scan("4111111111111111 depois 529.982.247-25", Todas);

        Assert.Equal([Category.PaymentCard, Category.Cpf], findings.Select(f => f.Category));
    }

    /// <summary>
    /// O scanner recebe as categorias ativas como parâmetro: o domínio não lê
    /// política. Com o CPF desligado, o mesmo texto não produz achado.
    /// </summary>
    [Fact]
    public void Categoria_inativa_nao_e_procurada()
    {
        var somenteCnpj = new HashSet<Category> { Category.Cnpj };

        Assert.Empty(ContentScanner.Scan("CPF 529.982.247-25", somenteCnpj));
        Assert.Single(ContentScanner.Scan("CNPJ 11.222.333/0001-81", somenteCnpj));
    }

    [Fact]
    public void Conjunto_vazio_de_categorias_nao_acha_nada()
    {
        Assert.Empty(ContentScanner.Scan("CPF 529.982.247-25", new HashSet<Category>()));
    }

    [Fact]
    public void Texto_limpo_nao_produz_achado()
    {
        Assert.Empty(ContentScanner.Scan("Relatorio trimestral, 42 paginas, revisao 3.", Todas));
    }

    /// <summary>
    /// Números separados por vírgula ou quebra de linha não podem se fundir
    /// numa sequência que não existe no arquivo.
    /// </summary>
    [Theory]
    [InlineData("11222333,000181")]
    [InlineData("11222333\n000181")]
    [InlineData("11222333;000181")]
    public void Numeros_de_campos_diferentes_nao_se_colam(string texto)
    {
        Assert.Empty(ContentScanner.Scan(texto, Todas));
    }

    /// <summary>
    /// Um número que apenas parece um documento — comprimento certo, dígito
    /// verificador errado — não vira achado.
    /// </summary>
    [Fact]
    public void Numero_com_digito_verificador_errado_nao_e_achado()
    {
        Assert.Empty(ContentScanner.Scan("Protocolo 529.982.247-24", Todas));
    }

    /// <summary>
    /// Uma senha cujo valor é um cartão é relatada uma vez só, pela categoria
    /// mais específica. Duas linhas para o mesmo trecho confundiriam quem lê a
    /// notificação sem mudar o veredito.
    /// </summary>
    [Fact]
    public void Trecho_sobreposto_nao_e_relatado_duas_vezes()
    {
        var finding = Assert.Single(ContentScanner.Scan("senha: 4111111111111111", Todas));

        Assert.Equal(Category.PaymentCard, finding.Category);
    }

    /// <summary>
    /// RN-007 — o exemplo literal da especificação.
    /// </summary>
    [Fact]
    public void Mascaramento_preserva_apenas_os_dois_ultimos_digitos()
    {
        Assert.Equal("•••••••••25", Masking.Mask("529.982.247-25"));
        Assert.Equal("•••••••••25", Masking.Mask("52998224725"));
    }

    /// <summary>
    /// O achado que sai do scanner já está mascarado. Não existe caminho pelo
    /// qual o valor original chegue a quem chama.
    /// </summary>
    [Fact]
    public void Achado_nunca_carrega_o_valor_original()
    {
        var finding = Assert.Single(ContentScanner.Scan("CPF: 529.982.247-25", Todas));

        Assert.DoesNotContain("529982247", finding.MaskedSnippet, StringComparison.Ordinal);
        Assert.DoesNotContain("529.982.247-25", finding.MaskedSnippet, StringComparison.Ordinal);
        Assert.Equal("•••••••••25", finding.MaskedSnippet);
    }

    /// <summary>
    /// A senha não preserva nem os dois últimos caracteres: o sufixo de uma
    /// senha é tão sensível quanto o resto dela. Só o rótulo sobrevive.
    /// </summary>
    [Fact]
    public void Senha_mascarada_nao_preserva_caractere_algum()
    {
        var finding = Assert.Single(ContentScanner.Scan("senha: Trocar123", Todas));

        Assert.Equal("senha: ••••••••", finding.MaskedSnippet);
        Assert.DoesNotContain("Trocar", finding.MaskedSnippet, StringComparison.Ordinal);
        Assert.DoesNotContain("123", finding.MaskedSnippet, StringComparison.Ordinal);
    }

    /// <summary>
    /// O número fixo de marcadores impede que o log revele o tamanho da senha.
    /// </summary>
    [Fact]
    public void Senha_mascarada_nao_revela_o_tamanho()
    {
        var curta = Assert.Single(ContentScanner.Scan("senha: abcd", Todas));
        var longa = Assert.Single(ContentScanner.Scan("senha: abcdefghijklmnopqrst", Todas));

        Assert.Equal(curta.MaskedSnippet, longa.MaskedSnippet);
    }
}
