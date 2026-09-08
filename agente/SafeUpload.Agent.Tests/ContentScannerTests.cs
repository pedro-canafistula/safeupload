using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Domain.Validators;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// A varredura e o mascaramento (RN-007), com atenção especial à sobreposição
/// entre padrões numéricos de comprimentos diferentes.
/// </summary>
public class ContentScannerTests
{
    /// <summary>
    /// Todas as categorias, derivadas do enum e não listadas à mão.
    ///
    /// Estavam listadas, e quando <see cref="Category.Secret"/> entrou o
    /// conjunto chamado "Todas" deixou de ser todas — silenciosamente, porque
    /// nada num teste reclama de uma categoria que ele não pediu. Derivar do
    /// enum faz a próxima categoria entrar aqui sozinha.
    /// </summary>
    private static readonly IReadOnlySet<Category> Todas =
        Enum.GetValues<Category>().ToHashSet();

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

    /// <summary>
    /// A chave da AWS no arquivo de configuração que foi junto com a pasta do
    /// projeto. Nenhuma outra regra dispara aqui: não é número documental e a
    /// heurística de senha não reage a "AccessKey".
    /// </summary>
    [Theory]
    [InlineData("\"AccessKeyId\": \"AKIAIOSFODNN7EXAMPLE\"")]
    [InlineData("token: ghp_1234567890abcdefghijklmnopqrstuvwxyz")]
    [InlineData("GOOGLE_KEY=AIzaSyD-1234567890abcdefghijklmnopqrstu")]
    [InlineData("-----BEGIN RSA PRIVATE KEY-----")]
    public void Credencial_de_maquina_e_encontrada(string texto)
    {
        var achados = ContentScanner.Scan(texto, Todas);

        Assert.Contains(achados, f => f.Category == Category.Secret);
    }

    /// <summary>
    /// O valor da credencial nunca sobrevive ao achado — nem o sufixo, ao
    /// contrário dos números. O rótulo diz o que rotacionar sem revelar nada.
    /// </summary>
    [Fact]
    public void Credencial_nao_aparece_em_claro_no_achado()
    {
        const string chave = "AKIAIOSFODNN7EXAMPLE";

        var achados = ContentScanner.Scan($"aws_key = {chave}", Todas);
        var achado = Assert.Single(achados);

        Assert.DoesNotContain("AKIA", achado.MaskedSnippet, StringComparison.Ordinal);
        Assert.DoesNotContain("EXAMPLE", achado.MaskedSnippet, StringComparison.Ordinal);
        Assert.Contains("chave da AWS", achado.MaskedSnippet, StringComparison.Ordinal);
    }

    /// <summary>
    /// O padrão mais específico vence. "password = ghp_..." casa as duas
    /// regras, e reportar como token do GitHub diz o que precisa ser
    /// rotacionado; reportar como senha diz apenas que havia uma.
    /// </summary>
    [Fact]
    public void Credencial_vence_a_heuristica_de_senha()
    {
        var achados = ContentScanner.Scan(
            "password = ghp_1234567890abcdefghijklmnopqrstuvwxyz", Todas);

        var achado = Assert.Single(achados);

        Assert.Equal(Category.Secret, achado.Category);
    }

    /// <summary>
    /// O preço da precisão é cobertura, e o teste registra isso: a regra só
    /// reconhece formatos conhecidos. Uma sequência aleatória qualquer não
    /// vira achado — detecção por entropia pegaria os provedores desconhecidos
    /// e traria junto todo hash, UUID e identificador de commit de qualquer
    /// máquina de desenvolvimento.
    /// </summary>
    [Theory]
    [InlineData("commit 7f3a9c2e1b4d5a6f8e0c2d4b6a8f0e1c3d5b7a9f")]
    [InlineData("id: 550e8400-e29b-41d4-a716-446655440000")]
    [InlineData("hash SHA256 de a3f5b8c9d0e1f2a3b4c5d6e7f8a9b0c1")]
    public void Sequencia_aleatoria_sem_formato_conhecido_nao_vira_achado(string texto)
    {
        var achados = ContentScanner.Scan(texto, Todas);

        Assert.DoesNotContain(achados, f => f.Category == Category.Secret);
    }
}
