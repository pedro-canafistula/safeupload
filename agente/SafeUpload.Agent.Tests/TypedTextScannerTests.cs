using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// A varredura de texto digitado na web (Fase 7): a régua de texto escrito por
/// uma pessoa, que não confunde telemetria de página com dado sensível.
/// </summary>
public sealed class TypedTextScannerTests
{
    private static readonly IReadOnlySet<Category> All =
        new HashSet<Category> { Category.Cpf, Category.Cnpj, Category.PaymentCard, Category.Password, Category.Secret };

    private static IReadOnlyList<Category> Scan(string text) =>
        [.. TypedTextScanner.Scan(text, All).Select(finding => finding.Category)];

    [Theory]
    [InlineData("meu cpf é 529.982.247-25, pode conferir?", Category.Cpf)]
    [InlineData("529.982.247-25", Category.Cpf)]
    [InlineData("cpf: 52998224725", Category.Cpf)]
    [InlineData("cpf=52998224725", Category.Cpf)]
    [InlineData("CPF\n52998224725\n", Category.Cpf)]
    [InlineData("em 11/10/2026 o cliente 529.982.247-25 pediu", Category.Cpf)]
    [InlineData("empresa 11.222.333/0001-81", Category.Cnpj)]
    [InlineData("cnpj 11222333000181", Category.Cnpj)]
    [InlineData("pague com 4111 1111 1111 1111 hoje", Category.PaymentCard)]
    [InlineData("4111-1111-1111-1111", Category.PaymentCard)]
    [InlineData("cartão: 4111111111111111", Category.PaymentCard)]
    public void Dado_escrito_por_uma_pessoa_e_encontrado(string text, Category expected)
    {
        Assert.Equal([expected], Scan(text));
    }

    /// <summary>
    /// O que barrou sites de verdade na qualificação: números soltos em
    /// telemetria, que por acaso têm dígito verificador válido.
    /// </summary>
    [Theory]
    [InlineData("52998224725")]                                 // 11 dígitos válidos, sem contexto
    [InlineData("{\"id\":52998224725,\"ts\":1760150000000}")]
    [InlineData("4111111111111111")]                            // 16 dígitos com Luhn, sem contexto
    [InlineData("session=4111111111111111&v=2")]
    [InlineData("trace 00-4111111111111111-01")]                // dentro de um identificador
    [InlineData("id 1529.982.247-25")]                          // parte de um número maior
    [InlineData("v529.982.247-25x")]
    [InlineData("11222333000181")]
    [InlineData("coords 529.982.247-25.7")]
    public void Numero_solto_de_telemetria_nao_conta(string text)
    {
        Assert.Empty(Scan(text));
    }

    [Fact]
    public void Numero_com_digito_verificador_errado_nao_conta()
    {
        Assert.Empty(Scan("cpf 529.982.247-26 e cartão 4111 1111 1111 1112"));
    }

    /// <summary>Login em qualquer site manda a senha; isso não é vazamento.</summary>
    [Theory]
    [InlineData("email=ana@example.com\npassword=Segredo123!")]
    [InlineData("senha: minhasenha123")]
    public void Senha_em_formulario_nao_conta(string text)
    {
        Assert.Empty(Scan(text));
    }

    /// <summary>JWT e chave de API do Google são o que a própria página envia para se autenticar.</summary>
    [Theory]
    [InlineData("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV")]
    [InlineData("key=AIzaSyA1234567890abcdefghijklmnopqrstuvw")]
    public void Credencial_da_propria_pagina_nao_conta(string text)
    {
        Assert.Empty(Scan(text));
    }

    [Theory]
    [InlineData("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")]
    [InlineData("use a chave AKIAIOSFODNN7EXAMPLE no deploy")]
    [InlineData("token ghp_abcdefghijklmnopqrstuvwxyz0123456789")]
    public void Segredo_do_usuario_e_encontrado(string text)
    {
        Assert.Equal([Category.Secret], Scan(text));
    }

    [Fact]
    public void So_as_categorias_ativas_contam()
    {
        var onlyCnpj = new HashSet<Category> { Category.Cnpj };

        Assert.Empty(TypedTextScanner.Scan("cpf 529.982.247-25", onlyCnpj));
    }

    [Fact]
    public void O_achado_sai_mascarado()
    {
        Finding finding = Assert.Single(TypedTextScanner.Scan("cpf 529.982.247-25", All));

        Assert.DoesNotContain("529", finding.MaskedSnippet);
    }
}
