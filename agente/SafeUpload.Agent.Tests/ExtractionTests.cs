using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// Extração de texto por formato (HU-01) e as garantias da RN-006.
/// </summary>
public class ExtractionTests : IDisposable
{
    private static readonly IReadOnlySet<Category> Todas = new HashSet<Category>
    {
        Category.Cpf,
        Category.Cnpj,
        Category.PaymentCard,
        Category.Password
    };

    private readonly TestWorkspace _workspace = new();
    private readonly ExtractorRegistry _registry = ExtractorRegistry.CreateDefault();

    /// <inheritdoc />
    public void Dispose() => _workspace.Dispose();

    private async Task<string> ExtractAsync(string path)
    {
        var extractor = _registry.Resolve(Path.GetExtension(path));
        Assert.NotNull(extractor);

        using var content = new MemoryStream(await File.ReadAllBytesAsync(path));
        return await extractor.ExtractAsync(content, CancellationToken.None);
    }

    [Theory]
    [InlineData(".txt")]
    [InlineData(".csv")]
    [InlineData(".docx")]
    [InlineData(".xlsx")]
    public void Formatos_previstos_tem_extrator(string extension) =>
        Assert.True(_registry.IsSupported(extension));

    /// <summary>
    /// PDF ficou fora desta entrega. Sem extrator, a RN-013 libera sem
    /// inspecionar em vez de bloquear.
    /// </summary>
    [Theory]
    [InlineData(".pdf")]
    [InlineData(".zip")]
    [InlineData(".exe")]
    [InlineData("")]
    [InlineData(null)]
    public void Formatos_fora_do_escopo_nao_tem_extrator(string? extension) =>
        Assert.False(_registry.IsSupported(extension));

    [Fact]
    public void Extensao_e_reconhecida_sem_diferenciar_maiusculas() =>
        Assert.True(_registry.IsSupported(".DOCX"));

    [Fact]
    public async Task Texto_puro_e_lido_integralmente()
    {
        var path = _workspace.WriteText("nota.txt", "CPF: 529.982.247-25\nfim");

        Assert.Contains("529.982.247-25", await ExtractAsync(path), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Csv_e_varrido()
    {
        var path = _workspace.WriteText("clientes.csv", "nome,documento\nMaria,529.982.247-25");
        var findings = ContentScanner.Scan(await ExtractAsync(path), Todas);

        Assert.Equal(Category.Cpf, Assert.Single(findings).Category);
    }

    [Fact]
    public async Task Docx_tem_o_texto_dos_paragrafos()
    {
        var path = _workspace.WriteWordDocument("contrato.docx", "Contratante", "CPF: 529.982.247-25");
        var findings = ContentScanner.Scan(await ExtractAsync(path), Todas);

        Assert.Equal(Category.Cpf, Assert.Single(findings).Category);
    }

    /// <summary>
    /// A regressão que motivou a extração parágrafo a parágrafo.
    ///
    /// Usar o InnerText do corpo emenda os parágrafos sem separador nenhum.
    /// Dois parágrafos que terminam e começam em dígito virariam uma única
    /// sequência numérica, e aqui essa sequência seria um CNPJ válido que não
    /// está no documento.
    /// </summary>
    [Fact]
    public async Task Docx_nao_funde_numeros_de_paragrafos_vizinhos()
    {
        var path = _workspace.WriteWordDocument("pedido.docx", "Pedido 11222333", "Lote 000181");

        Assert.Empty(ContentScanner.Scan(await ExtractAsync(path), Todas));
    }

    [Fact]
    public async Task Xlsx_resolve_a_tabela_de_strings_compartilhadas()
    {
        var path = _workspace.WriteSpreadsheet("fornecedores.xlsx", "Fornecedor", "CNPJ 11.222.333/0001-81");
        var findings = ContentScanner.Scan(await ExtractAsync(path), Todas);

        Assert.Equal(Category.Cnpj, Assert.Single(findings).Category);
    }

    /// <summary>
    /// Mesmo cuidado do .docx, agora entre células: unir células com espaço
    /// inventaria um CNPJ que a planilha não contém.
    /// </summary>
    [Fact]
    public async Task Xlsx_nao_funde_numeros_de_celulas_vizinhas()
    {
        var path = _workspace.WriteSpreadsheet("lotes.xlsx", "11222333", "000181");

        Assert.Empty(ContentScanner.Scan(await ExtractAsync(path), Todas));
    }

    /// <summary>
    /// RN-006 — a extração não grava arquivo em lugar nenhum, nem quando falha.
    /// O teste conta o conteúdo da pasta antes e depois de uma extração bem
    /// sucedida e de uma que lança.
    /// </summary>
    [Fact]
    public async Task Extracao_nao_deixa_arquivo_temporario()
    {
        var valido = _workspace.WriteSpreadsheet("ok.xlsx", "CPF 529.982.247-25");
        var corrompido = _workspace.WriteText("mentira.docx", "isto nao e um documento do Word");

        var antes = Directory.GetFileSystemEntries(_workspace.Root, "*", SearchOption.AllDirectories).Length;

        await ExtractAsync(valido);
        await Assert.ThrowsAnyAsync<Exception>(() => ExtractAsync(corrompido));

        var depois = Directory.GetFileSystemEntries(_workspace.Root, "*", SearchOption.AllDirectories).Length;

        Assert.Equal(antes, depois);
    }

    /// <summary>
    /// Extensão declarada por dois extratores é erro de configuração, e falha
    /// na composição em vez de escolher um deles em silêncio.
    /// </summary>
    [Fact]
    public void Extensao_duplicada_no_registro_e_rejeitada() =>
        Assert.Throws<InvalidOperationException>(
            () => new ExtractorRegistry([new PlainTextExtractor(), new PlainTextExtractor()]));
}
