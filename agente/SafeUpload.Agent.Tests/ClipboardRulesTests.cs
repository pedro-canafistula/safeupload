using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// As duas decisões do canal de clipboard: o que suja no Ctrl+C e o que passa
/// no Ctrl+V. É a tabela "Onde bloquear" do plano, em forma de teste.
/// </summary>
public class ClipboardRulesTests
{
    private const string CpfValido = "529.982.247-25";

    private static readonly string[] Saida = ["chrome", "WhatsApp", "ms-teams"];

    private static ClipboardPolicy Clipboard(
        ClipboardMode mode,
        int maxTextLength = ClipboardPolicy.DefaultMaxTextLength,
        bool oversizedTextIsDirty = true,
        params string[] excludedSources) =>
        new(
            mode,
            new HashSet<string>(Saida, StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(excludedSources, StringComparer.OrdinalIgnoreCase),
            maxTextLength,
            oversizedTextIsDirty);

    private static Policy Politica(ClipboardPolicy? clipboard) =>
        new(
            Version: 1,
            ActiveCategories: Enum.GetValues<Category>().ToHashSet(),
            MonitoredScopes: new MonitoredScopes(
                new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".txt" },
                [],
                RemovableDrives: true,
                NetworkPaths: true),
            MaxFileSizeMb: 20,
            InspectionTimeoutSeconds: 5,
            FailOpen: true,
            ExcludedProcesses: new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "SafeUpload.Agent.App" },
            Clipboard: clipboard);

    private static ClipboardClassification Classificar(string texto, Policy politica, string? origem = "notepad") =>
        ClipboardRules.Classify(texto, texto.Length, origem, politica);

    // ---------------------------------------------------------------- Ctrl+C

    [Theory]
    [InlineData("Cliente: " + CpfValido, Category.Cpf)]
    [InlineData("CNPJ 11.222.333/0001-81", Category.Cnpj)]
    [InlineData("cartao 4111111111111111", Category.PaymentCard)]
    [InlineData("senha: Trocar123", Category.Password)]
    [InlineData("\"AccessKeyId\": \"AKIAIOSFODNN7EXAMPLE\"", Category.Secret)]
    public void Texto_com_dado_sensivel_valido_suja(string texto, Category esperada)
    {
        var resultado = Classificar(texto, Politica(Clipboard(ClipboardMode.Audit)));

        Assert.True(resultado.Dirty);
        Assert.Equal(ClipboardCopyReason.Sensitive, resultado.Reason);
        Assert.Contains(esperada, resultado.Categories);
    }

    [Fact]
    public void Achado_vem_mascarado_e_nunca_com_o_valor_original()
    {
        var resultado = Classificar("CPF " + CpfValido, Politica(Clipboard(ClipboardMode.Audit)));

        var achado = Assert.Single(resultado.Findings);
        Assert.DoesNotContain(CpfValido, achado.MaskedSnippet, StringComparison.Ordinal);
        Assert.DoesNotContain("529982247", achado.MaskedSnippet, StringComparison.Ordinal);
    }

    /// <summary>
    /// Onze dígitos que não passam no módulo 11 não são CPF. É o que segura o
    /// falso positivo de quem copia um número qualquer de uma planilha.
    /// </summary>
    [Theory]
    [InlineData("Pedido 12345678901")]
    [InlineData("Total de vendas no trimestre: 1.234.567")]
    [InlineData("")]
    public void Texto_sem_dado_valido_fica_limpo(string texto)
    {
        var resultado = Classificar(texto, Politica(Clipboard(ClipboardMode.Block)));

        Assert.False(resultado.Dirty);
        Assert.Equal(ClipboardCopyReason.Clean, resultado.Reason);
        Assert.Empty(resultado.Findings);
    }

    [Fact]
    public void Canal_desligado_nao_olha_o_texto()
    {
        var resultado = Classificar(CpfValido, Politica(Clipboard(ClipboardMode.Off)));

        Assert.False(resultado.Dirty);
        Assert.Equal(ClipboardCopyReason.ChannelOff, resultado.Reason);
    }

    /// <summary>
    /// Uma política escrita antes do clipboard existir não tem o bloco, e
    /// precisa continuar valendo como canal desligado.
    /// </summary>
    [Fact]
    public void Politica_sem_bloco_de_clipboard_vale_como_desligada()
    {
        var politica = Politica(clipboard: null);

        Assert.Equal(ClipboardMode.Off, politica.EffectiveClipboard.Mode);
        Assert.False(Classificar(CpfValido, politica).Dirty);
    }

    [Theory]
    [InlineData("KeePass")]
    [InlineData("keepass.exe")]
    [InlineData(@"C:\Program Files\KeePass\KeePass.exe")]
    public void Copia_de_processo_excluido_nunca_suja(string origem)
    {
        var politica = Politica(Clipboard(ClipboardMode.Block, excludedSources: ["KeePass"]));

        var resultado = Classificar("senha: Trocar123", politica, origem);

        Assert.False(resultado.Dirty);
        Assert.Equal(ClipboardCopyReason.ExcludedSource, resultado.Reason);
    }

    /// <summary>RN-014 vale também aqui: o próprio agente não suja.</summary>
    [Fact]
    public void Copia_do_proprio_agente_nunca_suja()
    {
        var resultado = Classificar(CpfValido, Politica(Clipboard(ClipboardMode.Block)), "SafeUpload.Agent.App.exe");

        Assert.False(resultado.Dirty);
        Assert.Equal(ClipboardCopyReason.ExcludedSource, resultado.Reason);
    }

    /// <summary>
    /// Texto acima do teto não é varrido. Por padrão suja, seguindo a regra do
    /// driver para origem: o que não foi olhado marca. Sem isso, bastaria
    /// copiar um texto enorme com o CPF no fim.
    /// </summary>
    [Fact]
    public void Texto_grande_demais_suja_por_padrao_sem_ser_varrido()
    {
        var politica = Politica(Clipboard(ClipboardMode.Block, maxTextLength: 50));
        var texto = new string('a', 60);

        var resultado = Classificar(texto, politica);

        Assert.True(resultado.Dirty);
        Assert.Equal(ClipboardCopyReason.TextTooLarge, resultado.Reason);
        Assert.Empty(resultado.Findings);
    }

    [Fact]
    public void Texto_grande_demais_fica_limpo_quando_a_politica_manda()
    {
        var politica = Politica(Clipboard(ClipboardMode.Block, maxTextLength: 50, oversizedTextIsDirty: false));

        var resultado = Classificar(new string('a', 60), politica);

        Assert.False(resultado.Dirty);
        Assert.Equal(ClipboardCopyReason.TextTooLarge, resultado.Reason);
    }

    /// <summary>
    /// O App pode cortar o texto no teto do protocolo. O tamanho real, que
    /// viaja à parte, é o que decide, e não o pedaço que chegou.
    /// </summary>
    [Fact]
    public void Tamanho_real_decide_mesmo_quando_o_texto_chegou_cortado()
    {
        var politica = Politica(Clipboard(ClipboardMode.Block, maxTextLength: 50));

        var resultado = ClipboardRules.Classify("trecho curto", textLength: 1_000, "notepad", politica);

        Assert.Equal(ClipboardCopyReason.TextTooLarge, resultado.Reason);
    }

    // ---------------------------------------------------------------- Ctrl+V

    public static TheoryData<bool, string, string, ClipboardMode, ClipboardPasteVerdict> Colagens => new()
    {
        // Limpo: passa em qualquer lugar.
        { false, "notepad", "chrome", ClipboardMode.Block, ClipboardPasteVerdict.Allow },

        // Sujo, mesmo processo (Excel → Excel): passa.
        { true, "EXCEL", "excel.exe", ClipboardMode.Block, ClipboardPasteVerdict.Allow },

        // Sujo, app local fora da lista de saída (Excel → Word): passa.
        { true, "EXCEL", "WINWORD", ClipboardMode.Block, ClipboardPasteVerdict.Allow },
        { true, "EXCEL", "notepad", ClipboardMode.Audit, ClipboardPasteVerdict.Allow },

        // Sujo, destino de saída: depende do modo.
        { true, "notepad", "chrome", ClipboardMode.Audit, ClipboardPasteVerdict.AuditOnly },
        { true, "notepad", "chrome.exe", ClipboardMode.Block, ClipboardPasteVerdict.Block },
        { true, "EXCEL", "WhatsApp", ClipboardMode.Block, ClipboardPasteVerdict.Block },
        { true, "EXCEL", "ms-teams", ClipboardMode.Audit, ClipboardPasteVerdict.AuditOnly },

        // Canal desligado: nada é bloqueado.
        { true, "notepad", "chrome", ClipboardMode.Off, ClipboardPasteVerdict.Allow },
    };

    [Theory]
    [MemberData(nameof(Colagens))]
    public void Colagem_segue_a_tabela_do_plano(
        bool sujo, string origem, string destino, ClipboardMode modo, ClipboardPasteVerdict esperado)
    {
        var veredito = ClipboardRules.DecidePaste(sujo, origem, destino, Clipboard(modo));

        Assert.Equal(esperado, veredito);
    }

    /// <summary>
    /// Sem saber para onde vai, não se bloqueia: resolver incerteza negando é
    /// o que a RN-013 proíbe.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Destino_desconhecido_cola_normalmente(string? destino)
    {
        var veredito = ClipboardRules.DecidePaste(true, "notepad", destino, Clipboard(ClipboardMode.Block));

        Assert.Equal(ClipboardPasteVerdict.Allow, veredito);
    }

    /// <summary>
    /// Origem desconhecida não pode ser confundida com "mesmo processo".
    /// </summary>
    [Fact]
    public void Origem_desconhecida_nao_libera_colagem_em_destino_de_saida()
    {
        var veredito = ClipboardRules.DecidePaste(true, null, "chrome", Clipboard(ClipboardMode.Block));

        Assert.Equal(ClipboardPasteVerdict.Block, veredito);
    }
}
