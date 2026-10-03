using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// Carregamento do bloco <c>clipboard</c> do policy.json.
/// </summary>
public class ClipboardPolicyTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();

    /// <inheritdoc />
    public void Dispose() => _workspace.Dispose();

    private Task<Policy> LoadAsync() =>
        new LocalPolicyStore(_workspace.PolicyFile).LoadAsync(CancellationToken.None);

    private void Politica(string clipboard) => _workspace.WritePolicy($$"""
        { "version": 1, "activeCategories": ["Cpf"], "maxFileSizeMb": 20, "inspectionTimeoutSeconds": 5,
          "clipboard": {{clipboard}} }
        """);

    /// <summary>
    /// A política padrão traz o bloco, desligado: quem abrir o arquivo vê o que
    /// ligar, mas nada muda para o usuário até alguém decidir.
    /// </summary>
    [Fact]
    public async Task Politica_padrao_traz_o_clipboard_desligado_e_preenchido()
    {
        var policy = await LoadAsync();

        Assert.Equal(ClipboardMode.Off, policy.EffectiveClipboard.Mode);
        Assert.True(policy.EffectiveClipboard.IsEgressDestination("chrome.exe"));
        Assert.True(policy.EffectiveClipboard.IsExcludedSource("KeePass"));
        Assert.Contains("\"clipboard\"", await File.ReadAllTextAsync(_workspace.PolicyFile));
    }

    [Fact]
    public async Task Politica_antiga_sem_o_bloco_carrega_como_desligada()
    {
        _workspace.WritePolicy("""
            { "version": 3, "activeCategories": ["Cpf"], "maxFileSizeMb": 20, "inspectionTimeoutSeconds": 5 }
            """);

        var policy = await LoadAsync();

        Assert.Null(policy.Clipboard);
        Assert.Equal(ClipboardMode.Off, policy.EffectiveClipboard.Mode);
    }

    [Fact]
    public async Task Bloco_completo_e_lido_com_os_nomes_combinados()
    {
        Politica("""
            { "mode": "block", "egressDestinations": ["chrome", "WhatsApp"],
              "excludedSources": ["KeePass"], "maxTextLength": 5000, "oversizedTextIsDirty": false }
            """);

        var clipboard = (await LoadAsync()).EffectiveClipboard;

        Assert.Equal(ClipboardMode.Block, clipboard.Mode);
        Assert.True(clipboard.IsEgressDestination("WHATSAPP.EXE"));
        Assert.False(clipboard.IsEgressDestination("EXCEL"));
        Assert.True(clipboard.IsExcludedSource("keepass.exe"));
        Assert.Equal(5000, clipboard.MaxTextLength);
        Assert.False(clipboard.OversizedTextIsDirty);
    }

    [Fact]
    public async Task Campos_omitidos_usam_os_padroes()
    {
        Politica("""{ "mode": "Audit" }""");

        var clipboard = (await LoadAsync()).EffectiveClipboard;

        Assert.Equal(ClipboardMode.Audit, clipboard.Mode);
        Assert.Equal(ClipboardPolicy.DefaultMaxTextLength, clipboard.MaxTextLength);
        Assert.True(clipboard.OversizedTextIsDirty);
        Assert.Empty(clipboard.EgressDestinations);
    }

    /// <summary>
    /// Ignorar um modo desconhecido desligaria a proteção em silêncio por causa
    /// de um erro de digitação. Por isso é recusado (RN-009).
    /// </summary>
    [Theory]
    [InlineData("\"Blok\"")]
    [InlineData("\"\"")]
    [InlineData("\"2\"")]
    [InlineData("null")]
    public async Task Modo_desconhecido_e_recusado(string modo)
    {
        Politica($$"""{ "mode": {{modo}}, "egressDestinations": ["chrome"] }""");

        await Assert.ThrowsAsync<InvalidPolicyException>(LoadAsync);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public async Task Teto_de_texto_invalido_e_recusado(int teto)
    {
        Politica($$"""{ "mode": "Audit", "maxTextLength": {{teto}} }""");

        await Assert.ThrowsAsync<InvalidPolicyException>(LoadAsync);
    }

    /// <summary>
    /// Bloquear sem destino de saída nenhum é prometer bloqueio e nunca
    /// bloquear.
    /// </summary>
    [Fact]
    public async Task Bloquear_sem_destino_de_saida_e_recusado()
    {
        Politica("""{ "mode": "Block", "egressDestinations": [] }""");

        await Assert.ThrowsAsync<InvalidPolicyException>(LoadAsync);
    }

    [Theory]
    [InlineData("chrome", "chrome")]
    [InlineData("CHROME.EXE", "CHROME")]
    [InlineData(@"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome")]
    [InlineData("  notepad.exe  ", "notepad")]
    [InlineData("", null)]
    [InlineData(null, null)]
    public void Nome_de_processo_e_normalizado(string? entrada, string? esperado)
    {
        Assert.Equal(esperado, ClipboardPolicy.NormalizeProcessName(entrada));
    }
}
