using Microsoft.Extensions.Logging;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Service.Clipboard;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// O serviço do canal de clipboard na Fase 1: classifica, guarda o estado da
/// cópia, mede e nunca interfere. Cada teste aqui é uma linha da entrega da
/// fase.
/// </summary>
public class ClipboardServiceTests
{
    private const string CpfValido = "529.982.247-25";
    private const string CpfSemMascara = "52998224725";

    private static readonly string[] Saida = ["chrome", "WhatsApp"];

    private static Policy Politica(ClipboardMode mode, int maxTextLength = 1000, bool oversizedIsDirty = true) =>
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
            Clipboard: new ClipboardPolicy(
                mode,
                new HashSet<string>(Saida, StringComparer.OrdinalIgnoreCase),
                new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "KeePass" },
                maxTextLength,
                oversizedIsDirty));

    private sealed class FixedPolicyStore(Policy? policy) : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken cancellationToken) =>
            policy is null
                ? throw new InvalidPolicyException("política de teste inválida")
                : Task.FromResult(policy);
    }

    /// <summary>Guarda tudo o que o serviço logou, para provar o que NÃO está nos logs.</summary>
    private sealed class RecordingLogger<T> : ILogger<T>
    {
        public List<string> Lines { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Lines.Add(formatter(state, exception) + (exception is null ? string.Empty : " | " + exception));
    }

    private sealed class Harness
    {
        public Harness(Policy? policy)
        {
            Logger = new RecordingLogger<ClipboardService>();
            Service = new ClipboardService(
                new FixedPolicyStore(policy),
                new ClipboardCopyStore(),
                new ClipboardMetrics(),
                Logger);
        }

        public RecordingLogger<ClipboardService> Logger { get; }

        public ClipboardService Service { get; }

        public Task<ClipboardResponse> Copiar(string texto, string? origem = "notepad", uint? sessao = 1) =>
            Service.HandleAsync(ClipboardRequest.Classify(texto, origem), sessao, CancellationToken.None);

        public Task<ClipboardResponse> Foco(string copyId, string? destino, uint? sessao = 1) =>
            Service.HandleAsync(ClipboardRequest.Paste(copyId, destino), sessao, CancellationToken.None);
    }

    // ---------------------------------------------------------- classificação

    [Fact]
    public async Task Copiar_um_cpf_marca_sujo()
    {
        var h = new Harness(Politica(ClipboardMode.Audit));

        var resposta = await h.Copiar("Cliente: " + CpfValido);

        Assert.Equal(ClipboardProtocol.ClassifyType, resposta.Type);
        Assert.True(resposta.Dirty);
        Assert.Contains(Category.Cpf, resposta.Categories!);
        Assert.False(string.IsNullOrEmpty(resposta.CopyId));
    }

    [Fact]
    public async Task Copiar_texto_limpo_depois_de_um_sujo_volta_a_limpo()
    {
        var h = new Harness(Politica(ClipboardMode.Audit));

        var suja = await h.Copiar("CPF " + CpfValido);
        var limpa = await h.Copiar("reunião às 14h");

        Assert.True(suja.Dirty);
        Assert.False(limpa.Dirty);

        // E o identificador da cópia suja deixou de valer: ir para a saída com
        // ele não conta como "sujo", porque o clipboard já não está.
        var foco = await h.Foco(suja.CopyId!, "chrome");
        Assert.Equal(ClipboardPasteVerdict.Allow, foco.Verdict);
        Assert.Equal(0, h.Service.Metrics.FocusOnEgressWhileDirty);
    }

    [Fact]
    public async Task Resposta_traz_achado_mascarado_e_nunca_o_texto()
    {
        var h = new Harness(Politica(ClipboardMode.Audit));

        var resposta = await h.Copiar("Cliente: " + CpfValido);
        var linha = ClipboardProtocol.Serialize(resposta);

        Assert.NotEmpty(resposta.Findings!);
        Assert.DoesNotContain(CpfValido, linha, StringComparison.Ordinal);
        Assert.DoesNotContain(CpfSemMascara, linha, StringComparison.Ordinal);
        Assert.DoesNotContain("Cliente", linha, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Texto_copiado_nao_aparece_em_nenhum_log()
    {
        var h = new Harness(Politica(ClipboardMode.Audit));

        var suja = await h.Copiar("Segredo do cliente Joaquim: " + CpfValido, origem: "notepad");
        await h.Foco(suja.CopyId!, "chrome");
        await h.Copiar("texto limpo qualquer");

        Assert.NotEmpty(h.Logger.Lines);

        foreach (var linha in h.Logger.Lines)
        {
            Assert.DoesNotContain(CpfValido, linha, StringComparison.Ordinal);
            Assert.DoesNotContain(CpfSemMascara, linha, StringComparison.Ordinal);
            Assert.DoesNotContain("Joaquim", linha, StringComparison.Ordinal);
            Assert.DoesNotContain("texto limpo", linha, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task Texto_acima_do_teto_suja_por_padrao_e_nao_com_a_opcao_desligada()
    {
        var longo = new string('x', 5000);

        var padrao = await new Harness(Politica(ClipboardMode.Audit, maxTextLength: 1000)).Copiar(longo);
        var aberta = await new Harness(Politica(ClipboardMode.Audit, maxTextLength: 1000, oversizedIsDirty: false)).Copiar(longo);

        Assert.True(padrao.Dirty);
        Assert.False(aberta.Dirty);
    }

    [Fact]
    public async Task Texto_cortado_pelo_aplicativo_e_tratado_pelo_tamanho_real()
    {
        var h = new Harness(Politica(ClipboardMode.Audit, maxTextLength: 1000));

        // O aplicativo mandou só o começo, mas o texto tinha 500 mil caracteres.
        var pedido = new ClipboardRequest(
            ClipboardProtocol.ClassifyType,
            Text: "inicio limpo",
            TextLength: 500_000,
            SourceProcess: "notepad");

        var resposta = await h.Service.HandleAsync(pedido, 1, CancellationToken.None);

        Assert.True(resposta.Dirty);
    }

    [Fact]
    public async Task Fonte_excluida_nunca_suja()
    {
        var h = new Harness(Politica(ClipboardMode.Audit));

        var resposta = await h.Copiar("senha: Trocar123 " + CpfValido, origem: "KeePass.exe");

        Assert.False(resposta.Dirty);
    }

    [Fact]
    public async Task Canal_desligado_responde_limpo_e_nao_mede()
    {
        var h = new Harness(Politica(ClipboardMode.Off));

        var resposta = await h.Copiar("CPF " + CpfValido);

        Assert.False(resposta.Dirty);
        Assert.Equal(default(ClipboardMetricsSnapshot), h.Service.Metrics);
    }

    [Fact]
    public async Task Politica_que_nao_carrega_libera()
    {
        var h = new Harness(policy: null);

        var copia = await h.Copiar("CPF " + CpfValido);
        var foco = await h.Foco("qualquer", "chrome");

        Assert.False(copia.Dirty);
        Assert.Equal(ClipboardPasteVerdict.Allow, foco.Verdict);
    }

    // ------------------------------------------------------------- medições

    [Fact]
    public async Task Conta_copias_e_copias_sujas()
    {
        var h = new Harness(Politica(ClipboardMode.Audit));

        await h.Copiar("CPF " + CpfValido);
        await h.Copiar("nada demais");
        await h.Copiar("outro texto");
        await h.Copiar("CPF " + CpfValido);

        var metricas = h.Service.Metrics;
        Assert.Equal(4, metricas.Copies);
        Assert.Equal(2, metricas.DirtyCopies);
    }

    [Fact]
    public async Task Conta_o_foco_em_destino_de_saida_com_o_clipboard_sujo()
    {
        var h = new Harness(Politica(ClipboardMode.Audit));
        var suja = await h.Copiar("CPF " + CpfValido, origem: "notepad");

        var local = await h.Foco(suja.CopyId!, "explorer");
        var saida = await h.Foco(suja.CopyId!, "chrome.exe");

        // Na Fase 1 o veredito não muda nada para o usuário; só alimenta a conta.
        Assert.Equal(ClipboardPasteVerdict.Allow, local.Verdict);
        Assert.Equal(ClipboardPasteVerdict.AuditOnly, saida.Verdict);

        var metricas = h.Service.Metrics;
        Assert.Equal(2, metricas.FocusChangesWhileDirty);
        Assert.Equal(1, metricas.FocusOnEgressWhileDirty);
    }

    [Fact]
    public async Task Foco_no_mesmo_processo_de_origem_nao_conta_como_saida()
    {
        var h = new Harness(Politica(ClipboardMode.Audit));
        var suja = await h.Copiar("CPF " + CpfValido, origem: "chrome");

        var foco = await h.Foco(suja.CopyId!, "chrome");

        Assert.Equal(ClipboardPasteVerdict.Allow, foco.Verdict);
        Assert.Equal(0, h.Service.Metrics.FocusOnEgressWhileDirty);
    }

    [Fact]
    public async Task Foco_com_o_clipboard_limpo_nao_entra_na_conta()
    {
        var h = new Harness(Politica(ClipboardMode.Audit));
        var limpa = await h.Copiar("nada demais");

        var foco = await h.Foco(limpa.CopyId!, "chrome");

        Assert.Equal(ClipboardPasteVerdict.Allow, foco.Verdict);
        Assert.Equal(0, h.Service.Metrics.FocusChangesWhileDirty);
    }

    [Fact]
    public async Task Cada_sessao_so_enxerga_a_propria_copia()
    {
        var h = new Harness(Politica(ClipboardMode.Audit));
        var daSessao1 = await h.Copiar("CPF " + CpfValido, sessao: 1);

        var foco = await h.Foco(daSessao1.CopyId!, "chrome", sessao: 2);

        Assert.Equal(ClipboardPasteVerdict.Allow, foco.Verdict);
        Assert.Equal(0, h.Service.Metrics.FocusOnEgressWhileDirty);
    }

    [Fact]
    public async Task Identificador_desconhecido_libera()
    {
        var h = new Harness(Politica(ClipboardMode.Audit));

        var foco = await h.Foco("nao-existe", "chrome");

        Assert.Equal(ClipboardPasteVerdict.Allow, foco.Verdict);
    }

    [Fact]
    public async Task Modo_block_tambem_so_mede_na_fase_um_e_o_veredito_e_de_bloqueio()
    {
        var h = new Harness(Politica(ClipboardMode.Block));
        var suja = await h.Copiar("CPF " + CpfValido, origem: "notepad");

        var foco = await h.Foco(suja.CopyId!, "WhatsApp");

        // O serviço devolve o veredito que a política daria; é o aplicativo da
        // Fase 1 que o ignora. A conta é a mesma nos dois modos.
        Assert.Equal(ClipboardPasteVerdict.Block, foco.Verdict);
        Assert.Equal(1, h.Service.Metrics.FocusOnEgressWhileDirty);
    }
}
