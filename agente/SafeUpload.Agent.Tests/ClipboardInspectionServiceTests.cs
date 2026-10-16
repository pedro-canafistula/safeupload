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
public class ClipboardInspectionServiceTests
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

    /// <summary>
    /// O motor e o que a ponte no serviço faria com ele: cada pedido passa pelo
    /// motor, e a observação é escrita com o mesmo <see cref="ClipboardLog"/>
    /// do serviço. Assim o que os testes leem em <see cref="Logger"/> é o que
    /// iria para o log de verdade.
    /// </summary>
    private sealed class Harness
    {
        public Harness(Policy? policy)
        {
            Service = new ClipboardInspectionService(
                new FixedPolicyStore(policy),
                new ClipboardCopyStore(),
                new ClipboardMetrics());
        }

        public RecordingLogger<ClipboardInspectionService> Logger { get; } = new();

        public ClipboardInspectionService Service { get; }
        public ClipboardAuditSink Sink { get; } = new();

        public Task<ClipboardResponse> Copiar(string texto, string? origem = "notepad", uint? sessao = 1) =>
            Pedir(ClipboardRequest.Classify(texto, origem), sessao);

        public Task<ClipboardResponse> Foco(string copyId, string? destino, uint? sessao = 1) =>
            Pedir(ClipboardRequest.Paste(copyId, destino), sessao);

        public Task<ClipboardResponse> Estado(uint? sessao = 1) =>
            Pedir(ClipboardRequest.State(), sessao);

        public async Task<ClipboardResponse> Pedir(ClipboardRequest pedido, uint? sessao,
            string? userName = null, CancellationToken cancellationToken = default)
        {
            var resultado = await Service.HandleAsync(pedido, sessao, cancellationToken);
            ClipboardLog.Write(Logger, resultado.Observation);
            return await ClipboardAudit.WriteAsync(resultado, Sink, Logger, userName, cancellationToken);
        }
    }

    // ---------------------------------------------------------- classificação

    [Theory]
    [InlineData(ClipboardMode.Audit)]
    [InlineData(ClipboardMode.Block)]
    public async Task Observacao_vai_para_fila_sem_texto_e_sem_alegar_bloqueio(ClipboardMode mode)
    {
        var harness = new Harness(Politica(mode) with { Version = 7 });
        var copy = await harness.Copiar("Cliente Joaquim: " + CpfValido, origem: "EXCEL");
        Assert.Empty(harness.Sink.Events);
        var response = await harness.Pedir(ClipboardRequest.Paste(copy.CopyId!, "chrome"),
            1, "DOMINIO\\usuario");
        var audit = Assert.Single(harness.Sink.Events);
        Assert.Equal(audit.EventId.ToString(), response.EventId);
        Assert.Equal(AuditChannel.Clipboard, audit.Channel);
        Assert.Equal(Verdict.AllowedWithoutInspection, audit.Verdict);
        Assert.Equal("clipboard_focus_observed", audit.NotInspectedReason);
        Assert.Equal(7, audit.PolicyVersion);
        Assert.Equal(Environment.MachineName, audit.EndpointId);
        Assert.Equal("DOMINIO\\usuario", audit.UserName);
        Assert.Equal("EXCEL", audit.ProcessName);
        Assert.Equal("chrome", audit.DestinationPath);
        Assert.Equal(("Cliente Joaquim: " + CpfValido).Length * 2, audit.SizeBytes);
        Assert.Contains(Category.Cpf, audit.Categories);
        Assert.Empty(audit.MaskedSnippets);
        Assert.Empty(audit.FileName);
        Assert.Empty(audit.Extension);
        Assert.False(audit.Dispatched);
        var json = System.Text.Json.JsonSerializer.Serialize(audit);
        Assert.DoesNotContain("Joaquim", json);
        Assert.DoesNotContain(CpfValido, json);
        Assert.DoesNotContain(CpfSemMascara, json);
    }

    [Fact]
    public async Task Nao_audita_copia_limpa_local_excluida_desconhecida_ou_de_outra_sessao()
    {
        var harness = new Harness(Politica(ClipboardMode.Audit));
        var copy = await harness.Copiar(CpfValido);
        await harness.Foco(copy.CopyId!, "explorer");
        await harness.Foco(copy.CopyId!, "chrome", sessao: 2);
        await harness.Foco("desconhecida", "chrome");
        var clean = await harness.Copiar("limpo");
        await harness.Foco(clean.CopyId!, "chrome");
        await harness.Foco(copy.CopyId!, "chrome");
        var excluded = await harness.Copiar(CpfValido, origem: "KeePass");
        await harness.Foco(excluded.CopyId!, "chrome");
        Assert.Empty(harness.Sink.Events);
        var disabled = new Harness(Politica(ClipboardMode.Off));
        var offCopy = await disabled.Copiar(CpfValido);
        await disabled.Foco(offCopy.CopyId!, "chrome");
        Assert.Empty(disabled.Sink.Events);
    }

    [Fact]
    public async Task Falha_da_fila_nao_altera_decisao_nem_expoe_mensagem_da_excecao()
    {
        var harness = new Harness(Politica(ClipboardMode.Audit));
        harness.Sink.Failure = new IOException("segredo: " + CpfValido);
        var copy = await harness.Copiar(CpfValido);
        var response = await harness.Foco(copy.CopyId!, "chrome");
        Assert.Equal(ClipboardPasteVerdict.AuditOnly, response.Verdict);
        Assert.Null(response.EventId);
        Assert.Empty(harness.Sink.Events);
        Assert.DoesNotContain(harness.Logger.Lines, line => line.Contains(CpfValido));
    }

    [Fact]
    public async Task Texto_acima_do_teto_registra_tamanho_sem_inventar_categorias()
    {
        var harness = new Harness(Politica(ClipboardMode.Audit, maxTextLength: 10));
        var copy = await harness.Pedir(new ClipboardRequest(ClipboardProtocol.ClassifyType,
            Text: "inicio", TextLength: 500_000, SourceProcess: "notepad"), 1);
        await harness.Foco(copy.CopyId!, "chrome");
        var audit = Assert.Single(harness.Sink.Events);
        Assert.Equal(1_000_000L, audit.SizeBytes);
        Assert.Empty(audit.Categories);
        Assert.Empty(audit.MaskedSnippets);
        Assert.Equal(Verdict.AllowedWithoutInspection, audit.Verdict);
    }

    [Fact]
    public async Task Cancelamento_da_gravacao_e_propagado()
    {
        var harness = new Harness(Politica(ClipboardMode.Audit));
        var copy = await harness.Copiar(CpfValido);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => harness.Pedir(
            ClipboardRequest.Paste(copy.CopyId!, "chrome"), 1, cancellationToken: cancellation.Token));
        Assert.Empty(harness.Sink.Events);
    }

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

        var resposta = await h.Pedir(pedido, 1);

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

    // ------------------------------------------------- estado do canal (state)

    [Theory]
    [InlineData(ClipboardMode.Audit, true)]
    [InlineData(ClipboardMode.Block, true)]
    [InlineData(ClipboardMode.Off, false)]
    public async Task Pergunta_de_estado_diz_se_o_canal_esta_ligado(ClipboardMode mode, bool ligado)
    {
        var resposta = await new Harness(Politica(mode)).Estado();

        Assert.Equal(ClipboardProtocol.StateType, resposta.Type);
        Assert.Equal(ligado, resposta.Enabled);
    }

    [Fact]
    public async Task Pergunta_de_estado_nao_mexe_na_copia_nem_nos_contadores()
    {
        var h = new Harness(Politica(ClipboardMode.Audit));
        var suja = await h.Copiar("CPF " + CpfValido);

        await h.Estado();
        var foco = await h.Foco(suja.CopyId!, "chrome");

        Assert.Equal(ClipboardPasteVerdict.AuditOnly, foco.Verdict);
        Assert.Equal(1, h.Service.Metrics.Copies);
    }

    [Theory]
    [InlineData(ClipboardMode.Audit, true)]
    [InlineData(ClipboardMode.Off, false)]
    public async Task Classificacao_diz_se_o_canal_esta_ligado(ClipboardMode mode, bool ligado)
    {
        var resposta = await new Harness(Politica(mode)).Copiar("qualquer coisa");

        Assert.Equal(ligado, resposta.Enabled);
    }

    [Fact]
    public async Task Politica_que_nao_carrega_diz_canal_desligado_e_registra_so_o_tipo_do_erro()
    {
        var h = new Harness(policy: null);

        var estado = await h.Estado();
        var copia = await h.Copiar("CPF " + CpfValido);

        Assert.False(estado.Enabled);
        Assert.False(copia.Enabled);
        Assert.False(copia.Dirty);
        Assert.Contains(h.Logger.Lines, l => l.Contains(nameof(InvalidPolicyException), StringComparison.Ordinal));
        Assert.DoesNotContain(h.Logger.Lines, l => l.Contains("política de teste inválida", StringComparison.Ordinal));
    }

    // --------------------------------------------- auditOnly global da política

    [Fact]
    public async Task Com_auditOnly_ligado_o_bloqueio_vira_auditoria()
    {
        var h = new Harness(Politica(ClipboardMode.Block) with { AuditOnly = true });
        var suja = await h.Copiar("CPF " + CpfValido, origem: "notepad");

        var foco = await h.Foco(suja.CopyId!, "WhatsApp");

        Assert.Equal(ClipboardPasteVerdict.AuditOnly, foco.Verdict);
    }

    [Fact]
    public async Task Sem_auditOnly_o_bloqueio_continua_bloqueio()
    {
        var h = new Harness(Politica(ClipboardMode.Block) with { AuditOnly = false });
        var suja = await h.Copiar("CPF " + CpfValido, origem: "notepad");

        var foco = await h.Foco(suja.CopyId!, "WhatsApp");

        Assert.Equal(ClipboardPasteVerdict.Block, foco.Verdict);
    }

    [Theory]
    [InlineData(ClipboardMode.Off)]
    [InlineData(ClipboardMode.Audit)]
    public void AuditOnly_nao_muda_um_canal_desligado_nem_em_auditoria(ClipboardMode mode)
    {
        var politica = Politica(mode) with { AuditOnly = true };

        Assert.Equal(mode, politica.EffectiveClipboard.Mode);
    }

    [Fact]
    public void Block_sem_destino_de_saida_continua_recusado_mesmo_com_auditOnly()
    {
        var politica = Politica(ClipboardMode.Block) with
        {
            AuditOnly = true,
            Clipboard = new ClipboardPolicy(
                ClipboardMode.Block,
                new HashSet<string>(StringComparer.OrdinalIgnoreCase),
                new HashSet<string>(StringComparer.OrdinalIgnoreCase),
                1000,
                OversizedTextIsDirty: true)
        };

        Assert.Throws<InvalidPolicyException>(politica.EnsureValid);
    }
}
