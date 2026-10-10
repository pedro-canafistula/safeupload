using System.Text;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// O motor de inspeção do canal web (Fase 5 da inspeção TLS): mesmas regras
/// do canal de arquivo, com o conteúdo vindo de bytes em memória.
/// </summary>
public sealed class WebInspectionServiceTests : IDisposable
{
    private const string Cpf = "529.982.247-25";
    private const string Destino = "https://drive.example/upload";

    private readonly TestWorkspace _workspace = new();
    private readonly LocalQueueAuditSink _sink;
    private readonly WebInspectionService _service;

    public WebInspectionServiceTests()
    {
        _sink = new LocalQueueAuditSink(_workspace.QueueFile);
        _service = new WebInspectionService(
            new LocalPolicyStore(_workspace.PolicyFile),
            _sink,
            ExtractorRegistry.CreateDefault(),
            endpointId: "PC-TESTE",
            userName: "usuario.teste")
        {
            // Sem reaproveitar a política: os testes a trocam no meio.
            PolicyLifetime = TimeSpan.Zero,
        };
    }

    public void Dispose() => _workspace.Dispose();

    private Task<WebInspectionResult> InspectAsync(params WebUploadPart[] parts) =>
        _service.InspectAsync(new WebUpload(Destino, "msedge", 4242, parts), CancellationToken.None);

    private Task<IReadOnlyList<AuditEvent>> EventsAsync() => _sink.ReadRecentAsync(20, CancellationToken.None);

    private static WebUploadPart Text(string text) => new(null, Encoding.UTF8.GetBytes(text), IsFile: false);

    private static WebUploadPart File(string? name, byte[] content) => new(name, content, IsFile: true);

    [Fact]
    public async Task Texto_com_CPF_bloqueia_e_registra_no_canal_web()
    {
        WebInspectionResult result = await InspectAsync(Text($"meu cpf é {Cpf}"));

        Assert.True(result.IsBlocked);
        Assert.Contains(Category.Cpf, result.Categories);

        AuditEvent audit = Assert.Single(await EventsAsync());
        Assert.Equal(AuditChannel.Web, audit.Channel);
        Assert.Equal(Verdict.Blocked, audit.Verdict);
        Assert.Equal(Destino, audit.DestinationPath);
        Assert.Equal("msedge", audit.ProcessName);
        Assert.Equal(string.Empty, audit.FileName);
        Assert.DoesNotContain(audit.MaskedSnippets, snippet => snippet.Contains(Cpf));
    }

    /// <summary>
    /// Texto limpo não vira evento: uma página comum faz dezenas de POST por
    /// minuto, e registrar cada um afogaria a trilha.
    /// </summary>
    [Fact]
    public async Task Texto_limpo_e_liberado_sem_evento()
    {
        WebInspectionResult result = await InspectAsync(Text("bom dia, segue a pauta da reunião"));

        Assert.False(result.IsBlocked);
        Assert.Empty(await EventsAsync());
    }

    [Fact]
    public async Task Arquivo_limpo_e_aprovado_e_registrado()
    {
        WebInspectionResult result = await InspectAsync(File("pauta.txt", Encoding.UTF8.GetBytes("pauta da reunião")));

        Assert.False(result.IsBlocked);

        AuditEvent audit = Assert.Single(await EventsAsync());
        Assert.Equal(Verdict.Approved, audit.Verdict);
        Assert.Equal("pauta.txt", audit.FileName);
        Assert.Equal(".txt", audit.Extension);
    }

    /// <summary>
    /// O formato vem dos bytes: um docx renomeado para .jpg continua sendo
    /// aberto como docx.
    /// </summary>
    [Fact]
    public async Task Documento_renomeado_e_reconhecido_pelo_conteudo()
    {
        byte[] docx = System.IO.File.ReadAllBytes(_workspace.WriteWordDocument("origem.docx", $"CPF do cliente: {Cpf}"));

        WebInspectionResult result = await InspectAsync(File(@"C:\fakepath\foto.jpg", docx));

        Assert.True(result.IsBlocked);

        AuditEvent audit = Assert.Single(await EventsAsync());
        Assert.Equal("foto.jpg", audit.FileName);
        Assert.Equal(".docx", audit.Extension);
        Assert.Equal(Verdict.Blocked, audit.Verdict);
    }

    [Fact]
    public async Task Planilha_e_PDF_sem_nome_sao_inspecionados()
    {
        byte[] xlsx = System.IO.File.ReadAllBytes(_workspace.WriteSpreadsheet("origem.xlsx", "nome", Cpf));
        byte[] pdf = System.IO.File.ReadAllBytes(_workspace.WritePdf("origem.pdf", $"CPF {Cpf}"));

        Assert.True((await InspectAsync(File(null, xlsx))).IsBlocked);
        Assert.True((await InspectAsync(File(null, pdf))).IsBlocked);

        IReadOnlyList<AuditEvent> events = await EventsAsync();
        Assert.Contains(events, audit => audit.Extension == ".xlsx");
        Assert.Contains(events, audit => audit.Extension == ".pdf");
    }

    /// <summary>RN-011: imagem não está entre as extensões vigiadas.</summary>
    [Fact]
    public async Task Arquivo_fora_das_extensoes_vigiadas_passa_sem_evento()
    {
        byte[] png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13];

        WebInspectionResult result = await InspectAsync(File("foto.png", png));

        Assert.False(result.IsBlocked);
        Assert.Empty(await EventsAsync());
    }

    /// <summary>RN-012 e RN-013: falha de leitura libera com o motivo registrado.</summary>
    [Fact]
    public async Task Arquivo_corrompido_e_liberado_com_o_motivo()
    {
        byte[] broken = [.. "%PDF-1.7\n"u8, .. Encoding.UTF8.GetBytes("isto não é um pdf de verdade")];

        WebInspectionResult result = await InspectAsync(File("quebrado.pdf", broken));

        Assert.False(result.IsBlocked);

        AuditEvent audit = Assert.Single(await EventsAsync());
        Assert.Equal(Verdict.AllowedWithoutInspection, audit.Verdict);
        Assert.StartsWith("parse_error:", audit.NotInspectedReason);
    }

    [Fact]
    public async Task Um_achado_em_qualquer_parte_bloqueia_o_envio_inteiro()
    {
        WebInspectionResult result = await InspectAsync(
            Text("segue em anexo"),
            File("limpo.txt", Encoding.UTF8.GetBytes("nada aqui")),
            File("dados.csv", Encoding.UTF8.GetBytes($"nome;cpf\nAna;{Cpf}\n")));

        Assert.True(result.IsBlocked);

        IReadOnlyList<AuditEvent> events = await EventsAsync();
        Assert.Equal(2, events.Count);
        Assert.Contains(events, audit => audit.FileName == "limpo.txt" && audit.Verdict == Verdict.Approved);
        Assert.Contains(events, audit => audit.FileName == "dados.csv" && audit.Verdict == Verdict.Blocked);
    }

    /// <summary>
    /// Fase 6: o evento sai em nome do dono do navegador, e não da conta do
    /// serviço, e volta no resultado para ser anunciado ao usuário.
    /// </summary>
    [Fact]
    public async Task Evento_leva_o_usuario_do_navegador_e_volta_no_resultado()
    {
        WebInspectionResult result = await _service.InspectAsync(
            new WebUpload(Destino, "msedge", 4242, [Text($"cpf {Cpf}")], UserName: "ana.silva"), CancellationToken.None);

        WebAuditRecord record = Assert.Single(result.Records);
        Assert.Equal("ana.silva", record.Event.UserName);
        Assert.NotEmpty(record.Findings);
        Assert.Equal(record.Event.EventId, Assert.Single(await EventsAsync()).EventId);

        WebInspectionResult semDono = await InspectAsync(File("limpo.txt", Encoding.UTF8.GetBytes("nada")));
        Assert.Equal("usuario.teste", Assert.Single(semDono.Records).Event.UserName);
    }

    /// <summary>
    /// Fase 6: site que envia o texto a cada tecla. Todo envio é barrado, mas
    /// o mesmo achado para o mesmo site vira um evento só dentro do intervalo.
    /// </summary>
    [Fact]
    public async Task Bloqueio_repetido_de_texto_gera_um_evento_so()
    {
        var clock = new RelogioControlado(DateTimeOffset.UnixEpoch);
        var service = new WebInspectionService(
            new LocalPolicyStore(_workspace.PolicyFile), _sink, ExtractorRegistry.CreateDefault(), clock: clock);

        Task<WebInspectionResult> Digitar(string texto, string caminho = "/autocomplete") =>
            service.InspectAsync(new WebUpload($"https://chat.example{caminho}", "msedge", 7, [Text(texto)]), CancellationToken.None);

        Assert.Single((await Digitar($"meu cpf {Cpf}")).Records);

        WebInspectionResult repetido = await Digitar($"meu cpf {Cpf} e preciso de", "/conversation");
        Assert.True(repetido.IsBlocked);
        Assert.Empty(repetido.Records);
        Assert.Single(await EventsAsync());

        clock.Avancar(service.RepeatWindow + TimeSpan.FromSeconds(1));
        Assert.Single((await Digitar($"meu cpf {Cpf}")).Records);
        Assert.Equal(2, (await EventsAsync()).Count);
    }

    /// <summary>Arquivo não é agrupado: cada upload é um evento.</summary>
    [Fact]
    public async Task Arquivo_enviado_duas_vezes_gera_dois_eventos()
    {
        byte[] csv = Encoding.UTF8.GetBytes($"cpf\n{Cpf}\n");

        await InspectAsync(File("dados.csv", csv));
        await InspectAsync(File("dados.csv", csv));

        Assert.Equal(2, (await EventsAsync()).Count);
    }

    /// <summary>Relógio de teste, avançado à mão.</summary>
    private sealed class RelogioControlado(DateTimeOffset inicio) : TimeProvider
    {
        private DateTimeOffset _agora = inicio;

        public void Avancar(TimeSpan intervalo) => _agora += intervalo;

        public override DateTimeOffset GetUtcNow() => _agora;
    }

    /// <summary>
    /// A política é reaproveitada por um intervalo: com o painel configurado,
    /// carregá-la é uma chamada de rede, e uma página faz muitos POST.
    /// </summary>
    [Fact]
    public async Task Politica_e_reaproveitada_entre_envios_proximos()
    {
        var store = new CountingPolicyStore(new LocalPolicyStore(_workspace.PolicyFile));
        var service = new WebInspectionService(store, _sink, ExtractorRegistry.CreateDefault());

        for (int i = 0; i < 5; i++)
        {
            await service.InspectAsync(new WebUpload(Destino, "msedge", 1, [Text("oi")]), CancellationToken.None);
        }

        Assert.Equal(1, store.Loads);
    }

    private sealed class CountingPolicyStore(IPolicyStore inner) : IPolicyStore
    {
        public int Loads { get; private set; }

        public Task<Policy> LoadAsync(CancellationToken cancellationToken)
        {
            Loads++;
            return inner.LoadAsync(cancellationToken);
        }
    }

    /// <summary>Modo de auditoria: registra o bloqueio que faria, mas não nega.</summary>
    [Fact]
    public async Task Modo_de_auditoria_registra_mas_nao_bloqueia()
    {
        await _service.InspectAsync(new WebUpload(Destino, "msedge", 1, []), CancellationToken.None);
        string policy = System.IO.File.ReadAllText(_workspace.PolicyFile);
        Assert.Contains("\"auditOnly\": false", policy);
        _workspace.WritePolicy(policy.Replace("\"auditOnly\": false", "\"auditOnly\": true"));

        WebInspectionResult result = await InspectAsync(Text($"cpf {Cpf}"));

        Assert.False(result.IsBlocked);
        Assert.NotEmpty(result.Findings);
        Assert.Equal(Verdict.Blocked, Assert.Single(await EventsAsync()).Verdict);
    }
}
