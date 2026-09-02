using System.Diagnostics;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// O motor de decisão (HU-03) e as regras que ele arbitra: RN-005, RN-011,
/// RN-012, RN-013 e RN-014, mais o cache.
/// </summary>
public class InspectionServiceTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    private readonly LocalQueueAuditSink _sink;
    private readonly LocalPolicyStore _policies;
    private readonly VerdictCache _cache = new();

    /// <summary>Monta o motor sobre uma pasta temporária isolada.</summary>
    public InspectionServiceTests()
    {
        _sink = new LocalQueueAuditSink(_workspace.QueueFile);
        _policies = new LocalPolicyStore(_workspace.PolicyFile);
    }

    /// <inheritdoc />
    public void Dispose() => _workspace.Dispose();

    private InspectionService Service(ExtractorRegistry? extractors = null) => new(
        _policies,
        _sink,
        extractors ?? ExtractorRegistry.CreateDefault(),
        _cache,
        endpointId: "PC-TESTE",
        userName: "usuario.teste");

    private Task<InspectionResult> InspectAsync(FileOperation operation) =>
        Service().InspectAsync(operation, CancellationToken.None);

    [Fact]
    public async Task Arquivo_limpo_e_aprovado()
    {
        var path = _workspace.WriteText("limpo.txt", "Relatorio trimestral, 42 paginas.");
        var result = await InspectAsync(TestWorkspace.Operation(path));

        Assert.Equal(Verdict.Approved, result.Verdict);
        Assert.False(result.IsBlocked);
        Assert.True(result.InScope);
        Assert.Null(result.Reason);
        Assert.Empty(result.Findings);
    }

    /// <summary>
    /// RN-005 — um achado válido basta para negar.
    /// </summary>
    [Fact]
    public async Task Rn005_um_achado_valido_bloqueia()
    {
        var path = _workspace.WriteText("vazamento.txt", "CPF: 529.982.247-25");
        var result = await InspectAsync(TestWorkspace.Operation(path));

        Assert.Equal(Verdict.Blocked, result.Verdict);
        Assert.True(result.IsBlocked);
        Assert.Equal(Category.Cpf, Assert.Single(result.Categories));
        Assert.Equal("•••••••••25", Assert.Single(result.Findings).MaskedSnippet);
    }

    /// <summary>
    /// RN-014 — o próprio agente não é interceptado, mesmo com o arquivo
    /// contendo dado sensível e o destino em escopo.
    /// </summary>
    [Fact]
    public async Task Rn014_processo_excluido_nao_e_inspecionado()
    {
        var path = _workspace.WriteText("vazamento.txt", "CPF: 529.982.247-25");
        var result = await InspectAsync(
            TestWorkspace.Operation(path, processName: "SafeUpload.Agent.App"));

        Assert.False(result.InScope);
        Assert.Equal("excluded_process", result.Reason);
        Assert.NotEqual(Verdict.Blocked, result.Verdict);
    }

    /// <summary>
    /// RN-011 — destino fora do escopo não é inspecionado, e por isso também
    /// não bloqueia.
    /// </summary>
    [Fact]
    public async Task Rn011_destino_fora_do_escopo_nao_e_inspecionado()
    {
        var path = _workspace.WriteText("vazamento.txt", "CPF: 529.982.247-25");
        var result = await InspectAsync(
            TestWorkspace.Operation(path, DestinationKind.OutOfScope, destinationPath: @"C:\Temp"));

        Assert.False(result.InScope);
        Assert.Equal("out_of_scope", result.Reason);
        Assert.NotEqual(Verdict.Blocked, result.Verdict);
    }

    /// <summary>
    /// Extensão fora da política também sai de escopo, mesmo com destino
    /// monitorado.
    /// </summary>
    [Fact]
    public async Task Rn011_extensao_fora_da_politica_nao_e_inspecionada()
    {
        var path = _workspace.WriteText("notas.md", "CPF: 529.982.247-25");
        var result = await InspectAsync(TestWorkspace.Operation(path));

        Assert.False(result.InScope);
        Assert.Equal("out_of_scope", result.Reason);
    }

    /// <summary>
    /// Operação fora de escopo não entra na trilha de auditoria: registrar
    /// cada arquivo deliberadamente ignorado afogaria os eventos que importam.
    /// </summary>
    [Fact]
    public async Task Fora_de_escopo_nao_gera_evento_de_auditoria()
    {
        var path = _workspace.WriteText("vazamento.txt", "CPF: 529.982.247-25");
        await InspectAsync(TestWorkspace.Operation(path, DestinationKind.OutOfScope));

        Assert.Empty(await _sink.ReadRecentAsync(50, CancellationToken.None));
    }

    /// <summary>
    /// RN-013 — acima do limite libera sem inspecionar. O arquivo do teste
    /// contém um CPF, para deixar claro que a decisão é pelo tamanho e que
    /// nada foi lido.
    /// </summary>
    [Fact]
    public async Task Rn013_arquivo_grande_demais_e_liberado_sem_inspecao()
    {
        var path = _workspace.WriteText("grande.txt", "CPF: 529.982.247-25");
        var operation = TestWorkspace.Operation(path, sizeBytes: 25L * 1024 * 1024);

        var result = await InspectAsync(operation);

        Assert.Equal(Verdict.AllowedWithoutInspection, result.Verdict);
        Assert.Equal("file_too_large", result.Reason);
        Assert.Empty(result.Findings);
    }

    /// <summary>
    /// RN-013 — sem extrator para o formato, libera sem inspecionar.
    /// </summary>
    [Fact]
    public async Task Rn013_formato_nao_suportado_e_liberado_sem_inspecao()
    {
        var path = _workspace.WriteText("planilha.txt", "CPF: 529.982.247-25");

        // Registro sem o extrator de texto: a extensão continua em escopo pela
        // política, mas não há como ler o conteúdo.
        var registry = new ExtractorRegistry([new OpenXmlWordExtractor()]);
        var result = await Service(registry).InspectAsync(
            TestWorkspace.Operation(path), CancellationToken.None);

        Assert.Equal(Verdict.AllowedWithoutInspection, result.Verdict);
        Assert.Equal("unsupported_format", result.Reason);
    }

    /// <summary>
    /// RN-012 — arquivo cuja extensão mente sobre o formato quebra o parser, e
    /// a quebra libera em vez de bloquear.
    /// </summary>
    [Fact]
    public async Task Rn012_erro_de_parsing_libera_e_registra_o_motivo()
    {
        var path = _workspace.WriteText("falso.docx", "isto nao e um documento do Word");
        var result = await InspectAsync(TestWorkspace.Operation(path));

        Assert.Equal(Verdict.AllowedWithoutInspection, result.Verdict);
        Assert.StartsWith("parse_error:", result.Reason, StringComparison.Ordinal);
    }

    /// <summary>
    /// O motivo do parse_error leva o tipo da exceção, nunca a mensagem:
    /// mensagem de parser costuma citar trecho do conteúdo do arquivo, e o
    /// motivo vai para o log.
    /// </summary>
    [Fact]
    public async Task Motivo_do_erro_nao_carrega_a_mensagem_da_excecao()
    {
        var registry = new ExtractorRegistry([new ExtratorQueVaza()]);
        var path = _workspace.WriteText("qualquer.txt", "conteudo");

        var result = await Service(registry).InspectAsync(
            TestWorkspace.Operation(path), CancellationToken.None);

        Assert.Equal("parse_error:InvalidDataException", result.Reason);
        Assert.DoesNotContain("529", result.Reason, StringComparison.Ordinal);
    }

    /// <summary>
    /// RN-012 — a inspeção que não termina no prazo libera a operação. O
    /// extrator lento simula o travamento do serviço.
    /// </summary>
    [Fact]
    public async Task Rn012_timeout_libera_a_operacao()
    {
        var registry = new ExtractorRegistry([new ExtratorLento()]);
        var path = _workspace.WriteText("lento.txt", "CPF: 529.982.247-25");

        var stopwatch = Stopwatch.StartNew();
        var result = await Service(registry).InspectAsync(
            TestWorkspace.Operation(path), CancellationToken.None);
        stopwatch.Stop();

        Assert.Equal(Verdict.AllowedWithoutInspection, result.Verdict);
        Assert.Equal("inspection_timeout", result.Reason);

        // O corte tem de acontecer no prazo da política (5 s), e não ao fim
        // dos 8 s do extrator travado.
        Assert.InRange(stopwatch.ElapsedMilliseconds, 4_500, 7_000);
    }

    /// <summary>
    /// Segunda avaliação do mesmo arquivo vem do cache, com o mesmo veredito e
    /// dentro do limite de desempenho de 10 ms.
    /// </summary>
    [Fact]
    public async Task Cache_responde_a_segunda_avaliacao()
    {
        var path = _workspace.WriteText("repetido.txt", "CPF: 529.982.247-25");
        var operation = TestWorkspace.Operation(path);
        var service = Service();

        var primeira = await service.InspectAsync(operation, CancellationToken.None);
        var segunda = await service.InspectAsync(operation, CancellationToken.None);

        Assert.False(primeira.FromCache);
        Assert.True(segunda.FromCache);
        Assert.Equal(primeira.Verdict, segunda.Verdict);
        Assert.Equal(Verdict.Blocked, segunda.Verdict);
        Assert.True(segunda.ElapsedMs < 10, $"acerto de cache levou {segunda.ElapsedMs} ms");
    }

    /// <summary>
    /// O acerto de cache também é auditado: a operação aconteceu e precisa
    /// aparecer na trilha, ainda que a decisão tenha sido reaproveitada.
    /// </summary>
    [Fact]
    public async Task Acerto_de_cache_tambem_e_auditado()
    {
        var path = _workspace.WriteText("repetido.txt", "CPF: 529.982.247-25");
        var operation = TestWorkspace.Operation(path);
        var service = Service();

        await service.InspectAsync(operation, CancellationToken.None);
        await service.InspectAsync(operation, CancellationToken.None);

        var eventos = await _sink.ReadRecentAsync(50, CancellationToken.None);

        Assert.Equal(2, eventos.Count);
        Assert.All(eventos, e => Assert.Equal(Verdict.Blocked, e.Verdict));
    }

    /// <summary>
    /// O ponto perigoso do cache: editar o arquivo para incluir um CPF não
    /// pode reaproveitar o "aprovado" anterior. Tamanho e data de modificação
    /// fazem parte da chave justamente por isso.
    /// </summary>
    [Fact]
    public async Task Cache_nao_reaproveita_veredito_de_arquivo_editado()
    {
        var path = _workspace.WriteText("editado.txt", "Relatorio limpo.");
        var service = Service();

        var antes = await service.InspectAsync(TestWorkspace.Operation(path), CancellationToken.None);
        Assert.Equal(Verdict.Approved, antes.Verdict);

        await File.WriteAllTextAsync(path, "CPF: 529.982.247-25", CancellationToken.None);
        var depois = await service.InspectAsync(TestWorkspace.Operation(path), CancellationToken.None);

        Assert.Equal(Verdict.Blocked, depois.Verdict);
        Assert.False(depois.FromCache);
    }

    /// <summary>
    /// Mudança de política precisa valer na hora. Uma entrada gravada sob outra
    /// versão não pode continuar respondendo enquanto o cache não expira.
    /// </summary>
    [Fact]
    public async Task Cache_e_invalidado_quando_a_politica_muda_de_versao()
    {
        _workspace.WritePolicy(PolicyJson(version: 1, categorias: "\"Cnpj\""));

        var path = _workspace.WriteText("documento.txt", "CPF: 529.982.247-25");
        var operation = TestWorkspace.Operation(path);
        var service = Service();

        var comCpfDesligado = await service.InspectAsync(operation, CancellationToken.None);
        Assert.Equal(Verdict.Approved, comCpfDesligado.Verdict);

        // O administrador liga o CPF e publica uma versão nova.
        _workspace.WritePolicy(PolicyJson(version: 2, categorias: "\"Cnpj\", \"Cpf\""));

        var comCpfLigado = await service.InspectAsync(operation, CancellationToken.None);

        Assert.False(comCpfLigado.FromCache);
        Assert.Equal(Verdict.Blocked, comCpfLigado.Verdict);
    }

    /// <summary>
    /// A duração é medida em toda decisão e é o que demonstra os requisitos de
    /// desempenho: análise completa bem abaixo de 3 s.
    /// </summary>
    [Fact]
    public async Task Duracao_da_analise_completa_fica_abaixo_do_limite()
    {
        var path = _workspace.WriteText("medido.txt", "CPF: 529.982.247-25");
        var result = await InspectAsync(TestWorkspace.Operation(path));

        Assert.True(result.ElapsedMs < 3_000, $"analise completa levou {result.ElapsedMs} ms");
    }

    /// <summary>
    /// Falha ao gravar a auditoria não pode mudar o veredito nem derrubar a
    /// operação do usuário.
    /// </summary>
    [Fact]
    public async Task Falha_ao_auditar_nao_altera_o_veredito()
    {
        var service = new InspectionService(
            _policies, new SinkQueFalha(), ExtractorRegistry.CreateDefault(), _cache, "PC", "usuario");

        var path = _workspace.WriteText("vazamento.txt", "CPF: 529.982.247-25");
        var result = await service.InspectAsync(TestWorkspace.Operation(path), CancellationToken.None);

        Assert.Equal(Verdict.Blocked, result.Verdict);
    }

    private static string PolicyJson(int version, string categorias) => $$"""
        {
          "version": {{version}},
          "activeCategories": [{{categorias}}],
          "monitoredScopes": { "extensions": [".txt"], "destinationPaths": [], "removableDrives": true, "networkPaths": true },
          "maxFileSizeMb": 20,
          "inspectionTimeoutSeconds": 5,
          "failOpen": true,
          "excludedProcesses": ["System", "SafeUpload.Agent.App"]
        }
        """;

    /// <summary>Extrator que não termina dentro do prazo da política.</summary>
    private sealed class ExtratorLento : ITextExtractor
    {
        public IReadOnlySet<string> SupportedExtensions { get; } = new HashSet<string> { ".txt" };

        public async Task<string> ExtractAsync(Stream content, CancellationToken cancellationToken)
        {
            await Task.Delay(TimeSpan.FromSeconds(8), CancellationToken.None);
            return string.Empty;
        }
    }

    /// <summary>
    /// Extrator cuja exceção traz conteúdo do arquivo na mensagem, como fazem
    /// vários parsers reais.
    /// </summary>
    private sealed class ExtratorQueVaza : ITextExtractor
    {
        public IReadOnlySet<string> SupportedExtensions { get; } = new HashSet<string> { ".txt" };

        public Task<string> ExtractAsync(Stream content, CancellationToken cancellationToken) =>
            throw new InvalidDataException("token inesperado perto de 529.982.247-25");
    }

    /// <summary>Trilha de auditoria indisponível.</summary>
    private sealed class SinkQueFalha : IAuditSink
    {
        public Task WriteAsync(AuditEvent auditEvent, CancellationToken cancellationToken) =>
            throw new IOException("disco cheio");

        public Task<IReadOnlyList<AuditEvent>> ReadRecentAsync(int maxEvents, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<AuditEvent>>([]);

        public Task<IReadOnlyList<AuditEvent>> ReadPendingAsync(int maxEvents, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<AuditEvent>>([]);

        public Task MarkDispatchedAsync(IReadOnlyCollection<Guid> eventIds, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }
}
