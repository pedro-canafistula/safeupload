using System.Text.Json;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// A trilha de auditoria em disco: os campos exigidos pela HU-04 e, sobretudo,
/// a garantia da RNF-03 de que o dado original não vaza para o log.
/// </summary>
public class AuditTrailTests : IDisposable
{
    /// <summary>
    /// Os valores sensíveis do arquivo de exemplo. Ficam declarados aqui para
    /// que o teste possa provar, um a um, que nenhum deles chega ao log.
    /// </summary>
    private const string Cpf = "52998224725";

    private const string Cnpj = "11222333000181";
    private const string Cartao = "4111111111111111";
    private const string Senha = "Trocar123";

    private const string ConteudoDeExemplo = """
        Cadastro do cliente
        CPF: 529.982.247-25
        CNPJ 11.222.333/0001-81
        Cartao 4111 1111 1111 1111
        senha: Trocar123
        """;

    private readonly TestWorkspace _workspace = new();
    private readonly LocalQueueAuditSink _sink;
    private readonly LocalPolicyStore _policies;

    /// <summary>Monta a fila e a política numa pasta temporária isolada.</summary>
    public AuditTrailTests()
    {
        _sink = new LocalQueueAuditSink(_workspace.QueueFile);
        _policies = new LocalPolicyStore(_workspace.PolicyFile);
    }

    /// <inheritdoc />
    public void Dispose() => _workspace.Dispose();

    private async Task<InspectionResult> InspecionarExemploAsync(string fileName = "cadastro.txt")
    {
        var path = _workspace.WriteText(fileName, ConteudoDeExemplo);
        var service = new InspectionService(
            _policies, _sink, ExtractorRegistry.CreateDefault(), new VerdictCache(),
            endpointId: "PC-TESTE", userName: "usuario.teste");

        return await service.InspectAsync(TestWorkspace.Operation(path), CancellationToken.None);
    }

    /// <summary>
    /// HU-04 — todo campo exigido precisa estar na linha gravada, com o nome
    /// combinado. O Centro de Administração vai ler exatamente estas chaves.
    /// </summary>
    [Fact]
    public async Task Hu04_evento_tem_todos_os_campos_exigidos()
    {
        await InspecionarExemploAsync();

        var linha = Assert.Single(await File.ReadAllLinesAsync(_workspace.QueueFile, CancellationToken.None));
        using var documento = JsonDocument.Parse(linha);
        var raiz = documento.RootElement;

        string[] exigidos =
        [
            "eventId", "occurredAtUtc", "endpointId", "userName", "fileName", "extension",
            "sizeBytes", "verdict", "categories", "maskedSnippets", "processName", "processId",
            "destinationPath", "notInspectedReason", "policyVersion", "elapsedMs", "dispatched"
        ];

        foreach (var campo in exigidos)
        {
            Assert.True(raiz.TryGetProperty(campo, out _), $"campo ausente na linha de auditoria: {campo}");
        }
    }

    /// <summary>
    /// Todo evento nasce pendente de envio. O despachante da HU-10 é quem vai
    /// marcar verdadeiro, e ele ainda não existe.
    /// </summary>
    [Fact]
    public async Task Evento_nasce_com_dispatched_falso()
    {
        await InspecionarExemploAsync();

        var evento = Assert.Single(await _sink.ReadRecentAsync(10, CancellationToken.None));

        Assert.False(evento.Dispatched);
        Assert.Equal(Verdict.Blocked, evento.Verdict);
        Assert.Equal("cadastro.txt", evento.FileName);
        Assert.Equal(".txt", evento.Extension);
        Assert.Equal("PC-TESTE", evento.EndpointId);
        Assert.Null(evento.NotInspectedReason);
    }

    /// <summary>
    /// RNF-03 — o log não pode conter o dado original.
    ///
    /// A verificação é feita sobre o texto cru do queue.jsonl, e não sobre os
    /// objetos já desserializados: o que interessa é o que ficou gravado em
    /// disco, incluindo qualquer campo que alguém venha a acrescentar sem
    /// perceber que ele carrega conteúdo.
    ///
    /// Testar a ausência de trechos de seis dígitos ou mais, e não de três, é
    /// deliberado. A linha contém identificadores, carimbo de tempo e tamanhos,
    /// todos cheios de dígitos, e um trecho curto colidiria com eles por acaso,
    /// tornando o teste instável sem provar nada. Seis dígitos consecutivos do
    /// documento original não aparecem por acidente. O limite de dois dígitos
    /// da RN-007 é verificado logo abaixo, diretamente nos trechos mascarados.
    /// </summary>
    [Fact]
    public async Task Rnf03_nenhum_valor_original_aparece_no_queue_jsonl()
    {
        await InspecionarExemploAsync();

        var conteudoDoLog = await File.ReadAllTextAsync(_workspace.QueueFile, CancellationToken.None);

        // Os valores inteiros, como aparecem no arquivo e sem formatação.
        string[] valoresLiterais =
        [
            Cpf, "529.982.247-25",
            Cnpj, "11.222.333/0001-81",
            Cartao, "4111 1111 1111 1111",
            Senha
        ];

        foreach (var valor in valoresLiterais)
        {
            Assert.DoesNotContain(valor, conteudoDoLog, StringComparison.OrdinalIgnoreCase);
        }

        // E nenhum pedaço longo o bastante para reconstruí-los.
        foreach (var digitos in new[] { Cpf, Cnpj, Cartao })
        {
            foreach (var trecho in SubsequenciasDe(digitos, comprimentoMinimo: 6))
            {
                Assert.DoesNotContain(trecho, conteudoDoLog, StringComparison.Ordinal);
            }
        }
    }

    /// <summary>
    /// RN-007 no que foi efetivamente gravado: cada trecho mascarado carrega no
    /// máximo dois dígitos, e eles são os dois últimos do valor original.
    /// </summary>
    [Fact]
    public async Task Rn007_trechos_gravados_preservam_no_maximo_dois_digitos()
    {
        await InspecionarExemploAsync();

        var evento = Assert.Single(await _sink.ReadRecentAsync(10, CancellationToken.None));

        Assert.Equal(4, evento.MaskedSnippets.Count);

        foreach (var trecho in evento.MaskedSnippets)
        {
            var digitos = trecho.Count(char.IsAsciiDigit);
            Assert.True(digitos <= 2, $"o trecho '{trecho}' preserva {digitos} dígitos");
        }

        Assert.Contains("•••••••••25", evento.MaskedSnippets);
        Assert.Contains("senha: ••••••••", evento.MaskedSnippets);
    }

    /// <summary>
    /// As quatro categorias precisam chegar ao log, porque é o que o painel
    /// agrega. Elas identificam o tipo de dado, nunca o dado.
    /// </summary>
    [Fact]
    public async Task Categorias_encontradas_chegam_ao_log()
    {
        await InspecionarExemploAsync();

        var evento = Assert.Single(await _sink.ReadRecentAsync(10, CancellationToken.None));

        Assert.Equal(
            [Category.Cpf, Category.Cnpj, Category.PaymentCard, Category.Password],
            evento.Categories);
    }

    /// <summary>
    /// O motivo de não ter inspecionado é registrado, porque é o que explica
    /// depois por que uma operação passou sem análise (RN-012 e RN-013).
    /// </summary>
    [Fact]
    public async Task Motivo_de_nao_inspecao_e_registrado()
    {
        var path = _workspace.WriteText("grande.txt", ConteudoDeExemplo);
        var service = new InspectionService(
            _policies, _sink, ExtractorRegistry.CreateDefault(), new VerdictCache(), "PC-TESTE", "usuario.teste");

        await service.InspectAsync(
            TestWorkspace.Operation(path, sizeBytes: 25L * 1024 * 1024), CancellationToken.None);

        var evento = Assert.Single(await _sink.ReadRecentAsync(10, CancellationToken.None));

        Assert.Equal("file_too_large", evento.NotInspectedReason);
        Assert.Equal(Verdict.AllowedWithoutInspection, evento.Verdict);
        Assert.Empty(evento.MaskedSnippets);
    }

    /// <summary>
    /// Arquivo liberado sem inspeção não pode deixar rastro do conteúdo no log,
    /// já que nem chegou a ser lido.
    /// </summary>
    [Fact]
    public async Task Arquivo_nao_inspecionado_nao_deixa_conteudo_no_log()
    {
        var path = _workspace.WriteText("grande.txt", ConteudoDeExemplo);
        var service = new InspectionService(
            _policies, _sink, ExtractorRegistry.CreateDefault(), new VerdictCache(), "PC-TESTE", "usuario.teste");

        await service.InspectAsync(
            TestWorkspace.Operation(path, sizeBytes: 25L * 1024 * 1024), CancellationToken.None);

        var conteudoDoLog = await File.ReadAllTextAsync(_workspace.QueueFile, CancellationToken.None);

        Assert.DoesNotContain(Cpf, conteudoDoLog, StringComparison.Ordinal);
        Assert.DoesNotContain(Senha, conteudoDoLog, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// A fila é append-only: cada operação acrescenta uma linha e as anteriores
    /// permanecem intactas.
    /// </summary>
    [Fact]
    public async Task Fila_acumula_uma_linha_por_operacao()
    {
        await InspecionarExemploAsync("primeiro.txt");
        await InspecionarExemploAsync("segundo.txt");

        var linhas = await File.ReadAllLinesAsync(_workspace.QueueFile, CancellationToken.None);

        Assert.Equal(2, linhas.Length);
        Assert.All(linhas, linha => Assert.NotNull(JsonDocument.Parse(linha)));
    }

    /// <summary>
    /// Uma linha truncada por queda no meio da gravação não pode levar a trilha
    /// inteira junto. É a razão de ser do formato JSON Lines aqui.
    /// </summary>
    [Fact]
    public async Task Linha_corrompida_nao_impede_a_leitura_do_restante()
    {
        await InspecionarExemploAsync();
        await File.AppendAllTextAsync(
            _workspace.QueueFile, "{\"eventId\":\"linha truncada" + Environment.NewLine, CancellationToken.None);

        var eventos = await _sink.ReadRecentAsync(10, CancellationToken.None);

        Assert.Single(eventos);
    }

    /// <summary>
    /// Contraparte de leitura do futuro despachante da HU-10: os eventos
    /// confirmados passam a dispatched verdadeiro e saem da lista de pendentes.
    /// </summary>
    [Fact]
    public async Task Evento_marcado_como_despachado_sai_dos_pendentes()
    {
        await InspecionarExemploAsync("primeiro.txt");
        await InspecionarExemploAsync("segundo.txt");

        var pendentes = await _sink.ReadPendingAsync(10, CancellationToken.None);
        Assert.Equal(2, pendentes.Count);

        await _sink.MarkDispatchedAsync([pendentes[0].EventId], CancellationToken.None);

        var restantes = await _sink.ReadPendingAsync(10, CancellationToken.None);

        Assert.Single(restantes);
        Assert.DoesNotContain(restantes, e => e.EventId == pendentes[0].EventId);
        Assert.Equal(2, (await _sink.ReadRecentAsync(10, CancellationToken.None)).Count);
    }

    /// <summary>
    /// Todas as subsequências contíguas de <paramref name="digitos"/> com pelo
    /// menos <paramref name="comprimentoMinimo"/> caracteres.
    /// </summary>
    private static IEnumerable<string> SubsequenciasDe(string digitos, int comprimentoMinimo)
    {
        for (var comprimento = comprimentoMinimo; comprimento <= digitos.Length; comprimento++)
        {
            for (var inicio = 0; inicio + comprimento <= digitos.Length; inicio++)
            {
                yield return digitos.Substring(inicio, comprimento);
            }
        }
    }
}
