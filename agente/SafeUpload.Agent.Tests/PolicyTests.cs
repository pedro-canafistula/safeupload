using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// Carregamento da política (HU-07) e as regras de escopo e exclusão que ela
/// carrega: RN-009, RN-011 e RN-014.
/// </summary>
public class PolicyTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();

    /// <inheritdoc />
    public void Dispose() => _workspace.Dispose();

    private Task<Policy> LoadAsync() =>
        new LocalPolicyStore(_workspace.PolicyFile).LoadAsync(CancellationToken.None);

    [Fact]
    public async Task Politica_padrao_e_criada_quando_o_arquivo_nao_existe()
    {
        Assert.False(File.Exists(_workspace.PolicyFile));

        var policy = await LoadAsync();

        Assert.True(File.Exists(_workspace.PolicyFile));
        Assert.Equal(1, policy.Version);
        // Cinco desde que Secret entrou. Vale afirmar o numero e nao so
        // conferir uma a uma: se uma categoria nova aparecer sem passar por
        // aqui, ela esta ativa na politica padrao sem ninguem ter decidido.
        Assert.Equal(5, policy.ActiveCategories.Count);
        Assert.Equal(20, policy.MaxFileSizeMb);
        Assert.Equal(20L * 1024 * 1024, policy.MaxFileSizeBytes);
        Assert.Equal(TimeSpan.FromSeconds(5), policy.InspectionTimeout);
        Assert.True(policy.FailOpen);
    }

    /// <summary>
    /// O .pdf entrou na política padrão junto com seu extrator, e a ordem
    /// importa: monitorar uma extensão sem saber abri-la faz o driver mandar
    /// requisições que o motor não tem como responder.
    /// </summary>
    [Fact]
    public async Task Politica_padrao_vigia_os_cinco_formatos()
    {
        var policy = await LoadAsync();

        Assert.True(policy.IsMonitoredExtension(".txt"));
        Assert.True(policy.IsMonitoredExtension(".csv"));
        Assert.True(policy.IsMonitoredExtension(".docx"));
        Assert.True(policy.IsMonitoredExtension(".xlsx"));
        Assert.True(policy.IsMonitoredExtension(".pdf"));

        Assert.False(policy.IsMonitoredExtension(".zip"));
    }

    /// <summary>
    /// As variáveis de ambiente do arquivo precisam chegar expandidas ao
    /// domínio, que compara caminhos e não interpreta configuração.
    /// </summary>
    [Fact]
    public async Task Caminhos_monitorados_chegam_expandidos()
    {
        _workspace.WritePolicy("""
            {
              "version": 1,
              "activeCategories": ["Cpf"],
              "monitoredScopes": { "extensions": [".txt"], "destinationPaths": ["%USERPROFILE%\\Documentos"] },
              "maxFileSizeMb": 20,
              "inspectionTimeoutSeconds": 5
            }
            """);

        var policy = await LoadAsync();
        var monitorado = Assert.Single(policy.MonitoredScopes.DestinationPaths);

        Assert.DoesNotContain('%', monitorado);
        Assert.EndsWith(@"\Documentos", monitorado, StringComparison.Ordinal);
    }

    /// <summary>
    /// O escopo padrão precisa ser um caminho de máquina, e não do perfil do
    /// usuário.
    ///
    /// Quem lê esta política é um serviço rodando como LocalSystem. Nesse
    /// contexto <c>%USERPROFILE%</c> aponta para o perfil da conta de sistema, e
    /// não para o de quem está usando a máquina: o serviço passaria a vigiar
    /// uma pasta que ninguém enxerga e nunca interceptaria nada. O teste
    /// existe para que ninguém volte o padrão para o perfil sem perceber.
    /// </summary>
    [Fact]
    public async Task Escopo_padrao_e_caminho_de_maquina()
    {
        var policy = await LoadAsync();
        var monitorado = Assert.Single(policy.MonitoredScopes.DestinationPaths);

        Assert.Equal(AgentPaths.MonitoredFolder, monitorado);
        Assert.True(Path.IsPathRooted(monitorado));
        Assert.DoesNotContain("Users", monitorado, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Escopo Monitorado", monitorado, StringComparison.Ordinal);
    }

    /// <summary>
    /// A quarentena acompanha o escopo, na mesma raiz de máquina, e não pode
    /// ficar dentro da pasta vigiada — senão mover o arquivo bloqueado para lá
    /// dispararia uma nova interceptação em laço.
    /// </summary>
    [Fact]
    public void Quarentena_fica_fora_da_pasta_vigiada()
    {
        Assert.True(Path.IsPathRooted(AgentPaths.QuarantineFolder));
        Assert.DoesNotContain("Users", AgentPaths.QuarantineFolder, StringComparison.OrdinalIgnoreCase);
        Assert.False(
            AgentPaths.QuarantineFolder.StartsWith(AgentPaths.MonitoredFolder, StringComparison.OrdinalIgnoreCase),
            "a quarentena nao pode ficar dentro do escopo vigiado");
    }

    /// <summary>
    /// RN-009 — política sem categoria ativa é inválida e falha no
    /// carregamento, não no uso.
    /// </summary>
    [Fact]
    public async Task Rn009_politica_sem_categoria_ativa_lanca_ao_carregar()
    {
        _workspace.WritePolicy("""
            {
              "version": 3,
              "activeCategories": [],
              "monitoredScopes": { "extensions": [".txt"], "destinationPaths": [], "removableDrives": true, "networkPaths": true },
              "maxFileSizeMb": 20,
              "inspectionTimeoutSeconds": 5,
              "failOpen": true,
              "excludedProcesses": ["System"]
            }
            """);

        var exception = await Assert.ThrowsAsync<InvalidPolicyException>(LoadAsync);

        Assert.Contains("RN-009", exception.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Uma política em que todas as categorias são desconhecidas também cai na
    /// RN-009: ignorar o que não se entende não pode virar "não procure nada".
    /// </summary>
    [Fact]
    public async Task Rn009_vale_tambem_quando_todas_as_categorias_sao_desconhecidas()
    {
        _workspace.WritePolicy("""
            { "version": 4, "activeCategories": ["Biometria", "Prontuario"], "maxFileSizeMb": 20, "inspectionTimeoutSeconds": 5 }
            """);

        await Assert.ThrowsAsync<InvalidPolicyException>(LoadAsync);
    }

    /// <summary>
    /// Categoria desconhecida convivendo com categorias conhecidas é ignorada,
    /// e o agente continua funcionando. Um painel mais novo pode publicar uma
    /// categoria que esta versão ainda não implementa.
    /// </summary>
    [Fact]
    public async Task Categoria_desconhecida_e_ignorada_sem_derrubar_o_agente()
    {
        _workspace.WritePolicy("""
            { "version": 5, "activeCategories": ["Cpf", "Biometria"], "maxFileSizeMb": 20, "inspectionTimeoutSeconds": 5 }
            """);

        var policy = await LoadAsync();

        Assert.Equal(Category.Cpf, Assert.Single(policy.ActiveCategories));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public async Task Limite_de_tamanho_invalido_e_rejeitado(int megabytes)
    {
        _workspace.WritePolicy($$"""
            { "version": 1, "activeCategories": ["Cpf"], "maxFileSizeMb": {{megabytes}}, "inspectionTimeoutSeconds": 5 }
            """);

        await Assert.ThrowsAsync<InvalidPolicyException>(LoadAsync);
    }

    [Fact]
    public async Task Timeout_invalido_e_rejeitado()
    {
        _workspace.WritePolicy("""
            { "version": 1, "activeCategories": ["Cpf"], "maxFileSizeMb": 20, "inspectionTimeoutSeconds": 0 }
            """);

        await Assert.ThrowsAsync<InvalidPolicyException>(LoadAsync);
    }

    /// <summary>
    /// RN-014 — o próprio agente nunca é interceptado, com ou sem o sufixo
    /// .exe. Sem isso, a leitura que o agente faz do arquivo dispararia uma
    /// nova inspeção.
    /// </summary>
    [Theory]
    [InlineData("SafeUpload.Agent.App", true)]
    [InlineData("SafeUpload.Agent.App.exe", true)]
    [InlineData("safeupload.agent.app.exe", true)]
    [InlineData("System", true)]
    [InlineData("explorer.exe", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public async Task Rn014_processos_excluidos(string? processName, bool expected)
    {
        var policy = await LoadAsync();

        Assert.Equal(expected, policy.IsExcludedProcess(processName));
    }

    /// <summary>
    /// RN-011 — mídia removível e rede entram em escopo pelas chaves da
    /// política; nuvem entra pelo caminho monitorado.
    /// </summary>
    [Fact]
    public async Task Rn011_destinos_monitorados_pela_politica_padrao()
    {
        var policy = await LoadAsync();
        var monitorado = policy.MonitoredScopes.DestinationPaths[0];
        var arquivo = _workspace.WriteText("dados.txt", "vazio");

        Assert.True(policy.IsMonitoredDestination(
            TestWorkspace.Operation(arquivo, DestinationKind.RemovableDrive)));

        Assert.True(policy.IsMonitoredDestination(
            TestWorkspace.Operation(arquivo, DestinationKind.NetworkShare, destinationPath: @"\\servidor\publico")));

        Assert.True(policy.IsMonitoredDestination(TestWorkspace.Operation(
            arquivo, DestinationKind.Cloud, destinationPath: Path.Combine(monitorado, "OneDrive"))));

        Assert.False(policy.IsMonitoredDestination(
            TestWorkspace.Operation(arquivo, DestinationKind.OutOfScope, destinationPath: @"C:\Temp")));
    }

    /// <summary>
    /// RN-011 pelo outro lado: a leitura de uma origem sensível entra em
    /// escopo pela lista de origens, e não pela de destinos.
    ///
    /// Este teste existe porque a falta dele deixou passar um defeito inteiro.
    /// O motor decidia escopo só por destino, então toda leitura de origem era
    /// julgada contra os caminhos de destino, não casava nenhum e saía como
    /// fora de escopo — o arquivo nunca era aberto e a cadeia de contaminação
    /// ficava sem o primeiro elo. Os 156 testes passavam, porque nenhum
    /// perguntava isto.
    /// </summary>
    [Fact]
    public void Rn011_leitura_de_origem_sensivel_entra_em_escopo_pela_lista_de_origens()
    {
        var arquivo = _workspace.WriteText("relatorio.txt", "vazio");
        var origem = Path.GetDirectoryName(arquivo)!;

        var comOrigem = Policy(sourcePaths: [origem]);

        Assert.True(comOrigem.IsInScope(
            TestWorkspace.Operation(arquivo, DestinationKind.SensitiveSource)));

        // Sem origens configuradas a mesma leitura fica fora de escopo. É
        // configuração legítima — vigiar destinos sem manter cadeia — e o
        // resultado tem de ser esse, não um bloqueio.
        var semOrigem = Policy(sourcePaths: []);

        Assert.False(semOrigem.IsInScope(
            TestWorkspace.Operation(arquivo, DestinationKind.SensitiveSource)));

        // Uma origem que não cobre este arquivo também não vale.
        var outraOrigem = Policy(sourcePaths: [Path.Combine(origem, "outra-pasta")]);

        Assert.False(outraOrigem.IsInScope(
            TestWorkspace.Operation(arquivo, DestinationKind.SensitiveSource)));
    }

    /// <summary>
    /// A lista de origens não muda o julgamento de destino: os dois lados são
    /// independentes, e uma origem configurada não pode fazer entrar em escopo
    /// uma cópia para lugar nenhum.
    /// </summary>
    [Fact]
    public void Origem_configurada_nao_altera_o_julgamento_de_destino()
    {
        var arquivo = _workspace.WriteText("dados.txt", "vazio");
        var policy = Policy(sourcePaths: [Path.GetDirectoryName(arquivo)!]);

        Assert.False(policy.IsInScope(TestWorkspace.Operation(
            arquivo, DestinationKind.OutOfScope, destinationPath: @"C:\Temp")));

        Assert.True(policy.IsInScope(
            TestWorkspace.Operation(arquivo, DestinationKind.RemovableDrive)));
    }

    /// <summary>
    /// O modo auditoria sai do policy.json e chega ao domínio.
    ///
    /// Vale um teste porque o campo atravessa quatro camadas até virar
    /// comportamento — JSON, domínio, política do driver e a decisão no
    /// kernel — e um elo perdido no caminho não produz erro nenhum: produz
    /// uma máquina que alguém acha que está auditando e está bloqueando, ou
    /// o contrário, que é pior.
    /// </summary>
    [Fact]
    public async Task Modo_auditoria_vem_do_arquivo_de_politica()
    {
        var padrao = await LoadAsync();

        Assert.False(padrao.AuditOnly);

        await File.WriteAllTextAsync(_workspace.PolicyFile, """
            {
              "version": 7,
              "activeCategories": [ "Cpf" ],
              "auditOnly": true
            }
            """);

        var auditoria = await LoadAsync();

        Assert.True(auditoria.AuditOnly);
    }

    private static Policy Policy(IReadOnlyList<string> sourcePaths) =>
        new(
            Version: 1,
            ActiveCategories: new HashSet<Category> { Category.Cpf },
            MonitoredScopes: new MonitoredScopes(
                new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".txt" },
                [@"C:\destino-vigiado"],
                RemovableDrives: true,
                NetworkPaths: true,
                SourcePaths: sourcePaths),
            MaxFileSizeMb: 20,
            InspectionTimeoutSeconds: 5,
            FailOpen: true,
            ExcludedProcesses: new HashSet<string>(StringComparer.OrdinalIgnoreCase));

    /// <summary>
    /// Nuvem fora dos caminhos monitorados não entra em escopo: é uma pasta
    /// local como outra qualquer.
    /// </summary>
    [Fact]
    public async Task Rn011_nuvem_fora_do_caminho_monitorado_nao_entra_em_escopo()
    {
        var policy = await LoadAsync();
        var arquivo = _workspace.WriteText("dados.txt", "vazio");

        Assert.False(policy.IsMonitoredDestination(TestWorkspace.Operation(
            arquivo, DestinationKind.Cloud, destinationPath: @"C:\Users\alguem\Dropbox")));
    }

    /// <summary>
    /// Desligar mídia removível na política tira o destino do escopo, sem
    /// tocar em código.
    /// </summary>
    [Fact]
    public async Task Rn011_politica_pode_desligar_midia_removivel()
    {
        _workspace.WritePolicy("""
            {
              "version": 9,
              "activeCategories": ["Cpf"],
              "monitoredScopes": { "extensions": [".txt"], "destinationPaths": [], "removableDrives": false, "networkPaths": false },
              "maxFileSizeMb": 20,
              "inspectionTimeoutSeconds": 5
            }
            """);

        var policy = await LoadAsync();
        var arquivo = _workspace.WriteText("dados.txt", "vazio");

        Assert.False(policy.IsMonitoredDestination(
            TestWorkspace.Operation(arquivo, DestinationKind.RemovableDrive)));
        Assert.False(policy.IsMonitoredDestination(
            TestWorkspace.Operation(arquivo, DestinationKind.NetworkShare)));
    }
}
