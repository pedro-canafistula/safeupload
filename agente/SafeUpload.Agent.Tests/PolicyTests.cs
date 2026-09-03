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
        Assert.Equal(4, policy.ActiveCategories.Count);
        Assert.Equal(20, policy.MaxFileSizeMb);
        Assert.Equal(20L * 1024 * 1024, policy.MaxFileSizeBytes);
        Assert.Equal(TimeSpan.FromSeconds(5), policy.InspectionTimeout);
        Assert.True(policy.FailOpen);
    }

    [Fact]
    public async Task Politica_padrao_vigia_os_quatro_formatos()
    {
        var policy = await LoadAsync();

        Assert.True(policy.IsMonitoredExtension(".txt"));
        Assert.True(policy.IsMonitoredExtension(".csv"));
        Assert.True(policy.IsMonitoredExtension(".docx"));
        Assert.True(policy.IsMonitoredExtension(".xlsx"));
        Assert.False(policy.IsMonitoredExtension(".pdf"));
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
