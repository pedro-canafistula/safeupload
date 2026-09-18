using System.Text.Json.Serialization;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Infrastructure;

/// <summary>
/// O formato JSON da política, e a tradução dele para o domínio.
///
/// Vive separado das duas IPolicyStore porque as duas leem o MESMO formato: o
/// arquivo local em %ProgramData% e a resposta do Centro de Administração são
/// o mesmo documento, só que por transportes diferentes. Duplicar o
/// mapeamento faria com que uma mudança de schema precisasse ser lembrada em
/// dois lugares — e a que fosse esquecida só apareceria em produção, na forma
/// de uma política silenciosamente pela metade.
///
/// O domínio não conhece JSON; manter a tradução aqui deixa o formato livre
/// para evoluir (renomear chave, aceitar formato antigo) sem tocar em Policy.
/// </summary>
internal sealed record PolicyDocument
{
    [JsonPropertyName("version")]
    public int Version { get; init; } = 1;

    [JsonPropertyName("activeCategories")]
    public string[]? ActiveCategories { get; init; }

    [JsonPropertyName("monitoredScopes")]
    public MonitoredScopesDocument? MonitoredScopes { get; init; }

    [JsonPropertyName("maxFileSizeMb")]
    public int MaxFileSizeMb { get; init; } = 20;

    [JsonPropertyName("inspectionTimeoutSeconds")]
    public int InspectionTimeoutSeconds { get; init; } = 5;

    [JsonPropertyName("auditOnly")]
    public bool AuditOnly { get; init; }

    [JsonPropertyName("overrideAllowed")]
    public bool OverrideAllowed { get; init; }

    [JsonPropertyName("failOpen")]
    public bool FailOpen { get; init; } = true;

    [JsonPropertyName("excludedProcesses")]
    public string[]? ExcludedProcesses { get; init; }

    public static PolicyDocument Default { get; } = new()
    {
        Version = 1,
        ActiveCategories = ["Cpf", "Cnpj", "PaymentCard", "Password", "Secret"],
        MonitoredScopes = MonitoredScopesDocument.Default,
        MaxFileSizeMb = 20,
        InspectionTimeoutSeconds = 5,
        FailOpen = true,
        ExcludedProcesses = ["System", "SafeUpload.Agent.App"]
    };

    /// <summary>
    /// Converte para o objeto de domínio. Não valida: quem chama decide quando
    /// aplicar a RN-009, e as duas IPolicyStore fazem isso no carregamento.
    /// </summary>
    public Policy ToPolicy()
    {
        var categories = new HashSet<Category>();
        foreach (var name in ActiveCategories ?? [])
        {
            // Categoria desconhecida no documento é ignorada em vez de derrubar
            // o agente: um painel mais novo pode publicar uma categoria que esta
            // versão ainda não implementa. Se sobrar zero, a RN-009 pega.
            if (Enum.TryParse<Category>(name, ignoreCase: true, out var category))
            {
                categories.Add(category);
            }
        }

        var scopes = MonitoredScopes ?? MonitoredScopesDocument.Default;

        var extensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var extension in scopes.Extensions ?? [])
        {
            extensions.Add(extension.StartsWith('.') ? extension : "." + extension);
        }

        var destinations = new List<string>();
        foreach (var path in scopes.DestinationPaths ?? [])
        {
            // %USERPROFILE% e afins só fazem sentido depois de expandidos; o
            // domínio compara caminhos, não interpreta variáveis de ambiente.
            destinations.Add(Environment.ExpandEnvironmentVariables(path));
        }

        var excluded = new HashSet<string>(
            ExcludedProcesses ?? [],
            StringComparer.OrdinalIgnoreCase);

        return new Policy(
            Version,
            categories,
            new MonitoredScopes(
                extensions,
                destinations,
                scopes.RemovableDrives,
                scopes.NetworkPaths,
                scopes.SourcePaths is null ? [] : [.. scopes.SourcePaths]),
            MaxFileSizeMb,
            InspectionTimeoutSeconds,
            FailOpen,
            excluded,
            AuditOnly,
            OverrideAllowed);
    }
}

/// <summary>O bloco monitoredScopes do documento de política.</summary>
internal sealed record MonitoredScopesDocument
{
    [JsonPropertyName("extensions")]
    public string[]? Extensions { get; init; }

    [JsonPropertyName("destinationPaths")]
    public string[]? DestinationPaths { get; init; }

    [JsonPropertyName("sourcePaths")]
    public string[]? SourcePaths { get; init; }

    [JsonPropertyName("removableDrives")]
    public bool RemovableDrives { get; init; } = true;

    [JsonPropertyName("networkPaths")]
    public bool NetworkPaths { get; init; } = true;

    public static MonitoredScopesDocument Default { get; } = new()
    {
        Extensions = [".txt", ".csv", ".docx", ".xlsx", ".pdf"],

        // Caminho de máquina, e não sob %USERPROFILE%: quem lê esta política é
        // um serviço rodando como LocalSystem, para quem %USERPROFILE% aponta
        // para o perfil da conta de sistema.
        DestinationPaths = [@"C:\SafeUpload\Escopo Monitorado"],
        RemovableDrives = true,
        NetworkPaths = true
    };
}
