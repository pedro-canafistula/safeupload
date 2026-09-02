namespace SafeUpload.Agent.Core.Domain;

/// <summary>
/// Lançada quando uma política é inválida. A causa mais importante é a RN-009:
/// política sem nenhuma categoria ativa.
/// </summary>
public sealed class InvalidPolicyException : Exception
{
    /// <summary>Cria a exceção com a explicação do que está inválido.</summary>
    public InvalidPolicyException(string message) : base(message)
    {
    }
}

/// <summary>
/// Onde a política manda vigiar (RN-011).
/// </summary>
/// <param name="Extensions">Extensões inspecionadas, com ponto.</param>
/// <param name="DestinationPaths">Pastas monitoradas, com variáveis já expandidas.</param>
/// <param name="RemovableDrives">Se mídia removível entra em escopo.</param>
/// <param name="NetworkPaths">Se destino de rede entra em escopo.</param>
public sealed record MonitoredScopes(
    IReadOnlySet<string> Extensions,
    IReadOnlyList<string> DestinationPaths,
    bool RemovableDrives,
    bool NetworkPaths);

/// <summary>
/// A política vigente no endpoint.
///
/// É um objeto de domínio puro: não sabe de qual arquivo veio nem em que
/// formato estava. Quem carrega é a IPolicyStore, hoje a partir de um JSON
/// local e amanhã do Centro de Administração.
/// </summary>
/// <param name="Version">Versão da política, ecoada em todo evento de auditoria.</param>
/// <param name="ActiveCategories">Categorias que devem ser procuradas.</param>
/// <param name="MonitoredScopes">Destinos e extensões vigiados.</param>
/// <param name="MaxFileSizeMb">Acima disto não se inspeciona (RN-013).</param>
/// <param name="InspectionTimeoutSeconds">Tempo máximo de inspeção (RN-012).</param>
/// <param name="FailOpen">Se falha libera a operação. No projeto isto é sempre verdadeiro.</param>
/// <param name="ExcludedProcesses">Processos nunca interceptados (RN-014).</param>
public sealed record Policy(
    int Version,
    IReadOnlySet<Category> ActiveCategories,
    MonitoredScopes MonitoredScopes,
    int MaxFileSizeMb,
    int InspectionTimeoutSeconds,
    bool FailOpen,
    IReadOnlySet<string> ExcludedProcesses)
{
    /// <summary>Limite da RN-013 convertido para bytes.</summary>
    public long MaxFileSizeBytes => (long)MaxFileSizeMb * 1024 * 1024;

    /// <summary>Limite da RN-012 como intervalo.</summary>
    public TimeSpan InspectionTimeout => TimeSpan.FromSeconds(InspectionTimeoutSeconds);

    /// <summary>
    /// RN-009 — categoria mínima. Uma política sem categoria ativa não protege
    /// nada: ela aprovaria todo arquivo e ainda registraria os eventos como se
    /// tivesse inspecionado, o que é pior do que não ter agente, porque produz
    /// uma auditoria que parece limpa. Por isso é configuração inválida, e não
    /// um modo de operação com tudo desligado.
    /// </summary>
    /// <exception cref="InvalidPolicyException">Se a política não puder ser aplicada.</exception>
    public void EnsureValid()
    {
        if (ActiveCategories.Count == 0)
        {
            throw new InvalidPolicyException(
                "A política precisa de pelo menos uma categoria ativa (RN-009). "
                + "Uma política sem categorias aprovaria todo arquivo e produziria "
                + "uma auditoria falsamente limpa.");
        }

        if (MaxFileSizeMb <= 0)
        {
            throw new InvalidPolicyException("maxFileSizeMb precisa ser maior que zero.");
        }

        if (InspectionTimeoutSeconds <= 0)
        {
            throw new InvalidPolicyException("inspectionTimeoutSeconds precisa ser maior que zero.");
        }
    }

    /// <summary>
    /// RN-014 — exclusões. Processos de sistema e o próprio agente nunca são
    /// interceptados. O agente na lista não é detalhe: sem isso, a leitura que
    /// o próprio agente faz do arquivo dispararia uma nova inspeção, que faria
    /// outra leitura, e assim por diante.
    /// </summary>
    public bool IsExcludedProcess(string? processName)
    {
        if (string.IsNullOrWhiteSpace(processName))
        {
            return false;
        }

        // A política lista SafeUpload.Agent.App; o processo pode chegar com ou
        // sem o sufixo .exe dependendo de quem observou a operação.
        var bare = processName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? processName[..^4]
            : processName;

        return ExcludedProcesses.Contains(bare) || ExcludedProcesses.Contains(processName);
    }

    /// <summary>Verdadeiro se a extensão está na lista vigiada.</summary>
    public bool IsMonitoredExtension(string? extension) =>
        !string.IsNullOrWhiteSpace(extension) && MonitoredScopes.Extensions.Contains(extension);

    /// <summary>
    /// RN-011 — escopo. Só é inspecionado o que vai para um destino vigiado.
    /// Mídia removível e rede dependem das chaves da política; nuvem é uma
    /// pasta local e entra pelo caminho monitorado.
    /// </summary>
    public bool IsMonitoredDestination(FileOperation operation)
    {
        ArgumentNullException.ThrowIfNull(operation);

        return operation.Destination switch
        {
            DestinationKind.RemovableDrive => MonitoredScopes.RemovableDrives,
            DestinationKind.NetworkShare => MonitoredScopes.NetworkPaths,
            DestinationKind.Cloud => IsUnderMonitoredPath(operation.DestinationPath),
            _ => false
        };
    }

    private bool IsUnderMonitoredPath(string? destinationPath)
    {
        if (string.IsNullOrWhiteSpace(destinationPath))
        {
            return false;
        }

        foreach (var monitored in MonitoredScopes.DestinationPaths)
        {
            if (destinationPath.StartsWith(monitored, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
