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
    bool NetworkPaths,
    IReadOnlyList<string>? SourcePaths = null)
{
    /// <summary>
    /// Onde mora o conteúdo sensível: as pastas cuja leitura merece ser
    /// inspecionada.
    ///
    /// É a outra metade do escopo, e só passou a existir quando o gatilho
    /// virou o minifiltro. No mock a inspeção começa quando um arquivo
    /// <b>chega</b> à pasta vigiada, e origem e destino são a mesma coisa —
    /// não há o que distinguir. Com interceptação de verdade a cadeia tem dois
    /// elos: ler um documento sensível marca o processo, e o processo marcado
    /// deixa de escrever nos destinos vigiados. Sem esta lista o primeiro elo
    /// nunca acontece, e o segundo nunca dispara.
    ///
    /// Vazia é configuração legítima: significa vigiar destinos sem manter
    /// cadeia de contaminação.
    /// </summary>
    public IReadOnlyList<string> SourcePaths { get; init; } = SourcePaths ?? [];
}

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
/// <param name="AuditOnly">
/// Avalia e registra, mas não nega nada. É como se implanta um DLP sem ser
/// desinstalado na primeira semana: roda-se em auditoria até conhecer o que é
/// atividade legítima, e só então liga-se o bloqueio. Enquanto está ligado, o
/// contador <c>WouldHaveDenied</c> do driver mede exatamente quanto o bloqueio
/// custaria hoje.
/// </param>
/// <param name="OverrideAllowed">
/// Deixa o usuário justificar uma recusa e seguir. São dois modos, e só dois:
/// com justificativa e sem. Desligado, o mecanismo fica fora do ar — o driver
/// recusa conceder exceção, então nem uma interface comprometida libera nada.
/// A escolha é da organização, não do usuário, e por isso vive na política.
/// </param>
public sealed record Policy(
    int Version,
    IReadOnlySet<Category> ActiveCategories,
    MonitoredScopes MonitoredScopes,
    int MaxFileSizeMb,
    int InspectionTimeoutSeconds,
    bool FailOpen,
    IReadOnlySet<string> ExcludedProcesses,
    bool AuditOnly = false,
    bool OverrideAllowed = false)
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

    /// <summary>
    /// Se a operação entra em escopo, por qualquer um dos dois lados.
    ///
    /// É o que a RN-011 significa desde que existe leitura de origem: uma
    /// operação interessa por ir para um destino vigiado <b>ou</b> por ler uma
    /// origem sensível. <see cref="IsMonitoredDestination"/> responde só a
    /// primeira metade, e usá-lo sozinho descarta toda leitura de origem antes
    /// de abrir o arquivo — que é como a cadeia de contaminação ficou sem o
    /// primeiro elo até se medir.
    /// </summary>
    public bool IsInScope(FileOperation operation)
    {
        ArgumentNullException.ThrowIfNull(operation);

        return operation.Destination == DestinationKind.SensitiveSource
            ? IsUnderMonitoredSource(operation.FilePath)
            : IsMonitoredDestination(operation);
    }

    /// <summary>Se o caminho está sob uma das origens vigiadas.</summary>
    private bool IsUnderMonitoredSource(string? filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            return false;
        }

        foreach (string root in MonitoredScopes.SourcePaths)
        {
            if (filePath.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
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
