using System.Text.Json.Serialization;
using System.Text.Json;
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

    /// <summary>Subconjunto de activeCategories que só alerta (ação "alertar" do console).</summary>
    [JsonPropertyName("alertCategories")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string[]? AlertCategories { get; init; }

    [JsonPropertyName("monitoredScopes")]
    public MonitoredScopesDocument? MonitoredScopes { get; init; }

    private int? _maxFileSizeMb, _inspectionTimeoutSeconds;

    // Absence selects the consumption mode's defaults. Null is still malformed,
    // never a way to replace an explicit small limit with the larger default.
    [JsonPropertyName("maxFileSizeMb")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? MaxFileSizeMb
    {
        get => _maxFileSizeMb;
        init => _maxFileSizeMb = value ?? throw new JsonException("maxFileSizeMb must be an integer.");
    }

    [JsonPropertyName("inspectionTimeoutSeconds")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? InspectionTimeoutSeconds
    {
        get => _inspectionTimeoutSeconds;
        init => _inspectionTimeoutSeconds = value ?? throw new JsonException("inspectionTimeoutSeconds must be an integer.");
    }

    [JsonPropertyName("auditOnly")]
    public bool AuditOnly { get; init; }

    [JsonPropertyName("overrideAllowed")]
    public bool OverrideAllowed { get; init; }

    [JsonPropertyName("failOpen")]
    public bool FailOpen { get; init; } = true;

    [JsonPropertyName("excludedProcesses")]
    public string[]? ExcludedProcesses { get; init; }

    [JsonPropertyName("clipboard")]
    public ClipboardDocument? Clipboard { get; init; }

    public static PolicyDocument Default { get; } = new()
    {
        Version = 1,
        ActiveCategories = ["Cpf", "Cnpj", "PaymentCard", "Password", "Secret"],
        MonitoredScopes = MonitoredScopesDocument.Default,
        FailOpen = true,
        ExcludedProcesses = ["System", "SafeUpload.Agent.App"],
        Clipboard = ClipboardDocument.Default
    };

    // Snapshot operacional local: a console atual não configura escopos, limites ou canais.
    internal static PolicyDocument FromPolicy(Policy policy) => new()
    {
        Version = policy.Version,
        ActiveCategories = policy.ActiveCategories.Order().Select(c => c.ToString()).ToArray(),
        AlertCategories = policy.AlertCategories is { Count: > 0 } alerts
            ? alerts.Order().Select(c => c.ToString()).ToArray() : null,
        MonitoredScopes = new MonitoredScopesDocument
        {
            Extensions = policy.MonitoredScopes.Extensions.Order(StringComparer.OrdinalIgnoreCase).ToArray(),
            DestinationPaths = policy.MonitoredScopes.DestinationPaths.ToArray(),
            RemovableDrives = policy.MonitoredScopes.RemovableDrives,
            NetworkPaths = policy.MonitoredScopes.NetworkPaths
        },
        MaxFileSizeMb = policy.MaxFileSizeMb,
        InspectionTimeoutSeconds = policy.InspectionTimeoutSeconds,
        FailOpen = policy.FailOpen,
        ExcludedProcesses = policy.ExcludedProcesses.Order(StringComparer.OrdinalIgnoreCase).ToArray(),
        AuditOnly = policy.AuditOnly,
        OverrideAllowed = policy.OverrideAllowed,
        Clipboard = policy.Clipboard is { } clipboard ? new ClipboardDocument
        {
            Mode = clipboard.Mode.ToString(),
            EgressDestinations = clipboard.EgressDestinations.Order(StringComparer.OrdinalIgnoreCase).ToArray(),
            ExcludedSources = clipboard.ExcludedSources.Order(StringComparer.OrdinalIgnoreCase).ToArray(),
            MaxTextLength = clipboard.MaxTextLength,
            OversizedTextIsDirty = clipboard.OversizedTextIsDirty
        } : null
    };

    /// <summary>
    /// Converte para o objeto de domínio. Não valida: quem chama decide quando
    /// aplicar a RN-009, e as duas IPolicyStore fazem isso no carregamento.
    /// </summary>
    public Policy ToPolicy(bool staged = false)
    {
        var categories = ParseCategories(ActiveCategories);
        var alerts = ParseCategories(AlertCategories);
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
                scopes.NetworkPaths),
            MaxFileSizeMb ?? (staged ? 4096 : 20),
            InspectionTimeoutSeconds ?? (staged ? 900 : 5),
            FailOpen,
            excluded,
            AuditOnly,
            OverrideAllowed,
            MapClipboard(Clipboard),
            AlertCategories is null ? null : alerts);
    }

    private static HashSet<Category> ParseCategories(string[]? names)
    {
        var categories = new HashSet<Category>();
        foreach (var name in names ?? [])
        {
            // Categoria desconhecida no documento é ignorada em vez de derrubar
            // o agente: um painel mais novo pode publicar uma categoria que esta
            // versão ainda não implementa. Se sobrar zero, a RN-009 pega.
            if (Enum.TryParse<Category>(name, ignoreCase: true, out var category) &&
                Enum.IsDefined(category) && !int.TryParse(name, out _))
            {
                categories.Add(category);
            }
        }
        return categories;
    }

    /// <summary>
    /// Bloco <c>clipboard</c>. Ausente = canal desligado.
    ///
    /// O modo é lido como texto, e não pelo conversor de enum, para que um
    /// valor desconhecido vire <see cref="InvalidPolicyException"/> com uma
    /// mensagem clara. Diferente da categoria desconhecida, que é ignorada,
    /// aqui ignorar seria pior: um "Blok" digitado errado desligaria a
    /// proteção em silêncio.
    /// </summary>
    private static ClipboardPolicy? MapClipboard(ClipboardDocument? document)
    {
        if (document is null)
        {
            return null;
        }

        if (!Enum.TryParse<ClipboardMode>(document.Mode, ignoreCase: true, out var mode) ||
            !Enum.IsDefined(mode) ||
            int.TryParse(document.Mode, out _))
        {
            throw new InvalidPolicyException(
                $"clipboard.mode \"{document.Mode}\" não é válido. Use Off, Audit ou Block.");
        }

        // O console envia só o modo: sem listas, valem as do padrão.
        return new ClipboardPolicy(
            mode,
            new HashSet<string>(document.EgressDestinations ?? ClipboardDocument.Default.EgressDestinations ?? [],
                StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(document.ExcludedSources ?? ClipboardDocument.Default.ExcludedSources ?? [],
                StringComparer.OrdinalIgnoreCase),
            document.MaxTextLength,
            document.OversizedTextIsDirty);
    }
}

/// <summary>O bloco clipboard do documento de política.</summary>
internal sealed record ClipboardDocument
{
    [JsonPropertyName("mode")]
    public string Mode { get; init; } = nameof(ClipboardMode.Off);

    [JsonPropertyName("egressDestinations")]
    public string[]? EgressDestinations { get; init; }

    [JsonPropertyName("excludedSources")]
    public string[]? ExcludedSources { get; init; }

    [JsonPropertyName("maxTextLength")]
    public int MaxTextLength { get; init; } = ClipboardPolicy.DefaultMaxTextLength;

    [JsonPropertyName("oversizedTextIsDirty")]
    public bool OversizedTextIsDirty { get; init; } = true;

    // Desligado, mas preenchido: quem abrir o arquivo padrão vê o bloco e
    // o que ligar, em vez de ter de descobrir a chave no código. Os nomes
    // de executável são exemplos e precisam ser conferidos na máquina; a
    // comparação é exata. WhatsApp.Root é o WhatsApp para Windows, que não
    // casa com "WhatsApp".
    public static ClipboardDocument Default { get; } = new()
    {
        Mode = nameof(ClipboardMode.Off),
        EgressDestinations = ["chrome", "msedge", "firefox", "brave", "opera", "WhatsApp", "WhatsApp.Root", "Telegram", "ms-teams", "slack", "Discord", "OUTLOOK", "thunderbird"],
        ExcludedSources = ["KeePass", "KeePassXC", "1Password", "Bitwarden"],
        MaxTextLength = ClipboardPolicy.DefaultMaxTextLength,
        OversizedTextIsDirty = true
    };
}

/// <summary>O bloco monitoredScopes do documento de política.</summary>
internal sealed record MonitoredScopesDocument
{
    [JsonPropertyName("extensions")]
    public string[]? Extensions { get; init; }

    [JsonPropertyName("destinationPaths")]
    public string[]? DestinationPaths { get; init; }

    // Aceita e ignorada: o agente classifica arquivos de qualquer origem
    // (35a13695), e o domínio não tem mais SourcePaths. Mantida para que um
    // painel que ainda publica a chave não quebre a leitura do documento.
    [JsonPropertyName("sourcePaths")]
    public string[]? SourcePaths { get; init; }

    [JsonPropertyName("removableDrives")]
    public bool RemovableDrives { get; init; } = true;

    [JsonPropertyName("networkPaths")]
    public bool NetworkPaths { get; init; } = true;

    public static MonitoredScopesDocument Default { get; } = new()
    {
        Extensions = [".txt", ".csv", ".docx", ".xlsx", ".pdf", ".pptx", ".pptm", ".potx", ".ppsx", ".zip", ".7z"],

        // Caminho de máquina, e não sob %USERPROFILE%: quem lê esta política é
        // um serviço rodando como LocalSystem, para quem %USERPROFILE% aponta
        // para o perfil da conta de sistema.
        DestinationPaths = [@"C:\SafeUpload\Escopo Monitorado"],
        RemovableDrives = true,
        NetworkPaths = true
    };
}
