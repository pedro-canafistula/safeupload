namespace SafeUpload.Agent.Core.Domain;

/// <summary>
/// Modo do canal de área de transferência.
///
/// É o "modo por atividade" que a ARQUITETURA.md aponta como o primeiro item a
/// trazer do mercado: o canal sobe em auditoria para medir falso positivo, e só
/// depois passa a bloquear.
/// </summary>
public enum ClipboardMode
{
    /// <summary>O canal não faz nada: nem classifica, nem registra.</summary>
    Off,

    /// <summary>Classifica e registra a colagem que seria bloqueada, sem impedi-la.</summary>
    Audit,

    /// <summary>Impede a colagem de texto sensível num destino de saída.</summary>
    Block
}

/// <summary>
/// O bloco <c>clipboard</c> da política.
///
/// <para>O desenho, aprovado com o Victor: o Ctrl+C não bloqueia nada. Ele só
/// classifica o texto e marca o clipboard como sujo quando há achado. O
/// bloqueio acontece no Ctrl+V, e só quando o destino é um processo de saída
/// (navegador, mensageiro, e-mail). Colar entre aplicativos locais continua
/// livre, que é o que evita o falso positivo de quem só move dados de uma
/// planilha para outra.</para>
///
/// <para>As categorias não moram aqui: vêm de <see cref="Policy.ActiveCategories"/>.
/// Um CPF é o mesmo achado copiado ou salvo, e duas listas de categorias seriam
/// duas respostas diferentes para a mesma pergunta.</para>
/// </summary>
/// <param name="Mode">Off, Audit ou Block.</param>
/// <param name="EgressDestinations">
/// Processos que contam como saída. Lista de bloqueio: o que não está aqui é
/// tratado como aplicativo local.
/// </param>
/// <param name="ExcludedSources">
/// Processos cuja cópia nunca suja o clipboard (gerenciadores de senha, que
/// escrevem e limpam o clipboard o tempo todo).
/// </param>
/// <param name="MaxTextLength">Teto de caracteres que o serviço aceita varrer.</param>
/// <param name="OversizedTextIsDirty">
/// O que fazer com texto acima do teto. Verdadeiro segue a regra do driver para
/// origem: o que não foi olhado marca. Decisão em aberto com o Victor; o padrão
/// é verdadeiro porque o contrário abre o mesmo furo que o driver fechou para
/// arquivo grande demais.
/// </param>
public sealed record ClipboardPolicy(
    ClipboardMode Mode,
    IReadOnlySet<string> EgressDestinations,
    IReadOnlySet<string> ExcludedSources,
    int MaxTextLength,
    bool OversizedTextIsDirty)
{
    /// <summary>Teto padrão de caracteres varridos.</summary>
    public const int DefaultMaxTextLength = 100_000;

    /// <summary>
    /// Canal desligado. É o que vale para uma política sem o bloco
    /// <c>clipboard</c>, para que um arquivo antigo continue carregando igual.
    /// </summary>
    public static ClipboardPolicy Disabled { get; } = new(
        ClipboardMode.Off,
        new HashSet<string>(StringComparer.OrdinalIgnoreCase),
        new HashSet<string>(StringComparer.OrdinalIgnoreCase),
        DefaultMaxTextLength,
        OversizedTextIsDirty: true);

    /// <summary>Verdadeiro quando o canal faz alguma coisa.</summary>
    public bool IsEnabled => Mode != ClipboardMode.Off;

    /// <summary>
    /// Validação no carregamento (RN-009): falha alto e cedo, e não no meio de
    /// uma colagem.
    /// </summary>
    public void EnsureValid()
    {
        if (MaxTextLength <= 0)
        {
            throw new InvalidPolicyException("clipboard.maxTextLength precisa ser maior que zero.");
        }

        // Bloquear sem nenhum destino de saída é uma política que promete
        // bloquear e nunca bloqueia. Melhor recusar do que auditar limpo.
        if (Mode == ClipboardMode.Block && EgressDestinations.Count == 0)
        {
            throw new InvalidPolicyException(
                "clipboard.mode = Block exige ao menos um destino em clipboard.egressDestinations.");
        }
    }

    /// <summary>O processo de destino conta como saída?</summary>
    public bool IsEgressDestination(string? processName) => Matches(EgressDestinations, processName);

    /// <summary>A cópia feita por este processo deve ser ignorada?</summary>
    public bool IsExcludedSource(string? processName) => Matches(ExcludedSources, processName);

    /// <summary>
    /// Compara nomes de processo sem caixa e com ou sem ".exe", do mesmo jeito
    /// que <see cref="Policy.IsExcludedProcess"/>: quem observa o processo pode
    /// entregar o nome nas duas formas.
    /// </summary>
    public static string? NormalizeProcessName(string? processName)
    {
        if (string.IsNullOrWhiteSpace(processName))
        {
            return null;
        }

        var name = Path.GetFileName(processName.Trim());
        return name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name[..^4] : name;
    }

    private static bool Matches(IReadOnlySet<string> names, string? processName)
    {
        var bare = NormalizeProcessName(processName);
        if (bare is null)
        {
            return false;
        }

        foreach (var name in names)
        {
            if (string.Equals(NormalizeProcessName(name), bare, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
