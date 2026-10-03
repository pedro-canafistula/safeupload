namespace SafeUpload.Agent.Core.Domain;

/// <summary>Por que uma cópia ficou suja ou limpa.</summary>
public enum ClipboardCopyReason
{
    /// <summary>Canal desligado na política: nada foi olhado.</summary>
    ChannelOff,

    /// <summary>Copiado por um processo excluído: nunca suja.</summary>
    ExcludedSource,

    /// <summary>Varrido e sem achado.</summary>
    Clean,

    /// <summary>Varrido e com achado válido.</summary>
    Sensitive,

    /// <summary>Acima do teto: não foi varrido.</summary>
    TextTooLarge
}

/// <summary>
/// Resultado da classificação de uma cópia.
/// </summary>
/// <param name="Dirty">O clipboard ficou sujo.</param>
/// <param name="Reason">Por quê.</param>
/// <param name="Findings">Achados já mascarados (RN-007). Nunca o texto original.</param>
public sealed record ClipboardClassification(
    bool Dirty,
    ClipboardCopyReason Reason,
    IReadOnlyList<Finding> Findings)
{
    /// <summary>Categorias distintas dos achados, na ordem em que apareceram.</summary>
    public IReadOnlyList<Category> Categories =>
        Findings.Select(static f => f.Category).Distinct().ToList();
}

/// <summary>O que fazer com uma colagem.</summary>
public enum ClipboardPasteVerdict
{
    /// <summary>Cola normalmente, sem registro.</summary>
    Allow,

    /// <summary>Cola normalmente e registra o que teria sido bloqueado.</summary>
    AuditOnly,

    /// <summary>Entrega um aviso no lugar do texto, notifica e registra.</summary>
    Block
}

/// <summary>
/// As duas decisões do canal de clipboard, sem nada de Windows.
///
/// <para>Fica fora do App e do serviço de propósito: é a parte que precisa
/// estar certa, e é a única que dá para testar sem uma área de transferência
/// de verdade. O App só observa e aplica; o serviço só transporta e audita;
/// quem decide é isto.</para>
/// </summary>
public static class ClipboardRules
{
    /// <summary>
    /// No Ctrl+C: o clipboard ficou sujo?
    /// </summary>
    /// <param name="text">
    /// O texto recebido. Pode ter sido cortado pelo App no teto do protocolo;
    /// por isso o tamanho real vem à parte.
    /// </param>
    /// <param name="textLength">Tamanho real do texto copiado, em caracteres.</param>
    /// <param name="sourceProcess">Quem copiou, se conhecido.</param>
    /// <param name="policy">A política em vigor.</param>
    public static ClipboardClassification Classify(
        string text,
        int textLength,
        string? sourceProcess,
        Policy policy)
    {
        ArgumentNullException.ThrowIfNull(text);
        ArgumentNullException.ThrowIfNull(policy);

        var clipboard = policy.EffectiveClipboard;

        if (!clipboard.IsEnabled)
        {
            return new ClipboardClassification(false, ClipboardCopyReason.ChannelOff, []);
        }

        // RN-014 vale aqui também: o próprio agente e os processos que a
        // política exclui não sujam o clipboard.
        if (clipboard.IsExcludedSource(sourceProcess) || policy.IsExcludedProcess(sourceProcess))
        {
            return new ClipboardClassification(false, ClipboardCopyReason.ExcludedSource, []);
        }

        // Acima do teto não se varre. O resultado segue a regra que o driver
        // usa na origem: o que não foi olhado marca, a menos que a política
        // diga o contrário. Sem isso, bastaria copiar um texto grande com o CPF
        // no fim para passar.
        if (textLength > clipboard.MaxTextLength || text.Length > clipboard.MaxTextLength)
        {
            return new ClipboardClassification(
                clipboard.OversizedTextIsDirty,
                ClipboardCopyReason.TextTooLarge,
                []);
        }

        var findings = ContentScanner.Scan(text, policy.ActiveCategories);

        return findings.Count == 0
            ? new ClipboardClassification(false, ClipboardCopyReason.Clean, [])
            : new ClipboardClassification(true, ClipboardCopyReason.Sensitive, findings);
    }

    /// <summary>
    /// No Ctrl+V: a colagem passa?
    /// </summary>
    /// <param name="copyIsDirty">Se a cópia em vigor está suja.</param>
    /// <param name="sourceProcess">Quem copiou.</param>
    /// <param name="destinationProcess">Onde está colando.</param>
    /// <param name="clipboard">O bloco de clipboard da política.</param>
    public static ClipboardPasteVerdict DecidePaste(
        bool copyIsDirty,
        string? sourceProcess,
        string? destinationProcess,
        ClipboardPolicy clipboard)
    {
        ArgumentNullException.ThrowIfNull(clipboard);

        if (!clipboard.IsEnabled || !copyIsDirty)
        {
            return ClipboardPasteVerdict.Allow;
        }

        // Excel → Excel: o dado não saiu de onde já estava.
        var source = ClipboardPolicy.NormalizeProcessName(sourceProcess);
        var destination = ClipboardPolicy.NormalizeProcessName(destinationProcess);
        if (source is not null && string.Equals(source, destination, StringComparison.OrdinalIgnoreCase))
        {
            return ClipboardPasteVerdict.Allow;
        }

        // Destino desconhecido não é tratado como saída: sem saber para onde
        // vai, bloquear seria resolver incerteza negando, que é o que a RN-013
        // proíbe.
        if (!clipboard.IsEgressDestination(destinationProcess))
        {
            return ClipboardPasteVerdict.Allow;
        }

        return clipboard.Mode == ClipboardMode.Block
            ? ClipboardPasteVerdict.Block
            : ClipboardPasteVerdict.AuditOnly;
    }
}
