namespace SafeUpload.Agent.Core.Domain;

/// <summary>
/// Desfecho possível de uma operação de arquivo avaliada pelo agente.
/// </summary>
public enum Verdict
{
    /// <summary>Inspecionado e liberado: nenhum achado válido.</summary>
    Approved,

    /// <summary>
    /// Negado: achado válido (RN-005) ou uma transferência staged em escopo
    /// cujo conteúdo não pôde ser inspecionado completamente. A política pode
    /// permitir uma justificativa vinculada aos bytes e à versão da política.
    /// </summary>
    Blocked,

    /// <summary>
    /// Liberado sem inspeção de conteúdo — arquivo grande demais, formato não
    /// suportado, timeout ou erro de parsing (RN-012 e RN-013).
    /// Este tratamento de falhas pertence ao modo legado; staged usa Blocked.
    /// </summary>
    AllowedWithoutInspection,

    /// <summary>
    /// A staged transfer was held locally. No bytes were released to its
    /// protected destination.
    /// </summary>
    Retained
}
