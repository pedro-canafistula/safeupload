namespace SafeUpload.Agent.Core.Domain;

/// <summary>
/// Desfecho possível de uma operação de arquivo avaliada pelo agente.
/// </summary>
public enum Verdict
{
    /// <summary>Inspecionado e liberado: nenhum achado válido.</summary>
    Approved,

    /// <summary>
    /// Inspecionado e negado: pelo menos um achado válido (RN-005).
    /// Este é o único veredito que impede a operação, e ele nunca pode ser
    /// contornado pelo usuário.
    /// </summary>
    Blocked,

    /// <summary>
    /// Liberado sem inspeção de conteúdo — arquivo grande demais, formato não
    /// suportado, timeout ou erro de parsing (RN-012 e RN-013).
    /// Falha nunca vira bloqueio: o agente é fail-open.
    /// </summary>
    AllowedWithoutInspection
}
