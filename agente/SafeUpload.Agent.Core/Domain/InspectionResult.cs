namespace SafeUpload.Agent.Core.Domain;

/// <summary>
/// O que o motor de inspeção conclui sobre uma operação.
/// </summary>
/// <param name="Verdict">Desfecho.</param>
/// <param name="Findings">Achados mascarados; vazio quando não há.</param>
/// <param name="Reason">
/// Motivo padronizado quando não houve inspeção de conteúdo. Segue a mesma
/// grafia usada na auditoria: file_too_large, unsupported_format,
/// inspection_timeout, parse_error:Tipo, out_of_scope.
/// </param>
/// <param name="ElapsedMs">
/// Tempo da decisão, em milissegundos. É o número que demonstra os requisitos
/// de desempenho: acerto de cache abaixo de 10 ms, análise completa abaixo de
/// 3 s e corte por timeout em 5 s.
/// </param>
/// <param name="FromCache">Se a decisão veio do cache em vez de nova análise.</param>
/// <param name="PolicyVersion">Versão da política aplicada nesta decisão.</param>
/// <param name="InScope">
/// Falso quando a operação nem chegou a ser avaliada, por processo excluído
/// (RN-014) ou destino fora do escopo (RN-011).
/// </param>
public sealed record InspectionResult(
    Verdict Verdict,
    IReadOnlyList<Finding> Findings,
    string? Reason,
    long ElapsedMs,
    bool FromCache,
    int PolicyVersion,
    bool InScope)
{
    /// <summary>
    /// Categorias distintas encontradas, na ordem em que apareceram. É o que a
    /// notificação de bloqueio lista para o usuário.
    /// </summary>
    public IReadOnlyList<Category> Categories =>
        Findings.Select(static f => f.Category).Distinct().ToList();

    /// <summary>Verdadeiro quando a operação deve ser negada (RN-005).</summary>
    public bool IsBlocked => Verdict == Verdict.Blocked;
}
