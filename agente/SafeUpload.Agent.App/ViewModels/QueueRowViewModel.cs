using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.App.ViewModels;

/// <summary>
/// Uma linha da grade da fila de auditoria.
///
/// Traduz o <see cref="AuditEvent"/> para o que a grade mostra: horário local,
/// veredito em português e categorias já juntas. Os trechos vêm mascarados do
/// domínio; esta camada não tem como desmascarar nada, porque o valor original
/// nunca chegou até aqui.
/// </summary>
public sealed class QueueRowViewModel
{
    /// <summary>Cria a linha a partir do evento gravado.</summary>
    public QueueRowViewModel(AuditEvent auditEvent)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);

        EventId = auditEvent.EventId;
        OccurredAt = auditEvent.OccurredAtUtc.ToLocalTime().ToString("dd/MM HH:mm:ss");
        FileName = AuditSubject.Describe(auditEvent);
        Verdict = auditEvent.NotInspectedReason == "publication_outcome_unknown" ? "Não confirmado" :
            auditEvent.NotInspectedReason == "publication_failed" ? "Publicação pendente" :
            auditEvent.Verdict == Core.Domain.Verdict.Blocked && ReasonLabels.IsInspectionFailure(auditEvent.NotInspectedReason) ? "Inconclusivo / bloqueado" :
            auditEvent.Verdict == Core.Domain.Verdict.Approved && ReasonLabels.IsInspectionFailure(auditEvent.NotInspectedReason) ?
                auditEvent.PublishedSha256Hex is not null ? "Publicado com ressalva" : "Aprovado / sem inspeção" :
            auditEvent.Verdict == Core.Domain.Verdict.Approved && auditEvent.Categories.Count > 0 ?
                auditEvent.PublishedSha256Hex is not null ? "Publicado com alerta" : "Aprovado com achados" :
            auditEvent.Verdict == Core.Domain.Verdict.Approved && auditEvent.PublishedSha256Hex is not null ? "Publicado" : VerdictLabels.Describe(auditEvent.Verdict);
        Categories = CategoryLabels.Describe(auditEvent);
        MaskedSnippets = auditEvent.MaskedSnippets.Count == 0
            ? "—"
            : string.Join("   ", auditEvent.MaskedSnippets.Select(AuditTextPrivacy.Sanitize));
        Reason = auditEvent.NotInspectedReason is null ? "—" : ReasonLabels.Describe(auditEvent.NotInspectedReason);
        Process = AuditTextPrivacy.Sanitize(auditEvent.ProcessName);
        Destination = AuditTextPrivacy.Sanitize(auditEvent.DestinationPath);
        ElapsedMs = auditEvent.ElapsedMs;
        PolicyVersion = auditEvent.PolicyVersion;
        Dispatched = auditEvent.Dispatched ? "Sim" : "Não";
    }

    /// <summary>Momento da decisão, em hora local.</summary>
    public string OccurredAt { get; }
    public Guid EventId { get; }

    /// <summary>Nome do arquivo julgado.</summary>
    public string FileName { get; }

    /// <summary>Veredito em português.</summary>
    public string Verdict { get; }

    /// <summary>Categorias encontradas.</summary>
    public string Categories { get; }

    /// <summary>Trechos mascarados registrados.</summary>
    public string MaskedSnippets { get; }

    /// <summary>Motivo de não ter inspecionado, quando houver.</summary>
    public string Reason { get; }

    /// <summary>Processo de origem.</summary>
    public string Process { get; }

    /// <summary>Destino da operação.</summary>
    public string Destination { get; }

    /// <summary>Duração da decisão.</summary>
    public long ElapsedMs { get; }

    /// <summary>Versão da política aplicada.</summary>
    public int PolicyVersion { get; }

    /// <summary>Se já foi entregue ao servidor central.</summary>
    public string Dispatched { get; }
}

/// <summary>Nomes de exibição dos vereditos.</summary>
public static class VerdictLabels
{
    /// <summary>Descreve o veredito em português.</summary>
    public static string Describe(Verdict verdict) => verdict switch
    {
        Verdict.Approved => "Aprovado",
        Verdict.Blocked => "Bloqueado",
        Verdict.AllowedWithoutInspection => "Permitido sem inspeção",
        _ => verdict.ToString()
    };
}

/// <summary>Nomes de exibição das categorias.</summary>
public static class CategoryLabels
{
    /// <summary>Descreve a categoria em português.</summary>
    public static string Describe(Category category) => category switch
    {
        Category.Cpf => "CPF",
        Category.Cnpj => "CNPJ",
        Category.PaymentCard => "Cartão de pagamento",
        Category.Password => "Senha",
        Category.Secret => "Segredo/credencial",
        Category.Rg => "RG",
        Category.BankData => "Dados bancários",
        Category.HealthData => "Dados de saúde",
        Category.ConfidentialDocument => "Documento confidencial",
        Category.PersonalData => "Dados pessoais",
        Category.CustomRule or Category.CustomRuleAlert => "Regra da empresa",
        _ => category.ToString()
    };

    /// <summary>As categorias de um evento; as de regra personalizada mostram o nome da regra ("Regra: X"), como o console.</summary>
    public static string Describe(AuditEvent item) => item.Categories.Count == 0 ? "—" : string.Join(", ", item.Categories
        .SelectMany(category => IsCustom(category) && item.CustomRules is { Count: > 0 } names
            ? names.Select(name => "Regra: " + name) : [Describe(category)])
        .Distinct());

    public static string Describe(Finding finding) =>
        IsCustom(finding.Category) && finding.RuleName is { } name ? "Regra: " + name : Describe(finding.Category);

    private static bool IsCustom(Category category) => category is Category.CustomRule or Category.CustomRuleAlert;
}

/// <summary>Explicações dos motivos padronizados de não inspeção.</summary>
public static class ReasonLabels
{
    public static bool IsInspectionFailure(string? reason) => reason is "file_too_large" or "unsupported_format" or
        "inspection_timeout" or "inspection_limit" or "not_enough_staging_space" or
        "archive_encrypted" or "archive_unsupported_member" or "archive_unsupported_structure" or "archive_7z_unavailable" ||
        reason?.StartsWith("parse_error:", StringComparison.Ordinal) == true;

    /// <summary>
    /// Traduz o motivo técnico para uma frase legível. Os códigos continuam no
    /// log, porque é o que o Centro de Administração vai agregar; a tradução
    /// existe só para a tela.
    /// </summary>
    public static string Describe(string? reason) => reason switch
    {
        null => string.Empty,
        "file_too_large" => "Arquivo acima do limite da política; inspeção não concluída.",
        "unsupported_format" => "Formato sem extrator nesta versão; inspeção não concluída.",
        "inspection_timeout" => "A inspeção passou do prazo da política; análise inconclusiva.",
        "inspection_limit" => "O conteúdo excedeu a capacidade de análise completa desta versão.",
        "not_enough_staging_space" => "Espaço de preparação insuficiente; inspeção não concluída.",
        "archive_encrypted" => "Arquivo compactado criptografado; inspeção não concluída.",
        "archive_unsupported_member" => "Um item do arquivo compactado não pôde ser inspecionado.",
        "archive_unsupported_structure" => "A estrutura do arquivo compactado não permite concluir a inspeção.",
        "archive_7z_unavailable" => "O componente de leitura de arquivos 7z está indisponível; inspeção não concluída.",
        "publication_failed" => "Não foi possível concluir a publicação; a versão continua retida localmente.",
        "out_of_scope" => "Destino ou extensão fora do escopo monitorado.",
        "excluded_process" => "Processo excluído pela política; nunca interceptado.",
        "publication_outcome_unknown" => "Não foi possível confirmar o resultado da publicação após uma interrupção.",
        _ when reason.StartsWith("inspection_error:", StringComparison.Ordinal) =>
            "Erro interno na inspeção do envio; liberado e registrado.",
        _ when reason.StartsWith("parse_error:", StringComparison.Ordinal) =>
            "Falha ao interpretar o arquivo; inspeção não concluída.",
        _ => AuditTextPrivacy.Sanitize(reason)
    };
}
