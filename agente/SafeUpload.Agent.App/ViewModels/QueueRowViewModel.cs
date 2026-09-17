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

        OccurredAt = auditEvent.OccurredAtUtc.ToLocalTime().ToString("dd/MM HH:mm:ss");
        FileName = auditEvent.FileName;
        Verdict = VerdictLabels.Describe(auditEvent.Verdict);
        Categories = auditEvent.Categories.Count == 0
            ? "—"
            : string.Join(", ", auditEvent.Categories.Select(CategoryLabels.Describe));
        MaskedSnippets = auditEvent.MaskedSnippets.Count == 0
            ? "—"
            : string.Join("   ", auditEvent.MaskedSnippets);
        Reason = auditEvent.NotInspectedReason ?? "—";
        Process = auditEvent.ProcessName;
        Destination = auditEvent.DestinationPath;
        ElapsedMs = auditEvent.ElapsedMs;
        PolicyVersion = auditEvent.PolicyVersion;
        Dispatched = auditEvent.Dispatched ? "Sim" : "Não";
    }

    /// <summary>Momento da decisão, em hora local.</summary>
    public string OccurredAt { get; }

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
        _ => category.ToString()
    };
}

/// <summary>Explicações dos motivos padronizados de não inspeção.</summary>
public static class ReasonLabels
{
    /// <summary>
    /// Traduz o motivo técnico para uma frase legível. Os códigos continuam no
    /// log, porque é o que o Centro de Administração vai agregar; a tradução
    /// existe só para a tela.
    /// </summary>
    public static string Describe(string? reason) => reason switch
    {
        null => string.Empty,
        "file_too_large" => "Arquivo acima do limite da política; liberado sem inspeção.",
        "unsupported_format" => "Formato sem extrator nesta versão; liberado sem inspeção.",
        "inspection_timeout" => "A inspeção passou do prazo da política; liberado sem inspeção.",
        "out_of_scope" => "Destino ou extensão fora do escopo monitorado.",
        "excluded_process" => "Processo excluído pela política; nunca interceptado.",
        _ when reason.StartsWith("parse_error:", StringComparison.Ordinal) =>
            $"Falha ao interpretar o arquivo ({reason["parse_error:".Length..]}); liberado sem inspeção.",
        _ => reason
    };
}
