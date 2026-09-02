using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.App.ViewModels;

/// <summary>
/// Uma linha de "Monitoramento de Atividade": o que aconteceu com um arquivo,
/// em linguagem de usuário.
///
/// A tabela do status não repete a auditoria. Ela responde a uma pergunta
/// só — o que aconteceu com meus arquivos —, então a linha traz a frase e a
/// pílula, e nada de tamanho, PID ou versão de política. Isso está no
/// histórico, para quem precisa.
/// </summary>
public sealed class ActivityRowViewModel
{
    /// <summary>Traduz um evento gravado para a linha exibida.</summary>
    public ActivityRowViewModel(AuditEvent auditEvent)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);

        Description = Describe(auditEvent);
        IconKey = IconFor(auditEvent.Verdict);
        Status = StatusPill.For(auditEvent.Verdict);
        OccurredAt = auditEvent.OccurredAtUtc.ToLocalTime().ToString("dd/MM HH:mm");
    }

    /// <summary>Frase da operação, como "Upload bloqueado: clientes.xlsx".</summary>
    public string Description { get; }

    /// <summary>Chave do ícone da linha.</summary>
    public string IconKey { get; }

    /// <summary>Pílula de status.</summary>
    public StatusPill Status { get; }

    /// <summary>Momento da operação, em hora local.</summary>
    public string OccurredAt { get; }

    private static string Describe(AuditEvent auditEvent) => auditEvent.Verdict switch
    {
        Verdict.Blocked => $"Upload bloqueado: {auditEvent.FileName}",
        Verdict.Approved => $"Arquivo enviado: {auditEvent.FileName}",
        _ => $"Arquivo não inspecionado: {auditEvent.FileName}"
    };

    /// <summary>
    /// Proibido para o bloqueio, alerta para o que passou sem exame, arquivo
    /// para o envio normal. O ícone precisa distinguir "examinado e liberado"
    /// de "não examinado": são as duas situações que um usuário confundiria, e
    /// só uma delas significa que o arquivo foi olhado.
    /// </summary>
    private static string IconFor(Verdict verdict) => verdict switch
    {
        Verdict.Blocked => "IconBan",
        Verdict.Approved => "IconFile",
        _ => "IconAlert"
    };
}

/// <summary>
/// A pílula de status usada no painel: texto e cores por veredito.
/// </summary>
/// <param name="Text">Rótulo em maiúscula.</param>
/// <param name="BackgroundKey">Chave do pincel de fundo.</param>
/// <param name="ForegroundKey">Chave do pincel de texto.</param>
public sealed record StatusPill(string Text, string BackgroundKey, string ForegroundKey)
{
    /// <summary>Pílula correspondente ao veredito.</summary>
    public static StatusPill For(Verdict verdict) => verdict switch
    {
        Verdict.Approved => new StatusPill("PERMITIDO", "SuccessBg", "PillApprovedText"),
        Verdict.Blocked => new StatusPill("BLOQUEADO", "DangerBg", "PillBlockedText"),
        _ => new StatusPill("NÃO INSPECIONADO", "WarningBg", "PillNotInspectedText")
    };
}
