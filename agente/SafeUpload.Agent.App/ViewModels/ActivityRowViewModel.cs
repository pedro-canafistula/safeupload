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
        EventId = auditEvent.EventId;

        Description = Describe(auditEvent);
        IconKey = IconFor(auditEvent.Verdict);
        Status = StatusPill.For(auditEvent.Verdict);
        OccurredAt = auditEvent.OccurredAtUtc.ToLocalTime().ToString("dd/MM HH:mm");
    }

    /// <summary>Resultado da inspeção, sem presumir envio ou bloqueio preventivo.</summary>
    public string Description { get; }
    public Guid EventId { get; }

    /// <summary>Chave do ícone da linha.</summary>
    public string IconKey { get; }

    /// <summary>Pílula de status.</summary>
    public StatusPill Status { get; }

    /// <summary>Momento da operação, em hora local.</summary>
    public string OccurredAt { get; }

    // O histórico não registra se um arquivo foi enviado ou impedido antes da
    // gravação. O estado atual do serviço também não descreve uma decisão antiga.
    private static string Describe(AuditEvent auditEvent) => auditEvent.Verdict switch
    {
        Verdict.Blocked => $"Restrição pela política: {AuditSubject.Describe(auditEvent)}",
        Verdict.Approved => $"Inspeção aprovada: {AuditSubject.Describe(auditEvent)}",
        Verdict.Retained => $"Arquivo retido para análise: {AuditSubject.Describe(auditEvent)}",
        _ => $"Conteúdo não inspecionado: {AuditSubject.Describe(auditEvent)}"
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
        Verdict.Retained => "IconAlert",
        _ => "IconAlert"
    };
}

/// <summary>
/// O rótulo de status usado no painel: texto e cor por veredito.
///
/// Só a cor do texto distingue os vereditos; não há faixa colorida atrás dele.
/// Numa lista de operações, um fundo por linha compete com o próprio conteúdo
/// da linha e transforma a tabela num semáforo — a cor da letra já carrega a
/// mesma informação sem tirar a atenção do nome do arquivo.
/// </summary>
/// <param name="Text">Rótulo em maiúscula.</param>
/// <param name="ForegroundKey">Chave do pincel de texto nos tokens da paleta.</param>
public sealed record StatusPill(string Text, string ForegroundKey)
{
    /// <summary>Rótulo correspondente ao veredito.</summary>
    public static StatusPill For(Verdict verdict) => verdict switch
    {
        Verdict.Approved => new StatusPill("APROVADO", "PillApprovedText"),
        Verdict.Blocked => new StatusPill("RESTRITO", "PillBlockedText"),
        Verdict.Retained => new StatusPill("RETIDO", "PillNotInspectedText"),
        _ => new StatusPill("NÃO INSPECIONADO", "PillNotInspectedText")
    };
}
