using System.Globalization;
using SafeUpload.Agent.Core.Contracts;

namespace SafeUpload.Agent.App.Notifications;

/// <summary>Displays received history without claiming persistence, completeness or recovery.</summary>
public sealed record AuditWritePresentation(string Summary, string Detail, string Message)
{
    public static AuditWritePresentation Unavailable { get; } = new(
        "Diagnóstico indisponível", "O serviço ainda não informou este diagnóstico.",
        "A ausência de diagnóstico não confirma a gravação da auditoria.");

    public static AuditWritePresentation Disconnected { get; } = new(
        "Sem comunicação com o serviço", "Não foi possível atualizar o diagnóstico.",
        "Reconecte ao serviço para receber seu histórico atual.");

    public static AuditWritePresentation From(AuditWriteStatus? status)
    {
        if (status is null || status.FailureCount < 0) return Unavailable;
        if (status.FailureCount == 0)
            return new("Nenhuma falha relatada pelo serviço",
                "Último diagnóstico recebido · nesta execução do serviço",
                "Este contador não confirma auditoria completa nem entrega ao servidor.");

        string kind = status.LastRecordKind switch
        {
            "event" => "evento", "override" => "justificativa", _ => "registro"
        };
        string error = status.LastErrorClass switch
        {
            "access_denied" => "acesso negado", "io" => "entrada e saída",
            "interrupted" => "gravação interrompida", _ => "falha não especificada"
        };
        return new("Falhas de gravação observadas: " + status.FailureCount.ToString(CultureInfo.InvariantCulture),
            $"Último diagnóstico recebido · nesta execução do serviço · {kind}: {error}",
            "Persistência não confirmada. Verifique espaço em disco e permissões. " +
            "Gravações posteriores não recuperam automaticamente os registros afetados.");
    }
}
