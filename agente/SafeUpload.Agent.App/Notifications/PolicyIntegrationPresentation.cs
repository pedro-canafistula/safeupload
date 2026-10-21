using SafeUpload.Agent.Core.Contracts;

namespace SafeUpload.Agent.App.Notifications;

/// <summary>Presentation only. Does not decide protection, readiness or authorization.</summary>
public sealed record PolicyIntegrationPresentation(string Available, string LastRead, string Accepted, string Message)
{
    public static PolicyIntegrationPresentation Unavailable { get; } =
        new("—", "—", "—", "O serviço ainda não enviou o diagnóstico da política.");
    public static PolicyIntegrationPresentation Disconnected { get; } =
        new("—", "—", "—", "Sem comunicação com o serviço. Aguarde a reconexão.");

    public static PolicyIntegrationPresentation From(PolicyIntegrationStatus? status)
    {
        if (status is null) return Unavailable;
        string source = status.SnapshotSource switch
        {
            "remote" => "servidor", "memory" => "memória", "disk" => "cache em disco",
            "default" => "padrão local", "local" => "local", _ => "origem não informada"
        };
        string available = status.SnapshotVersion is > 0 ? $"v{status.SnapshotVersion} · {source}" : "Não informada";
        string read = status.StrictVersion is > 0 ? $"v{status.StrictVersion}" : "Ainda não registrada";
        string accepted = status.LastAcceptedVersion is > 0
            ? $"v{status.LastAcceptedVersion}" + (status.DriverScopeRecorded ? " · escopo aceito" : " · histórico")
            : "Ainda não registrado";
        string message = status.DriverApplyFailed ? "Falha ao aplicar o escopo. O aceite anterior é apenas histórico."
            : status.CurrentReadFailed ? "A consulta da política atual falhou. A última leitura exibida é histórica."
            : !status.DriverScopeRecorded ? "Sem aceite de escopo confirmado na conexão atual."
            : status.CurrentContentMatchesAccepted == false ? "A política recebida difere da usada no último aceite de escopo."
            : status.CurrentContentMatchesAccepted == true ? "A última leitura corresponde à política do aceite de escopo registrado."
            : "Escopo aceito; a comparação com a última leitura ainda não está disponível.";
        return new(available, read, accepted, message);
    }
}
