using SafeUpload.Agent.App.Mvvm;
using SafeUpload.Agent.Core.Contracts;

namespace SafeUpload.Agent.App.ViewModels;

/// <summary>Displays service observations, independently of local protection.</summary>
public sealed class CommunicationViewModel : ObservableObject
{
    private string _heartbeat = "Aguardando o serviço";
    private string _audit = "Aguardando o serviço";
    private string _policy = "Aguardando o serviço";
    private string _summary = "Aguardando informações de comunicação com o backend.";

    public string Heartbeat { get => _heartbeat; private set => SetProperty(ref _heartbeat, value); }
    public string Audit { get => _audit; private set => SetProperty(ref _audit, value); }
    public string Policy { get => _policy; private set => SetProperty(ref _policy, value); }
    public string Summary { get => _summary; private set => SetProperty(ref _summary, value); }

    public void Apply(AdministrationCommunicationStatus? status)
    {
        Heartbeat = Describe(status?.Heartbeat);
        Audit = Describe(status?.Audit);
        Policy = Describe(status?.Policy);
        Summary = status is null ? "Comunicação com o backend não informada pelo serviço." :
            new[] { status.Heartbeat.State, status.Audit.State, status.Policy.State }.Contains(AdministrationOperationState.Failure)
                ? "Backend: falha na última tentativa. O estado da proteção local é informado separadamente."
                : "Comunicação com o backend: resultados das últimas tentativas, sem garantia de conexão contínua.";
    }

    public void SetDisconnected()
    {
        Heartbeat = Audit = Policy = "Serviço indisponível";
        Summary = "Sem comunicação com o serviço Windows; estado do backend desconhecido.";
    }

    private static string Describe(AdministrationOperationStatus? status)
    {
        if (status is null) return "Informação indisponível nesta versão do serviço";
        string text = status.State switch
        {
            AdministrationOperationState.NotConfigured => "Não configurado",
            AdministrationOperationState.NotAttempted => "Aguardando tentativa",
            AdministrationOperationState.InProgress => "Tentativa em andamento",
            AdministrationOperationState.Success => "Última tentativa confirmada",
            AdministrationOperationState.Failure => "Falha na última tentativa",
            AdministrationOperationState.Cancelled => "Última tentativa cancelada",
            _ => "Estado desconhecido"
        };
        if (status.LastAttemptUtc is { } attempted)
            text += $" · tentativa: {attempted.ToLocalTime():dd/MM/yyyy HH:mm:ss}";
        if (status.LastSuccessUtc is { } success)
            text += $" · última confirmação: {success.ToLocalTime():dd/MM/yyyy HH:mm:ss}";
        return text;
    }
}
