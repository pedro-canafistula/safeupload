using System.Collections.ObjectModel;
using SafeUpload.Agent.App.Mvvm;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.App.ViewModels;

/// <summary>
/// A tela de status: o estado da proteção agora e as interceptações recentes.
///
/// Nada aqui é descoberto pelo aplicativo. A versão da política, a contagem de
/// categorias e o próprio fato de haver proteção ativa chegam do serviço pelo
/// canal de notificação; a atividade recente vem dos eventos que ele anuncia.
/// O aplicativo lê a trilha em disco uma vez, ao abrir, só para não começar
/// vazio.
/// </summary>
public sealed class StatusViewModel : ObservableObject
{
    /// <summary>Quantas operações a tabela de atividade mostra.</summary>
    public const int RecentActivityCount = 8;

    private readonly IAuditSink _auditSink;

    private string _securityState = "Aguardando o serviço";
    private string _securityCaption = "CONECTANDO";
    private string _policyVersion = "—";
    private string _activeCategoriesCaption = "AGUARDANDO O SERVIÇO";
    private string _monitoringState = "AGUARDANDO";
    private bool _connected;

    /// <summary>Compõe a tela sobre a trilha de auditoria.</summary>
    public StatusViewModel(IAuditSink auditSink) =>
        _auditSink = auditSink ?? throw new ArgumentNullException(nameof(auditSink));

    /// <summary>As operações recentes, da mais nova para a mais antiga.</summary>
    public ObservableCollection<ActivityRowViewModel> RecentActivity { get; } = [];

    /// <summary>Valor em destaque do cartão de segurança.</summary>
    public string SecurityState
    {
        get => _securityState;
        private set => SetProperty(ref _securityState, value);
    }

    /// <summary>Legenda do cartão de segurança.</summary>
    public string SecurityCaption
    {
        get => _securityCaption;
        private set => SetProperty(ref _securityCaption, value);
    }

    /// <summary>Versão da política em vigor, no formato exibido.</summary>
    public string PolicyVersion
    {
        get => _policyVersion;
        private set => SetProperty(ref _policyVersion, value);
    }

    /// <summary>Legenda do cartão de política, com a contagem de categorias.</summary>
    public string ActiveCategoriesCaption
    {
        get => _activeCategoriesCaption;
        private set => SetProperty(ref _activeCategoriesCaption, value);
    }

    /// <summary>Rótulo do indicador de monitoramento.</summary>
    public string MonitoringState
    {
        get => _monitoringState;
        private set => SetProperty(ref _monitoringState, value);
    }

    /// <summary>
    /// Se o canal com o serviço está de pé. Governa a cor do indicador: só há
    /// verde quando existe alguém do outro lado dizendo que protege.
    /// </summary>
    public bool Connected
    {
        get => _connected;
        private set => SetProperty(ref _connected, value);
    }

    /// <summary>Verdadeiro quando não há nenhuma operação registrada ainda.</summary>
    public bool HasNoActivity => RecentActivity.Count == 0;

    /// <summary>Carrega a atividade já registrada em disco.</summary>
    public async Task LoadAsync()
    {
        var events = await _auditSink
            .ReadRecentAsync(RecentActivityCount, CancellationToken.None)
            .ConfigureAwait(true);

        RecentActivity.Clear();
        foreach (var auditEvent in events)
        {
            RecentActivity.Add(new ActivityRowViewModel(auditEvent));
        }

        OnPropertyChanged(nameof(HasNoActivity));
    }

    /// <summary>
    /// Aplica o estado anunciado pelo serviço.
    /// </summary>
    public void ApplyStatus(StatusNotification status)
    {
        ArgumentNullException.ThrowIfNull(status);

        Connected = true;
        PolicyVersion = $"v{status.PolicyVersion}";
        ActiveCategoriesCaption = $"{status.ActiveCategories} CATEGORIAS ATIVAS";

        // O serviço pode estar no ar sem estar vigiando — política inválida,
        // pasta inacessível. Exibir "Protegido" nesse caso seria a pior forma
        // de erro possível nesta tela: o usuário confiaria numa proteção que
        // não existe.
        if (status.ProtectionActive)
        {
            SecurityState = "Protegido";
            SecurityCaption = "DISPOSITIVO SEGURO";
            MonitoringState = "INTERCEPTANDO";
        }
        else
        {
            SecurityState = "Sem proteção";
            SecurityCaption = "SERVIÇO ATIVO, MAS SEM VIGIAR";
            MonitoringState = "PARADO";
        }
    }

    /// <summary>
    /// Marca a ausência do serviço.
    ///
    /// Mentir sobre proteção ativa é pior do que admitir a falha: um usuário
    /// que vê "Protegido" com o serviço fora do ar copia o arquivo confiante.
    /// </summary>
    public void SetDisconnected()
    {
        Connected = false;
        SecurityState = "Serviço indisponível";
        SecurityCaption = "SEM COMUNICAÇÃO COM O SERVIÇO";
        PolicyVersion = "—";
        ActiveCategoriesCaption = "POLÍTICA DESCONHECIDA";
        MonitoringState = "SEM SERVIÇO";
    }

    /// <summary>
    /// Insere uma operação recém-anunciada no topo da lista, mantendo o
    /// tamanho da tabela.
    ///
    /// Precisa ser chamado na thread da interface: quem recebe a mensagem é o
    /// cliente do pipe, numa thread de fundo, e uma
    /// <c>ObservableCollection</c> alterada fora da thread da interface lança
    /// na hora.
    /// </summary>
    public void PrependActivity(AuditEvent auditEvent)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);

        RecentActivity.Insert(0, new ActivityRowViewModel(auditEvent));

        while (RecentActivity.Count > RecentActivityCount)
        {
            RecentActivity.RemoveAt(RecentActivity.Count - 1);
        }

        OnPropertyChanged(nameof(HasNoActivity));
    }
}
