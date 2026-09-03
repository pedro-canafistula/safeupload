using System.Collections.ObjectModel;
using SafeUpload.Agent.App.Mvvm;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.App.ViewModels;

/// <summary>
/// A tela de status: o estado da proteção agora e as interceptações recentes.
/// </summary>
public sealed class StatusViewModel : ObservableObject
{
    /// <summary>Quantas operações a tabela de atividade mostra.</summary>
    public const int RecentActivityCount = 8;

    private readonly IPolicyStore _policyStore;
    private readonly IAuditSink _auditSink;

    private string _policyVersion = "—";
    private string _activeCategoriesCaption = "POLÍTICA NÃO CARREGADA";
    private bool _policyLoaded;

    /// <summary>Compõe a tela sobre a política e a trilha de auditoria.</summary>
    public StatusViewModel(IPolicyStore policyStore, IAuditSink auditSink)
    {
        _policyStore = policyStore ?? throw new ArgumentNullException(nameof(policyStore));
        _auditSink = auditSink ?? throw new ArgumentNullException(nameof(auditSink));
    }

    /// <summary>As operações recentes, da mais nova para a mais antiga.</summary>
    public ObservableCollection<ActivityRowViewModel> RecentActivity { get; } = [];

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

    /// <summary>
    /// Falso quando a política não pôde ser carregada. O cartão mostra o
    /// problema em vez de um número inventado: um agente que exibe "v1" sem ter
    /// lido política nenhuma mente sobre o próprio estado.
    /// </summary>
    public bool PolicyLoaded
    {
        get => _policyLoaded;
        private set => SetProperty(ref _policyLoaded, value);
    }

    /// <summary>Verdadeiro quando não há nenhuma operação registrada ainda.</summary>
    public bool HasNoActivity => RecentActivity.Count == 0;

    /// <summary>Carrega política e atividade recente.</summary>
    public async Task LoadAsync()
    {
        await LoadPolicyAsync().ConfigureAwait(true);
        await LoadActivityAsync().ConfigureAwait(true);
    }

    /// <summary>
    /// Insere uma operação recém-interceptada no topo da lista, mantendo o
    /// tamanho da tabela.
    ///
    /// Precisa ser chamado na thread da interface: quem intercepta é um
    /// FileSystemWatcher, que dispara numa thread de fundo, e uma
    /// ObservableCollection alterada fora da thread da UI lança na hora.
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

    private async Task LoadPolicyAsync()
    {
        try
        {
            var policy = await _policyStore.LoadAsync(CancellationToken.None).ConfigureAwait(true);

            PolicyVersion = $"v{policy.Version}";
            ActiveCategoriesCaption = $"{policy.ActiveCategories.Count} CATEGORIAS ATIVAS";
            PolicyLoaded = true;
        }
        catch (Exception)
        {
            // RN-009 chega aqui quando alguém edita o policy.json à mão e deixa
            // a política sem categoria ativa.
            PolicyVersion = "—";
            ActiveCategoriesCaption = "POLÍTICA INVÁLIDA";
            PolicyLoaded = false;
        }
    }

    private async Task LoadActivityAsync()
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
}
