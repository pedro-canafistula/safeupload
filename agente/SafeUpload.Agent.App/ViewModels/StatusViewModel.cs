using SafeUpload.Agent.App.Mvvm;
using SafeUpload.Agent.Core.Application;

namespace SafeUpload.Agent.App.ViewModels;

/// <summary>
/// A tela de status: o estado da proteção agora e as interceptações recentes.
/// </summary>
public sealed class StatusViewModel : ObservableObject
{
    private readonly IPolicyStore _policyStore;
    private readonly IAuditSink _auditSink;

    /// <summary>Compõe a tela sobre a política e a trilha de auditoria.</summary>
    public StatusViewModel(IPolicyStore policyStore, IAuditSink auditSink)
    {
        _policyStore = policyStore ?? throw new ArgumentNullException(nameof(policyStore));
        _auditSink = auditSink ?? throw new ArgumentNullException(nameof(auditSink));
    }

    /// <summary>Carrega política e atividade recente.</summary>
    public Task LoadAsync() => Task.CompletedTask;
}
