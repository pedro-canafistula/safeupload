using SafeUpload.Agent.App.Mvvm;
using SafeUpload.Agent.Core.Application;

namespace SafeUpload.Agent.App.ViewModels;

/// <summary>
/// A tela de histórico: a trilha de auditoria completa, só leitura.
/// </summary>
public sealed class HistoryViewModel : ObservableObject
{
    private readonly IAuditSink _auditSink;

    /// <summary>Compõe a tela sobre a trilha de auditoria.</summary>
    public HistoryViewModel(IAuditSink auditSink) =>
        _auditSink = auditSink ?? throw new ArgumentNullException(nameof(auditSink));

    /// <summary>Carrega o histórico gravado.</summary>
    public Task LoadAsync() => Task.CompletedTask;
}
