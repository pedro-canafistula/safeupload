using System.Windows.Controls;

namespace SafeUpload.Agent.App.Views;

/// <summary>A tela de histórico de auditoria do painel do agente.</summary>
public partial class HistoryView : UserControl
{
    /// <summary>Cria a tela.</summary>
    public HistoryView()
    {
        InitializeComponent();

        // History is supplied by the service, not by the interactive user's
        // filesystem permissions. Switching tabs preserves the current model.
    }
}
