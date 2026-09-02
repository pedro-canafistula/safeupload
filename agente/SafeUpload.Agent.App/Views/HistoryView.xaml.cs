using System.Windows.Controls;
using SafeUpload.Agent.App.ViewModels;

namespace SafeUpload.Agent.App.Views;

/// <summary>A tela de histórico de auditoria do painel do agente.</summary>
public partial class HistoryView : UserControl
{
    /// <summary>Cria a tela.</summary>
    public HistoryView()
    {
        InitializeComponent();

        // Recarrega ao aparecer, para que a trilha mostrada seja a do disco
        // agora e não a de quando o painel foi construído.
        Loaded += async (_, _) =>
        {
            if (DataContext is HistoryViewModel viewModel)
            {
                await viewModel.LoadAsync();
            }
        };
    }
}
