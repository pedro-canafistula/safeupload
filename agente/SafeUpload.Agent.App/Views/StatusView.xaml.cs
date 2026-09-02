using System.Windows.Controls;
using SafeUpload.Agent.App.ViewModels;

namespace SafeUpload.Agent.App.Views;

/// <summary>A tela de status do painel do agente.</summary>
public partial class StatusView : UserControl
{
    /// <summary>Cria a tela.</summary>
    public StatusView()
    {
        InitializeComponent();

        // A tela é recriada a cada troca de aba pelo DataTemplate, então ela
        // recarrega ao aparecer. Assim, voltar para o Status depois de olhar o
        // histórico mostra o estado de agora, e não o de quando o painel abriu.
        Loaded += async (_, _) =>
        {
            if (DataContext is StatusViewModel viewModel)
            {
                await viewModel.LoadAsync();
            }
        };
    }
}
