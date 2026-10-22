using System.Windows.Controls;

namespace SafeUpload.Agent.App.Views;

/// <summary>A tela de status do painel do agente.</summary>
public partial class StatusView : UserControl
{
    /// <summary>Cria a tela.</summary>
    public StatusView()
    {
        InitializeComponent();

        // The shared view model is updated by the service pipe, including
        // while this view is hidden. Navigation never reads private files.
    }
}
