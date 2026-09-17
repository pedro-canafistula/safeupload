using System.ComponentModel;
using System.Windows;
using SafeUpload.Agent.App.ViewModels;

namespace SafeUpload.Agent.App.Views;

/// <summary>
/// O painel do agente.
///
/// Fechar esta janela não encerra o agente. O botão de fechar da barra de
/// título apenas a oculta, e a proteção continua: um usuário que fecha o
/// painel está dizendo que terminou de olhar, não que quer desligar a
/// prevenção de vazamento. Encerrar de verdade só pelo item "Sair" da bandeja.
/// </summary>
public partial class AgentWindow : Window
{
    private readonly AgentViewModel _viewModel;

    /// <summary>Cria o painel sobre o modelo de visão informado.</summary>
    public AgentWindow(AgentViewModel viewModel)
    {
        _viewModel = viewModel ?? throw new ArgumentNullException(nameof(viewModel));

        InitializeComponent();
        DataContext = _viewModel;
    }

    /// <summary>
    /// Quando verdadeiro, o fechamento encerra de fato — é o caminho do item
    /// "Sair" da bandeja, que desliga o agente inteiro.
    /// </summary>
    public bool AllowClose { get; set; }

    /// <inheritdoc />
    protected override void OnClosing(CancelEventArgs e)
    {
        if (!AllowClose)
        {
            e.Cancel = true;
            Hide();
            return;
        }

        base.OnClosing(e);
    }
}
