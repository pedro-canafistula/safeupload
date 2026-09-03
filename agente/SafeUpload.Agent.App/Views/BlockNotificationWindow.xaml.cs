using System.Windows;
using SafeUpload.Agent.App.ViewModels;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.App.Views;

/// <summary>
/// A notificação de bloqueio (HU-05).
///
/// Aparece ancorada no canto inferior direito da área de trabalho útil, acima
/// das outras janelas e fora da barra de tarefas: é uma notificação do sistema,
/// não um documento que o usuário abriu.
/// </summary>
public partial class BlockNotificationWindow : Window
{
    private const double ScreenMargin = 16;

    /// <summary>
    /// Monta a notificação para um bloqueio.
    /// </summary>
    /// <param name="fileName">Arquivo barrado.</param>
    /// <param name="findings">Achados, já mascarados pelo domínio.</param>
    /// <param name="quarantined">
    /// Se o arquivo foi retirado da pasta monitorada. Quando é o caso, a
    /// notificação diz para onde ele foi: o arquivo sumiu de onde o usuário
    /// acabou de colocá-lo, e deixá-lo procurar seria transformar um bloqueio
    /// explicado num arquivo perdido.
    /// </param>
    public BlockNotificationWindow(string fileName, IReadOnlyList<Finding> findings, bool quarantined = false)
    {
        ArgumentNullException.ThrowIfNull(findings);

        InitializeComponent();

        FileNameText.Text = fileName;

        QuarantineText.Visibility = quarantined ? Visibility.Visible : Visibility.Collapsed;
        FindingsList.ItemsSource = findings
            .Select(f => new FindingViewModel(CategoryLabels.Describe(f.Category), f.MaskedSnippet))
            .ToList();

        // A área útil exclui a barra de tarefas, então a notificação não fica
        // escondida atrás dela nem em telas com a barra em outra borda.
        Loaded += (_, _) =>
        {
            var area = SystemParameters.WorkArea;
            Left = area.Right - Width - ScreenMargin;
            Top = area.Bottom - ActualHeight - ScreenMargin;
        };
    }

    private void Acknowledge_Click(object sender, RoutedEventArgs e) => Close();
}
