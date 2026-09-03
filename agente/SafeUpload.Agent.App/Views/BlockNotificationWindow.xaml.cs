using System.Windows;
using SafeUpload.Agent.App.ViewModels;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.App.Views;

/// <summary>
/// A notificação de bloqueio (HU-05).
///
/// Aparece ancorada no canto inferior direito da área de trabalho útil, acima
/// das outras janelas e fora da barra de tarefas: é uma notificação do sistema,
/// não um documento que o usuário abriu. E não toma o foco — ver
/// <c>ShowActivated</c> no XAML.
///
/// Uma janela por vez. Copiar uma pasta com dez arquivos sensíveis produz dez
/// bloqueios em poucos segundos, e dez janelas empilhadas no mesmo canto não
/// informam nada: a de cima esconde as outras e o usuário fecha uma por uma
/// sem ler. Em vez disso a janela existente se agrega — passa a dizer quantos
/// arquivos foram bloqueados e junta as categorias.
/// </summary>
public partial class BlockNotificationWindow : Window
{
    private const double ScreenMargin = 16;

    private readonly List<string> _fileNames = [];
    private readonly List<FindingViewModel> _findings = [];

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

        QuarantineText.Visibility = quarantined ? Visibility.Visible : Visibility.Collapsed;

        Add(fileName, findings);

        // A área útil exclui a barra de tarefas, então a notificação não fica
        // escondida atrás dela nem em telas com a barra em outra borda.
        Loaded += (_, _) => Reposition();
    }

    /// <summary>
    /// Acrescenta mais um bloqueio a esta notificação, em vez de abrir outra.
    /// </summary>
    public void Add(string fileName, IReadOnlyList<Finding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);

        if (!string.IsNullOrEmpty(fileName))
        {
            _fileNames.Add(fileName);
        }

        foreach (var finding in findings)
        {
            var view = new FindingViewModel(CategoryLabels.Describe(finding.Category), finding.MaskedSnippet);

            // Dez arquivos com o mesmo CPF renderiam dez linhas idênticas.
            // Repetir o mesmo achado não acrescenta informação nenhuma.
            if (!_findings.Contains(view))
            {
                _findings.Add(view);
            }
        }

        SummaryText.Text = _fileNames.Count == 1
            ? _fileNames[0]
            : $"{_fileNames.Count} arquivos bloqueados";

        // Reatribuir a fonte é o que faz a lista redesenhar: a coleção local é
        // simples, e uma ObservableCollection aqui só acrescentaria maquinaria
        // para uma janela que vive segundos.
        FindingsList.ItemsSource = null;
        FindingsList.ItemsSource = _findings;

        if (IsLoaded)
        {
            // A janela cresceu ao ganhar linhas; sem reposicionar, a borda de
            // baixo passaria por trás da barra de tarefas.
            Dispatcher.BeginInvoke(Reposition);
        }
    }

    private void Reposition()
    {
        var area = SystemParameters.WorkArea;

        Left = area.Right - Width - ScreenMargin;
        Top = area.Bottom - ActualHeight - ScreenMargin;
    }

    private void Acknowledge_Click(object sender, RoutedEventArgs e) => Close();
}
