using System.Windows;
using System.Windows.Controls;
using SafeUpload.Agent.App.Notifications;
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
/// arquivos foram bloqueados e junta as categorias. A justificativa, quando
/// permitida, sempre nomeia o bloqueio mais recente.
/// </summary>
public partial class BlockNotificationWindow : Window
{
    private const double ScreenMargin = 16;

    private readonly List<string> _fileNames = [];
    private readonly List<FindingViewModel> _findings = [];
    private string? _justificationEventId;
    private bool _staged;

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
    public BlockNotificationWindow(
        string fileName,
        IReadOnlyList<Finding> findings,
        string? justificationEventId = null,
        bool quarantined = false,
        bool staged = false,
        string? handbackPath = null,
        bool? handbackVerified = null,
        string? snapshotSha256Hex = null,
        InspectionFailureKind? inspectionFailure = null)
    {
        ArgumentNullException.ThrowIfNull(findings);

        InitializeComponent();

        Add(fileName, findings, justificationEventId, quarantined, staged,
            handbackPath, handbackVerified, snapshotSha256Hex, inspectionFailure);

        // A área útil exclui a barra de tarefas, então a notificação não fica
        // escondida atrás dela nem em telas com a barra em outra borda.
        Loaded += (_, _) => Reposition();
    }

    /// <summary>
    /// Acrescenta mais um bloqueio a esta notificação, em vez de abrir outra.
    /// </summary>
    public void Add(
        string fileName,
        IReadOnlyList<Finding> findings,
        string? justificationEventId = null,
        bool quarantined = false,
        bool staged = false,
        string? handbackPath = null,
        bool? handbackVerified = null,
        string? snapshotSha256Hex = null,
        InspectionFailureKind? inspectionFailure = null)
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

        // A notificação agrega vários bloqueios. A justificativa sempre
        // nomeia o evento mais recente para não conceder uma exceção a um
        // arquivo diferente daquele mostrado ao lado do campo.
        _justificationEventId = justificationEventId;
        _staged = staged;
        bool incomplete = staged && inspectionFailure is not null;
        InspectionFailureText.Visibility = incomplete ? Visibility.Visible : Visibility.Collapsed;
        string failureMessage = inspectionFailure switch
        {
            InspectionFailureKind.TooLarge => "O arquivo ultrapassa o limite de inspeção atual.",
            InspectionFailureKind.UnsupportedFormat => "Não há suporte para inspecionar este formato.",
            InspectionFailureKind.Timeout => "A análise não terminou dentro do prazo.",
            InspectionFailureKind.Limit => "O conteúdo excedeu a capacidade de análise completa desta versão.",
            _ => "Não foi possível ler ou analisar todo o arquivo."
        };
        InspectionFailureText.Text = _fileNames.Count == 1
            ? "Inspeção incompleta: " + failureMessage
            : $"Inspeção incompleta no último arquivo ({fileName}): {failureMessage}";
        FindingsHeading.Visibility = _findings.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        FindingsHeading.Text = _fileNames.Count == 1 ? "O que foi encontrado" : "Achados nos arquivos bloqueados";
        FindingsList.Visibility = _findings.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        GuidanceText.Text = incomplete
            ? "A versão não foi enviada ao destino. Tente salvar novamente ou peça ajuda ao administrador para concluir a análise."
            : "Revise o arquivo, remova ou anonimize as informações e tente novamente.";
        JustificationHelpText.Text = incomplete
            ? "Informe o motivo de negócio para autorizar o envio desta versão mesmo se sua análise não puder ser concluída."
            : "Informe o motivo de negócio para tentar novamente.";
        QuarantineText.Visibility = quarantined ? Visibility.Visible : Visibility.Collapsed;
        QuarantineText.Text = staged
            ? handbackVerified == true && !string.IsNullOrWhiteSpace(handbackPath)
                ? $"Devolvido para: {handbackPath}\nSHA-256: {snapshotSha256Hex ?? "indisponível"}"
                : "Não foi possível devolver o arquivo com segurança. A versão permanece no staging protegido do SafeUpload e não foi enviada ao destino."
            : "O arquivo foi retirado da pasta monitorada e guardado em SafeUpload\\_bloqueados na sua pasta de usuário.";
        JustificationPanel.Visibility = justificationEventId is null
            ? Visibility.Collapsed
            : Visibility.Visible;
        JustificationTargetText.Text = $"Justificar: {fileName}";
        JustificationInput.Text = string.Empty;
        JustificationInput.IsEnabled = true;
        JustificationStatusText.Text = string.Empty;

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

    private void JustificationInput_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (SubmitJustificationButton is null)
        {
            return;
        }

        SubmitJustificationButton.IsEnabled =
            _justificationEventId is not null &&
            JustificationInput.IsEnabled &&
            !string.IsNullOrWhiteSpace(JustificationInput.Text);
    }

    private async void SubmitJustification_Click(object sender, RoutedEventArgs e)
    {
        string? eventId = _justificationEventId;
        string reason = JustificationInput.Text.Trim();

        if (eventId is null || reason.Length == 0)
        {
            return;
        }

        SubmitJustificationButton.IsEnabled = false;
        JustificationStatusText.Text = "Enviando ao serviço...";

        try
        {
            await JustificationPipeClient.SendAsync(eventId, reason);

            if (_justificationEventId == eventId)
            {
                JustificationInput.IsEnabled = false;
                JustificationStatusText.Text =
                    _staged ? "Justificativa aceita. A versão devolvida foi enviada."
                            : "Justificativa aceita. Tente a operação novamente.";
            }
        }
        catch (Exception)
        {
            if (_justificationEventId == eventId)
            {
                JustificationStatusText.Text =
                    "O serviço não aceitou a justificativa. O bloqueio pode ter expirado; tente iniciar a operação novamente.";
                SubmitJustificationButton.IsEnabled = true;
            }
        }
    }
}
