using System.IO;
using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;
using SafeUpload.Agent.App.ViewModels;

namespace SafeUpload.Agent.App.Views;

/// <summary>
/// A janela do simulador.
///
/// O código aqui cuida só do que é próprio da janela — arrastar e soltar e a
/// caixa de escolher arquivo, que são gestos e não estado. A decisão e o
/// resultado ficam no <see cref="SimulatorViewModel"/>.
/// </summary>
public partial class SimulatorWindow : Window
{
    private readonly SimulatorViewModel _viewModel;

    /// <summary>Abre o simulador sobre o modelo de visão informado.</summary>
    public SimulatorWindow(SimulatorViewModel viewModel)
    {
        _viewModel = viewModel ?? throw new ArgumentNullException(nameof(viewModel));

        InitializeComponent();
        DataContext = _viewModel;

        // A janela abre já com política, escopo e fila carregados.
        Loaded += async (_, _) => await _viewModel.InitializeAsync();
    }

    private async void DropZone_Drop(object sender, DragEventArgs e)
    {
        ResetDropZoneBorder();

        if (e.Data.GetData(DataFormats.FileDrop) is not string[] paths || paths.Length == 0)
        {
            return;
        }

        // Uma pasta arrastada não é uma operação de arquivo; ignora em silêncio
        // em vez de tentar inspecionar um diretório.
        var file = paths.FirstOrDefault(File.Exists);
        if (file is null)
        {
            return;
        }

        await _viewModel.InspectAsync(file);
    }

    private void DropZone_DragOver(object sender, DragEventArgs e)
    {
        var isFile = e.Data.GetDataPresent(DataFormats.FileDrop);

        e.Effects = isFile ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;

        if (isFile && TryFindBrush("Accent") is { } accent)
        {
            DropZone.BorderBrush = accent;
        }
    }

    private void DropZone_DragLeave(object sender, DragEventArgs e) => ResetDropZoneBorder();

    private void ResetDropZoneBorder()
    {
        if (TryFindBrush("Border") is { } border)
        {
            DropZone.BorderBrush = border;
        }
    }

    private Brush? TryFindBrush(string key) => TryFindResource(key) as Brush;

    private async void SelectFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Escolha o arquivo a enviar",
            Filter = "Formatos inspecionados (*.txt;*.csv;*.docx;*.xlsx)|*.txt;*.csv;*.docx;*.xlsx"
                     + "|Todos os arquivos (*.*)|*.*",
            CheckFileExists = true
        };

        if (dialog.ShowDialog(this) == true)
        {
            await _viewModel.InspectAsync(dialog.FileName);
        }
    }
}
