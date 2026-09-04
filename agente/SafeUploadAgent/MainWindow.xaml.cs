using System.Windows;
using System.Windows.Input;
using System.Windows.Media;

namespace SafeUploadAgent
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        // Permite arrastar a janela clicando na barra de título customizada,
        // e maximizar/restaurar com duplo clique.
        private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ClickCount == 2)
            {
                MaximizeRestore_Click(sender, e);
            }
            else if (e.LeftButton == MouseButtonState.Pressed)
            {
                DragMove();
            }
        }

        private void Minimize_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void MaximizeRestore_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState == WindowState.Maximized
                ? WindowState.Normal
                : WindowState.Maximized;
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        // Alterna o destaque (azul) entre os itens do menu lateral e troca a view exibida
        private void NavStatus_Click(object sender, RoutedEventArgs e)
        {
            NavStatusButton.Background = (Brush)new BrushConverter().ConvertFrom("#2563EB")!;
            NavStatusButton.Foreground = Brushes.White;

            NavHistoricoButton.Background = Brushes.Transparent;
            NavHistoricoButton.Foreground = (Brush)new BrushConverter().ConvertFrom("#374151")!;

            StatusView.Visibility = Visibility.Visible;
            HistoricoView.Visibility = Visibility.Collapsed;
        }

        private void NavHistorico_Click(object sender, RoutedEventArgs e)
        {
            NavHistoricoButton.Background = (Brush)new BrushConverter().ConvertFrom("#2563EB")!;
            NavHistoricoButton.Foreground = Brushes.White;

            NavStatusButton.Background = Brushes.Transparent;
            NavStatusButton.Foreground = (Brush)new BrushConverter().ConvertFrom("#374151")!;

            HistoricoView.Visibility = Visibility.Visible;
            StatusView.Visibility = Visibility.Collapsed;
        }
    }
}
