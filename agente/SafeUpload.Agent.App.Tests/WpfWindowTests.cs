using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using SafeUpload.Agent.App.ViewModels;
using SafeUpload.Agent.App.Views;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.App.Tests;

public sealed class WpfWindowTests
{
    // Loads the production XAML/resources on STA and renders real WPF controls.
    // No service, fake authenticated pipe, clipboard monitor or tray icon is started.
    // These images are rendering evidence, not delivery through the final VM's pipe.
    [Fact]
    public async Task Real_windows_render_with_resolved_bindings_safe_text_and_accessible_block_details()
    {
        var completed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            try { RenderWindows(); completed.SetResult(); }
            catch (Exception error) { completed.SetException(error); }
        }) { IsBackground = true };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        await completed.Task.WaitAsync(TimeSpan.FromSeconds(40));
    }

    private static void RenderWindows()
    {
        var app = new SafeUpload.Agent.App.App();
        app.InitializeComponent(); // OnStartup/Run is intentionally never invoked.
        var messages = new StringBuilder();
        using var writer = new StringWriter(messages);
        using var trace = new TextWriterTraceListener(writer);
        var source = PresentationTraceSources.DataBindingSource;
        source.Listeners.Add(trace);
        source.Switch.Level = SourceLevels.Error;
        try
        {
            var model = new AgentViewModel(new StatusViewModel(), new HistoryViewModel());
            var statuses = new[] { "published", "blocked", "alert", "incomplete", "unknown", "pending" };
            var events = statuses.Select(Samples.Event).ToArray();
            var wire = NotificationProtocol.Serialize(new HistoryNotification(events));
            model.ApplyHistory((HistoryNotification)NotificationProtocol.Deserialize(wire)!);
            model.Status.ApplyStatus(Samples.Status(true));
            var panel = new AgentWindow(model);
            Render((FrameworkElement)panel.Content, 980, 680, "status-backend-offline.png");
            Assert.True(model.Status.MonitoringActive);
            Assert.Contains("Backend: falha", Texts((DependencyObject)panel.Content));
            Assert.Contains("6 evento(s)", Texts((DependencyObject)panel.Content));

            model.Status.ApplyStatus(Samples.Status(false));
            Render((FrameworkElement)panel.Content, 980, 680, "status-preventive-unavailable.png");
            Assert.False(model.Status.MonitoringActive);
            model.SelectedSection = model.Sections[1];
            Render((FrameworkElement)panel.Content, 980, 680, "history-outcomes.png");
            var grid = Descendants((DependencyObject)panel.Content).OfType<DataGrid>().Single();
            Assert.Equal(6, grid.Items.Count);
            // Nothing in the history is cut or pushed sideways: the grid fits the window and the outcome column
            // is as wide as its longest label.
            Assert.True(grid.Columns.Sum(c => c.ActualWidth) <= grid.ActualWidth + 1, "The history must fit without sideways scrolling.");
            foreach (var label in Descendants(grid).OfType<DataGridCell>().Where(c => c.Column == grid.Columns[0])
                .SelectMany(c => Descendants(c).OfType<TextBlock>()).ToArray())
            {
                label.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
                Assert.True(label.DesiredSize.Width <= grid.Columns[0].ActualWidth, label.Text + " must not be cut.");
            }
            Assert.Contains("PUBLICADO COM ALERTA", Texts(grid));
            Assert.Contains("NÃO CONFIRMADO", Texts(grid));

            var blocked = new BlockNotificationWindow("529.982.247-25.txt", [new Finding(Category.Cpf, "529.982.247-25")],
                quarantined: true, staged: true, handbackPath: @"S:\529.982.247-25.txt", handbackVerified: true, snapshotSha256Hex: Samples.Hash);
            Render((FrameworkElement)blocked.Content, 380, 560, "block-redacted.png");
            Assert.DoesNotContain("529.982.247-25", Texts((DependencyObject)blocked.Content));
            Assert.Equal(Visibility.Collapsed, ((FrameworkElement)blocked.FindName("JustificationPanel")).Visibility);

            var incomplete = new BlockNotificationWindow("invalid.docx", [], quarantined: true, staged: true,
                handbackPath: @"S:\invalid.docx", handbackVerified: true, inspectionFailure: InspectionFailureKind.ReadOrParse);
            Render((FrameworkElement)incomplete.Content, 380, 560, "block-inconclusive.png");
            Assert.Contains("Inspeção inconclusiva", ((TextBlock)incomplete.FindName("HeadingText")).Text);
            Assert.DoesNotContain("remova ou anonimize", ((TextBlock)incomplete.FindName("GuidanceText")).Text);

            var many = new BlockNotificationWindow("many.txt", Enumerable.Range(1, 45)
                .Select(i => new Finding(Category.Cpf, "•••••••••" + i.ToString("00"))).ToArray(), staged: true);
            Render((FrameworkElement)many.Content, 380, 550, "block-scroll.png");
            Assert.Contains(Descendants((DependencyObject)many.Content).OfType<ScrollViewer>(), s => s.ScrollableHeight > 0);
            var scroll = Descendants((DependencyObject)many.Content).OfType<ScrollViewer>().Single();
            scroll.ScrollToEnd();
            Render((FrameworkElement)many.Content, 380, 550, "block-scroll.png");
            var acknowledge = (Button)many.FindName("AcknowledgeButton");
            var position = acknowledge.TransformToAncestor((Visual)many.Content).Transform(new Point());
            Assert.InRange(position.Y + acknowledge.ActualHeight, 1, 550);
            Assert.True(many.MaxHeight <= SystemParameters.WorkArea.Height);

            source.Flush();
            Assert.True(messages.Length == 0, messages.ToString());
        }
        finally
        {
            source.Listeners.Remove(trace);
            app.Shutdown();
        }
    }

    private static void Render(FrameworkElement content, int width, int height, string name)
    {
        bool autoHeight = Window.GetWindow(content)?.SizeToContent == SizeToContent.Height;
        content.Measure(new Size(width, autoHeight ? double.PositiveInfinity : height));
        if (autoHeight)
        {
            height = Math.Min(height, (int)Math.Ceiling(content.DesiredSize.Height));
            // Apply the host's height constraint after measuring SizeToContent, just as
            // Window.MaxHeight does, so the scroll viewer receives a finite viewport.
            content.Measure(new Size(width, height));
        }
        content.Arrange(new Rect(0, 0, width, height));
        content.UpdateLayout();
        content.Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
        var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(content);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        string directory = Environment.GetEnvironmentVariable("SAFEUPLOAD_WPF_SNAPSHOTS") ?? Path.Combine(Path.GetTempPath(), "safeupload-wpf-render");
        Directory.CreateDirectory(directory);
        using var output = File.Create(Path.Combine(directory, name));
        encoder.Save(output);
    }

    private static IEnumerable<DependencyObject> Descendants(DependencyObject node)
    {
        yield return node;
        for (int i = 0; i < VisualTreeHelper.GetChildrenCount(node); i++)
            foreach (var child in Descendants(VisualTreeHelper.GetChild(node, i))) yield return child;
    }
    private static string Texts(DependencyObject node) => string.Join("\n", Descendants(node).OfType<TextBlock>().Select(b => b.Text));
}
