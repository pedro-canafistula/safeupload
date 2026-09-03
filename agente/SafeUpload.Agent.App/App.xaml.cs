using System.Windows;
using SafeUpload.Agent.App.ViewModels;
using SafeUpload.Agent.App.Views;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.App;

/// <summary>
/// Ponto de entrada e composition root do aplicativo de bandeja.
///
/// A partir da separação em dois processos, este aplicativo é um <b>visor</b>.
/// Ele não intercepta, não inspeciona e não decide: quem faz isso é o serviço
/// <c>SafeUploadAgent</c>, que roda como LocalSystem e continua funcionando com
/// esta janela fechada. Nada que o usuário clique aqui altera um veredito,
/// porque não existe caminho de volta até o serviço.
///
/// A consequência prática é a lista de dependências: não há mais
/// <c>InspectionService</c>, <c>ContentScanner</c> nem extratores neste projeto.
/// Se algum deles reaparecer, alguma decisão voltou para o lado errado.
/// </summary>
public partial class App : System.Windows.Application
{
    private readonly LocalPolicyStore _policyStore = new();
    private readonly LocalQueueAuditSink _auditSink = new();

    private AgentViewModel? _agentViewModel;
    private AgentWindow? _panel;
    private TrayIconHost? _tray;
    private BlockNotificationWindow? _notification;

    /// <inheritdoc />
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        _agentViewModel = new AgentViewModel(
            new StatusViewModel(_policyStore, _auditSink),
            new HistoryViewModel(_auditSink));

        // O painel é construído no arranque e mantido oculto. O modelo de visão
        // precisa existir desde já para acumular o que o serviço anunciar
        // enquanto a janela estiver fechada.
        _panel = new AgentWindow(_agentViewModel);

        _ = _agentViewModel.LoadAsync();

        _tray = new TrayIconHost(OpenPanel, ExitAgent);
        _tray.ShowBalloon("SafeUpload", "Proteção ativa. O agente está na bandeja do sistema.");
    }

    /// <inheritdoc />
    protected override void OnExit(ExitEventArgs e)
    {
        _tray?.Dispose();
        base.OnExit(e);
    }

    private void OpenPanel()
    {
        if (_panel is null)
        {
            return;
        }

        _panel.Show();

        if (_panel.WindowState == WindowState.Minimized)
        {
            _panel.WindowState = WindowState.Normal;
        }

        _panel.Activate();
    }

    /// <summary>
    /// RN-005 — todo bloqueio notifica. A janela não tem nenhuma forma de
    /// liberar o arquivo; ela existe para o usuário saber por que a operação
    /// não passou.
    ///
    /// Quem chama isto passa a ser o cliente do pipe, na etapa seguinte da
    /// separação: o aplicativo não descobre mais o bloqueio sozinho, ele é
    /// avisado pelo serviço.
    /// </summary>
    private void ShowBlockNotification(string fileName, IReadOnlyList<Finding> findings, bool quarantined)
    {
        // Uma notificação por vez. Vários bloqueios seguidos empilhariam
        // janelas no mesmo canto da tela, sobrepostas e ilegíveis.
        _notification?.Close();

        _notification = new BlockNotificationWindow(fileName, findings, quarantined);
        _notification.Closed += (_, _) => _notification = null;

        if (_panel is { IsVisible: true })
        {
            _notification.Owner = _panel;
        }

        _notification.Show();
    }

    private void ExitAgent()
    {
        // Encerramento explícito: é a única forma de fechar o visor, já que
        // ShutdownMode é OnExplicitShutdown e o painel apenas se oculta ao ser
        // fechado. Isto encerra a interface, não a proteção — quem protege é o
        // serviço, e ele continua rodando.
        if (_panel is not null)
        {
            _panel.AllowClose = true;
            _panel.Close();
        }

        Shutdown();
    }
}
