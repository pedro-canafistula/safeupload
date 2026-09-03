using System.Windows;
using SafeUpload.Agent.App.Notifications;
using SafeUpload.Agent.App.ViewModels;
using SafeUpload.Agent.App.Views;
using SafeUpload.Agent.Core.Contracts;
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
/// porque o canal com o serviço não tem caminho de volta.
///
/// A consequência prática é a lista de dependências: não há mais
/// <c>InspectionService</c>, <c>ContentScanner</c> nem extratores neste projeto.
/// Se algum deles reaparecer, alguma decisão voltou para o lado errado.
/// </summary>
public partial class App : System.Windows.Application
{
    private readonly LocalQueueAuditSink _auditSink = new();
    private readonly PipeClient _pipe = new();

    private AgentViewModel? _agentViewModel;
    private AgentWindow? _panel;
    private TrayIconHost? _tray;
    private BlockNotificationWindow? _notification;

    /// <inheritdoc />
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        _agentViewModel = new AgentViewModel(
            new StatusViewModel(_auditSink),
            new HistoryViewModel(_auditSink));

        // O painel é construído no arranque e mantido oculto. O modelo de visão
        // precisa existir desde já para acumular o que o serviço anunciar
        // enquanto a janela estiver fechada.
        _panel = new AgentWindow(_agentViewModel);

        _ = _agentViewModel.LoadAsync();

        _tray = new TrayIconHost(OpenPanel, ExitAgent);

        _pipe.NotificationReceived += OnNotificationReceived;
        _pipe.ConnectionChanged += OnConnectionChanged;
        _pipe.Start();

        _tray.ShowBalloon("SafeUpload", "Painel do agente ativo na bandeja do sistema.");
    }

    /// <inheritdoc />
    protected override void OnExit(ExitEventArgs e)
    {
        _pipe.NotificationReceived -= OnNotificationReceived;
        _pipe.ConnectionChanged -= OnConnectionChanged;
        _ = _pipe.DisposeAsync().AsTask();

        _tray?.Dispose();
        base.OnExit(e);
    }

    /// <summary>
    /// Chegou uma mensagem do serviço.
    ///
    /// O cliente do pipe lê numa thread de fundo, e uma
    /// <c>ObservableCollection</c> alterada fora da thread da interface lança
    /// na hora — não é uma corrida rara que às vezes passa, é falha imediata.
    /// Por isso tudo o que toca o modelo de visão passa pelo Dispatcher.
    /// </summary>
    private void OnNotificationReceived(object? sender, AgentNotification notification)
    {
        Current.Dispatcher.Invoke(() =>
        {
            if (_agentViewModel is null)
            {
                return;
            }

            switch (notification)
            {
                case StatusNotification status:
                    _agentViewModel.Status.ApplyStatus(status);
                    break;

                case EventNotification evento:
                    _agentViewModel.Status.PrependActivity(evento.Event);
                    _agentViewModel.History.Prepend(evento.Event);

                    // RN-005 — todo bloqueio notifica, com o painel aberto ou
                    // fechado.
                    if (evento.Event.Verdict == Verdict.Blocked)
                    {
                        ShowBlockNotification(evento);
                    }

                    break;
            }
        });
    }

    private void OnConnectionChanged(object? sender, bool connected)
    {
        if (connected)
        {
            // O estado real chega logo em seguida, na mensagem de status que o
            // serviço envia assim que aceita a conexão.
            return;
        }

        Current.Dispatcher.Invoke(() => _agentViewModel?.Status.SetDisconnected());
    }

    /// <summary>
    /// RN-005 — todo bloqueio notifica. A janela não tem nenhuma forma de
    /// liberar o arquivo; ela existe para o usuário saber por que a operação
    /// não passou.
    /// </summary>
    private void ShowBlockNotification(EventNotification notification)
    {
        // Uma notificação por vez. Vários bloqueios seguidos empilhariam
        // janelas no mesmo canto da tela, sobrepostas e ilegíveis.
        _notification?.Close();

        // Os achados chegam prontos do serviço, já mascarados e já com a
        // categoria de cada trecho. O aplicativo não recompõe esse par: fazer
        // isso a partir das duas listas do evento erraria justamente quando há
        // mais de um achado da mesma categoria.
        _notification = new BlockNotificationWindow(
            notification.Event.FileName,
            notification.Findings,
            quarantined: true);
        _notification.Closed += (_, _) => _notification = null;

        if (_panel is { IsVisible: true })
        {
            _notification.Owner = _panel;
        }

        _notification.Show();
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
