using System.IO;
using System.Windows;
using SafeUpload.Agent.App.ClipboardWatch;
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
/// A partir da separação em dois processos, este aplicativo mostra o estado
/// e recebe justificativas. Ele não intercepta, não inspeciona e não decide:
/// quem faz isso é o serviço <c>SafeUploadAgent</c>, que continua funcionando
/// com esta janela fechada. A justificativa vai por um pipe separado, e o
/// serviço valida o ID do bloqueio antes de conceder uma nova tentativa.
///
/// A consequência prática é a lista de dependências: não há mais
/// <c>InspectionService</c>, <c>ContentScanner</c> nem extratores neste projeto.
/// Se algum deles reaparecer, alguma decisão voltou para o lado errado.
/// </summary>
public partial class App : System.Windows.Application
{
    private readonly LocalQueueAuditSink _auditSink = new();
    private readonly PipeClient _pipe = new();
    private readonly ClipboardMonitor _clipboard = new(new ClipboardPipeClient());

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

        // Observa o clipboard e o foco e pergunta ao serviço. Na Fase 1 não
        // altera nada para o usuário; com a política em "Off" (o padrão) o
        // serviço responde "limpo" a tudo.
        _clipboard.Start();

        _tray.ShowBalloon("SafeUpload", "Painel do agente ativo na bandeja do sistema.");
    }

    /// <inheritdoc />
    protected override void OnExit(ExitEventArgs e)
    {
        _pipe.NotificationReceived -= OnNotificationReceived;
        _pipe.ConnectionChanged -= OnConnectionChanged;
        _ = _pipe.DisposeAsync().AsTask();

        _clipboard.Dispose();
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

                case TransferNotification transfer:
                    ShowTransferNotification(transfer);
                    break;
            }
        });
    }

    private void ShowTransferNotification(TransferNotification transfer)
    {
        if (_tray is null)
        {
            return;
        }

        string fileName = Path.GetFileName(transfer.FileName);

        switch (transfer.Phase)
        {
            case TransferPhase.Analyzing:
                _tray.ShowBalloon("SafeUpload: analisando arquivo",
                    $"{fileName} foi salvo localmente. Aguarde a análise antes do envio.");
                break;
            case TransferPhase.Released:
                _tray.ShowBalloon("SafeUpload: envio concluído",
                    $"{fileName} foi analisado e enviado ao destino. SHA-256: {transfer.PublishedSha256Hex ?? "indisponível"}");
                break;
            case TransferPhase.Retained:
                _tray.ShowBalloon("SafeUpload: envio pendente",
                    $"{fileName} permanece guardado localmente. O envio será tentado novamente.");
                break;
            // A janela de bloqueio detalha o motivo; no status, o arquivo
            // continua somente no armazenamento local de staging.
            case TransferPhase.Blocked:
                _tray.ShowBalloon("SafeUpload: envio bloqueado",
                    $"{fileName} não foi enviado ao destino.");
                ShowStagedBlockNotification(transfer);
                break;
        }
    }

    private void ShowStagedBlockNotification(TransferNotification transfer)
    {
        string? eventId = transfer.OverrideAllowed ? transfer.TransferId.ToString("D") : null;
        var findings = transfer.Findings ?? [];
        if (_notification is { IsLoaded: true })
        {
            _notification.Add(transfer.FileName, findings, eventId, quarantined: true, staged: true,
                handbackPath: transfer.HandbackPath, handbackVerified: transfer.HandbackVerified,
                snapshotSha256Hex: transfer.SnapshotSha256Hex);
            return;
        }
        _notification = new BlockNotificationWindow(transfer.FileName, findings,
            eventId, quarantined: true, staged: true,
            handbackPath: transfer.HandbackPath, handbackVerified: transfer.HandbackVerified,
            snapshotSha256Hex: transfer.SnapshotSha256Hex);
        _notification.Closed += (_, _) => _notification = null;
        if (_panel is { IsVisible: true }) _notification.Owner = _panel;
        _notification.Show();
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
    /// RN-005 — todo bloqueio notifica. Quando a política permite, a janela
    /// envia uma justificativa para que o serviço autorize uma nova tentativa.
    /// </summary>
    private void ShowBlockNotification(EventNotification notification)
    {
        // Os achados chegam prontos do serviço, já mascarados e já com a
        // categoria de cada trecho. O aplicativo não recompõe esse par: fazer
        // isso a partir das duas listas do evento erraria justamente quando há
        // mais de um achado da mesma categoria.
        if (_notification is { IsLoaded: true })
        {
            // Já há uma notificação na tela: ela absorve este bloqueio em vez
            // de uma segunda janela nascer por cima. Copiar uma pasta com dez
            // arquivos sensíveis produziria dez janelas empilhadas no mesmo
            // canto, e o usuário fecharia uma por uma sem ler nenhuma.
            _notification.Add(
                notification.Event.FileName,
                notification.Findings,
                notification.OverrideAllowed ? notification.Event.EventId.ToString("D") : null,
                notification.Quarantined);
            return;
        }

        _notification = new BlockNotificationWindow(
            notification.Event.FileName,
            notification.Findings,
            notification.OverrideAllowed ? notification.Event.EventId.ToString("D") : null,
            quarantined: notification.Quarantined);

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
