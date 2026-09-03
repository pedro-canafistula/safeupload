using System.Windows;
using SafeUpload.Agent.App.Interception;
using SafeUpload.Agent.App.Simulation;
using SafeUpload.Agent.App.ViewModels;
using SafeUpload.Agent.App.Views;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.App;

/// <summary>
/// Ponto de entrada e composition root do agente.
///
/// A composição é feita à mão, aqui, num único lugar. São poucos objetos com
/// dependências conhecidas em tempo de compilação; um contêiner de injeção
/// trocaria essa clareza por reflexão e adiaria para a execução erros que hoje
/// o compilador pega.
///
/// O que este arquivo escolhe é exatamente o que a integração com o servidor
/// vai trocar depois: LocalPolicyStore por HttpPolicyStore, e o despachante da
/// fila. Nada abaixo daqui muda.
/// </summary>
public partial class App : System.Windows.Application
{
    private readonly LocalPolicyStore _policyStore = new();
    private readonly LocalQueueAuditSink _auditSink = new();
    private readonly VerdictCache _cache = new();

    private InspectionService? _inspection;
    private AgentViewModel? _agentViewModel;
    private AgentWindow? _panel;
    private TrayIconHost? _tray;
    private BlockNotificationWindow? _notification;
    private SimulatedInterceptor? _interceptor;

#if DEBUG
    // Estado exclusivo do simulador. Fora de depuração ele não existe, e por
    // isso nem os campos são declarados: um campo nunca lido viraria aviso do
    // compilador e, pior, sugeriria que o recurso está lá.
    private InspectionService? _stalledInspection;
    private SimulatorWindow? _simulator;
#endif

    /// <inheritdoc />
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        AgentPaths.EnsureRootDirectory();

        var extractors = ExtractorRegistry.CreateDefault();

        _inspection = new InspectionService(_policyStore, _auditSink, extractors, _cache);

#if DEBUG
        // O mesmo motor, com os extratores embrulhados por um atraso de oito
        // segundos. É assim que o simulador demonstra a RN-012 sem que o motor
        // saiba que está sendo simulado.
        _stalledInspection = new InspectionService(
            _policyStore,
            _auditSink,
            StalledTextExtractor.Wrap(extractors, StalledTextExtractor.DefaultDelay),
            _cache);
#endif

        _agentViewModel = new AgentViewModel(
            new StatusViewModel(_policyStore, _auditSink),
            new HistoryViewModel(_auditSink));

        // O painel é construído no arranque e mantido oculto. O modelo de visão
        // precisa existir desde já para acumular o que acontecer enquanto a
        // janela estiver fechada; construí-lo só na primeira abertura perderia
        // tudo o que o agente fez antes disso.
        _panel = new AgentWindow(_agentViewModel);

        // Carrega politica e trilha ja no arranque, com a janela oculta.
        _ = _agentViewModel.LoadAsync();

#if DEBUG
        _tray = new TrayIconHost(OpenPanel, ExitAgent, OpenSimulator);
#else
        _tray = new TrayIconHost(OpenPanel, ExitAgent);
#endif
        _tray.ShowBalloon("SafeUpload", "Proteção ativa. O agente está na bandeja do sistema.");

        // O gatilho de inspeção. A partir daqui o agente reage sozinho ao que o
        // usuário faz com seus arquivos, sem que ninguém precise abrir o painel.
        _interceptor = new SimulatedInterceptor(_inspection, _policyStore, _auditSink);
        _interceptor.Intercepted += OnIntercepted;
        _interceptor.Failed += OnInterceptionFailed;
        _ = StartInterceptionAsync();
    }

    /// <inheritdoc />
    protected override void OnExit(ExitEventArgs e)
    {
        if (_interceptor is not null)
        {
            _interceptor.Intercepted -= OnIntercepted;
            _interceptor.Failed -= OnInterceptionFailed;
            _interceptor.Dispose();
        }

        _tray?.Dispose();
        base.OnExit(e);
    }

    private async Task StartInterceptionAsync()
    {
        try
        {
            await _interceptor!.StartAsync(CancellationToken.None);
        }
        catch (Exception ex)
        {
            // Sem gatilho o agente vira uma janela de leitura, e o usuário
            // continuaria vendo "INTERCEPTANDO" no cartão de status. Falhar em
            // silêncio aqui seria mentir sobre o estado da proteção.
            MessageBox.Show(
                "O agente não conseguiu vigiar as pastas monitoradas e não vai interceptar "
                + $"operações nesta sessão.{Environment.NewLine}{Environment.NewLine}{ex.Message}",
                "SafeUpload — interceptação indisponível",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
    }

    /// <summary>
    /// Chegada de uma interceptação.
    ///
    /// O <c>FileSystemWatcher</c> dispara numa thread de fundo, e uma
    /// <c>ObservableCollection</c> alterada fora da thread da interface lança na
    /// hora — não é uma corrida rara que às vezes passa, é falha imediata. Por
    /// isso tudo o que toca o modelo de visão passa pelo Dispatcher.
    /// </summary>
    private void OnIntercepted(object? sender, InterceptionEventArgs e)
    {
        Current.Dispatcher.Invoke(() =>
        {
            if (e.AuditEvent is not null && _agentViewModel is not null)
            {
                _agentViewModel.Status.PrependActivity(e.AuditEvent);
                _agentViewModel.History.Prepend(e.AuditEvent);
            }

            // RN-005 — todo bloqueio notifica, com o painel aberto ou fechado.
            if (e.Result.IsBlocked)
            {
                ShowBlockNotification(e.Result, e.Operation, e.Quarantined);
            }
        });
    }

    /// <summary>
    /// Uma interceptação falhou. O arquivo seguiu seu caminho, porque o agente
    /// é fail-open, mas o usuário precisa saber que aquele arquivo não foi
    /// examinado — do contrário o cartão de status continuaria dizendo
    /// "INTERCEPTANDO" e a ausência de bloqueio seria lida como aprovação.
    /// </summary>
    private void OnInterceptionFailed(object? sender, InterceptionFailureEventArgs e)
    {
        Current.Dispatcher.Invoke(() => _tray?.ShowBalloon(
            "SafeUpload",
            $"Não foi possível examinar {System.IO.Path.GetFileName(e.Path)}. "
            + "A operação foi permitida sem inspeção."));
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

#if DEBUG

    /// <summary>
    /// Abre o simulador. Ferramenta de desenvolvimento: existe apenas em builds
    /// de depuração.
    /// </summary>
    private void OpenSimulator()
    {
        if (_simulator is not null)
        {
            if (_simulator.WindowState == WindowState.Minimized)
            {
                _simulator.WindowState = WindowState.Normal;
            }

            _simulator.Activate();
            return;
        }

        var viewModel = new SimulatorViewModel(
            _inspection!,
            _stalledInspection!,
            _policyStore,
            _auditSink,
            _cache,
            ShowBlockNotificationAsync);

        _simulator = new SimulatorWindow(viewModel);
        _simulator.Closed += (_, _) => _simulator = null;
        _simulator.Show();
    }

#endif

    /// <summary>
    /// RN-005 — todo bloqueio notifica. A janela não tem nenhuma forma de
    /// liberar o arquivo; ela existe para o usuário saber por que a operação
    /// não passou.
    /// </summary>
#if DEBUG
    private Task ShowBlockNotificationAsync(InspectionResult result, FileOperation operation)
    {
        ShowBlockNotification(result, operation, quarantined: false);
        return Task.CompletedTask;
    }

#endif

    private void ShowBlockNotification(InspectionResult result, FileOperation operation, bool quarantined)
    {
        // Uma notificação por vez. Vários bloqueios seguidos empilhariam
        // janelas no mesmo canto da tela, sobrepostas e ilegíveis.
        _notification?.Close();

        _notification = new BlockNotificationWindow(operation.FileName, result.Findings, quarantined);
        _notification.Closed += (_, _) => _notification = null;

#if DEBUG
        if (_simulator is { IsVisible: true })
        {
            _notification.Owner = _simulator;
        }
        else
#endif
        if (_panel is { IsVisible: true })
        {
            _notification.Owner = _panel;
        }

        _notification.Show();
    }

    private void ExitAgent()
    {
        // Encerramento explícito: é a única forma de derrubar o agente, já que
        // ShutdownMode é OnExplicitShutdown e o painel apenas se oculta ao ser
        // fechado.
        if (_panel is not null)
        {
            _panel.AllowClose = true;
            _panel.Close();
        }

        Shutdown();
    }
}
