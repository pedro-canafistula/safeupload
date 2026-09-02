using System.Windows;
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
    private InspectionService? _stalledInspection;
    private AgentViewModel? _agentViewModel;
    private AgentWindow? _panel;
    private TrayIconHost? _tray;
    private SimulatorWindow? _simulator;
    private BlockNotificationWindow? _notification;

    /// <inheritdoc />
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        AgentPaths.EnsureRootDirectory();

        var extractors = ExtractorRegistry.CreateDefault();

        _inspection = new InspectionService(_policyStore, _auditSink, extractors, _cache);

        // O mesmo motor, com os extratores embrulhados por um atraso de oito
        // segundos. É assim que o simulador demonstra a RN-012 sem que o motor
        // saiba que está sendo simulado.
        _stalledInspection = new InspectionService(
            _policyStore,
            _auditSink,
            StalledTextExtractor.Wrap(extractors, StalledTextExtractor.DefaultDelay),
            _cache);

        _agentViewModel = new AgentViewModel(
            new StatusViewModel(_policyStore, _auditSink),
            new HistoryViewModel(_auditSink));

        // O painel é construído no arranque e mantido oculto. O modelo de visão
        // precisa existir desde já para acumular o que acontecer enquanto a
        // janela estiver fechada; construí-lo só na primeira abertura perderia
        // tudo o que o agente fez antes disso.
        _panel = new AgentWindow(_agentViewModel);

        _tray = new TrayIconHost(OpenPanel, OpenSimulator, ExitAgent);
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

    /// <summary>
    /// RN-005 — todo bloqueio notifica. A janela não tem nenhuma forma de
    /// liberar o arquivo; ela existe para o usuário saber por que a operação
    /// não passou.
    /// </summary>
    private Task ShowBlockNotificationAsync(InspectionResult result, FileOperation operation)
    {
        // Uma notificação por vez. Vários bloqueios seguidos empilhariam
        // janelas no mesmo canto da tela, sobrepostas e ilegíveis.
        _notification?.Close();

        _notification = new BlockNotificationWindow(operation.FileName, result.Findings);
        _notification.Closed += (_, _) => _notification = null;

        if (_simulator is { IsVisible: true })
        {
            _notification.Owner = _simulator;
        }
        else if (_panel is { IsVisible: true })
        {
            _notification.Owner = _panel;
        }

        _notification.Show();
        return Task.CompletedTask;
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
