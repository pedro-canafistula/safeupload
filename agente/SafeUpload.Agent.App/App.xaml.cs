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
/// A composição é feita à mão, aqui, num único lugar. São seis objetos com
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
    private TrayIconHost? _tray;
    private SimulatorWindow? _simulator;

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

        _tray = new TrayIconHost(OpenSimulator, ShowPolicyVersion, ExitAgent);

        // O agente sobe protegendo e sem roubar a tela: a única presença é o
        // ícone na bandeja.
        _tray.ShowBalloon("SafeUpload", "Proteção ativa. O agente está na bandeja do sistema.");
    }

    /// <inheritdoc />
    protected override void OnExit(ExitEventArgs e)
    {
        _tray?.Dispose();
        base.OnExit(e);
    }

    private void OpenSimulator()
    {
        if (_simulator is not null)
        {
            // Já aberto: traz para a frente em vez de abrir uma segunda cópia,
            // que teria a própria fila desatualizada.
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
    /// RN-005 — todo bloqueio notifica. A janela é modal em relação ao
    /// simulador para que o usuário veja o motivo antes de tentar de novo, e
    /// não tem nenhuma forma de liberar o arquivo.
    /// </summary>
    private Task ShowBlockNotificationAsync(InspectionResult result, FileOperation operation)
    {
        var notification = new BlockNotificationWindow(operation.FileName, result.Findings);

        if (_simulator is not null)
        {
            notification.Owner = _simulator;
        }

        notification.ShowDialog();
        return Task.CompletedTask;
    }

    private async void ShowPolicyVersion()
    {
        string message;

        try
        {
            var policy = await _policyStore.LoadAsync(CancellationToken.None);

            message = $"""
                Versão da política: {policy.Version}
                Categorias ativas: {string.Join(", ", policy.ActiveCategories.Select(CategoryLabels.Describe))}
                Extensões vigiadas: {string.Join(" ", policy.MonitoredScopes.Extensions.Order())}
                Limite de tamanho: {policy.MaxFileSizeMb} MB
                Prazo de inspeção: {policy.InspectionTimeoutSeconds} s

                Arquivo: {_policyStore.PolicyFilePath}
                Fila: {_auditSink.QueueFilePath}
                """;
        }
        catch (Exception ex)
        {
            message = $"Não foi possível carregar a política.{Environment.NewLine}{Environment.NewLine}{ex.Message}";
        }

        MessageBox.Show(message, "SafeUpload — política vigente", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void ExitAgent()
    {
        // Encerramento explícito: é a única forma de derrubar o agente, já que
        // ShutdownMode é OnExplicitShutdown.
        Shutdown();
    }
}
