using System.Collections.ObjectModel;
using System.IO;
using System.Windows.Media;
using SafeUpload.Agent.App.Mvvm;
using SafeUpload.Agent.App.Simulation;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.App.ViewModels;

/// <summary>
/// O modelo de visão do simulador.
///
/// O simulador existe porque este mock não tem minifiltro: sem ele, nada
/// dispara uma inspeção. Aqui o usuário monta a operação à mão — arquivo,
/// destino e processo de origem — e o agente a julga pelo mesmo caminho de
/// código que usaria se a operação viesse do sistema de arquivos.
/// </summary>
public sealed class SimulatorViewModel : ObservableObject
{
    private readonly InspectionService _inspection;
    private readonly InspectionService _stalledInspection;
    private readonly IAuditSink _auditSink;
    private readonly IPolicyStore _policyStore;
    private readonly VerdictCache _cache;
    private readonly Func<InspectionResult, FileOperation, Task> _onBlocked;

    private DestinationOption _destination;
    private string _processName = "explorer.exe";
    private bool _simulateStall;
    private string _selectedFilePath = string.Empty;
    private string _statusMessage = "Arraste um arquivo para a área acima para simular um envio.";
    private bool _hasResult;
    private Policy? _policy;

    private string _verdictText = string.Empty;
    private Brush _verdictBrush = Brushes.Gray;
    private string _resultFileName = string.Empty;
    private string _resultReason = string.Empty;
    private string _resultElapsed = string.Empty;
    private bool _resultFromCache;
    private string _resultPolicyVersion = string.Empty;

    /// <summary>Compõe o modelo de visão com o motor e o estado local.</summary>
    public SimulatorViewModel(
        InspectionService inspection,
        InspectionService stalledInspection,
        IPolicyStore policyStore,
        IAuditSink auditSink,
        VerdictCache cache,
        Func<InspectionResult, FileOperation, Task> onBlocked)
    {
        _inspection = inspection ?? throw new ArgumentNullException(nameof(inspection));
        _stalledInspection = stalledInspection ?? throw new ArgumentNullException(nameof(stalledInspection));
        _policyStore = policyStore ?? throw new ArgumentNullException(nameof(policyStore));
        _auditSink = auditSink ?? throw new ArgumentNullException(nameof(auditSink));
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        _onBlocked = onBlocked ?? throw new ArgumentNullException(nameof(onBlocked));

        Destinations =
        [
            new DestinationOption("Mídia removível", DestinationKind.RemovableDrive, @"E:\pendrive"),
            new DestinationOption("Rede", DestinationKind.NetworkShare, @"\\servidor\publico"),
            new DestinationOption("Nuvem (pasta sincronizada)", DestinationKind.Cloud, string.Empty),
            new DestinationOption("Fora de escopo", DestinationKind.OutOfScope, @"C:\Temp")
        ];

        _destination = Destinations[0];

        RefreshQueueCommand = new RelayCommand(ReloadQueueAsync);
        CreateSamplesCommand = new RelayCommand(CreateSampleFilesAsync);
    }

    /// <summary>Destinos que o simulador sabe montar.</summary>
    public IReadOnlyList<DestinationOption> Destinations { get; }

    /// <summary>Fila de auditoria lida do queue.jsonl.</summary>
    public ObservableCollection<QueueRowViewModel> Queue { get; } = [];

    /// <summary>Recarrega a grade da fila.</summary>
    public RelayCommand RefreshQueueCommand { get; }

    /// <summary>Gera os arquivos de exemplo do roteiro de demonstração.</summary>
    public RelayCommand CreateSamplesCommand { get; }

    /// <summary>Destino escolhido para a operação.</summary>
    public DestinationOption Destination
    {
        get => _destination;
        set => SetProperty(ref _destination, value);
    }

    /// <summary>Processo que originaria a operação.</summary>
    public string ProcessName
    {
        get => _processName;
        set => SetProperty(ref _processName, value);
    }

    /// <summary>
    /// Injeta oito segundos de atraso na extração, acima do prazo de cinco
    /// segundos da política, para exercitar a RN-012.
    /// </summary>
    public bool SimulateStall
    {
        get => _simulateStall;
        set => SetProperty(ref _simulateStall, value);
    }

    /// <summary>Arquivo atualmente escolhido.</summary>
    public string SelectedFilePath
    {
        get => _selectedFilePath;
        private set
        {
            if (SetProperty(ref _selectedFilePath, value))
            {
                OnPropertyChanged(nameof(SelectedFileLabel));
            }
        }
    }

    /// <summary>Nome do arquivo escolhido, para exibição.</summary>
    public string SelectedFileLabel => string.IsNullOrEmpty(SelectedFilePath)
        ? "Nenhum arquivo escolhido"
        : Path.GetFileName(SelectedFilePath);

    /// <summary>Mensagem de acompanhamento mostrada na zona de arrastar.</summary>
    public string StatusMessage
    {
        get => _statusMessage;
        private set => SetProperty(ref _statusMessage, value);
    }

    /// <summary>Se já existe um resultado para mostrar.</summary>
    public bool HasResult
    {
        get => _hasResult;
        private set => SetProperty(ref _hasResult, value);
    }

    /// <summary>Veredito em português.</summary>
    public string VerdictText
    {
        get => _verdictText;
        private set => SetProperty(ref _verdictText, value);
    }

    /// <summary>Cor do veredito, vinda dos tokens da paleta.</summary>
    public Brush VerdictBrush
    {
        get => _verdictBrush;
        private set => SetProperty(ref _verdictBrush, value);
    }

    /// <summary>Arquivo do último resultado.</summary>
    public string ResultFileName
    {
        get => _resultFileName;
        private set => SetProperty(ref _resultFileName, value);
    }

    /// <summary>Explicação do motivo, quando não houve inspeção.</summary>
    public string ResultReason
    {
        get => _resultReason;
        private set => SetProperty(ref _resultReason, value);
    }

    /// <summary>Duração da decisão.</summary>
    public string ResultElapsed
    {
        get => _resultElapsed;
        private set => SetProperty(ref _resultElapsed, value);
    }

    /// <summary>Se a decisão veio do cache.</summary>
    public bool ResultFromCache
    {
        get => _resultFromCache;
        private set => SetProperty(ref _resultFromCache, value);
    }

    /// <summary>Versão da política aplicada.</summary>
    public string ResultPolicyVersion
    {
        get => _resultPolicyVersion;
        private set => SetProperty(ref _resultPolicyVersion, value);
    }

    /// <summary>Achados do último resultado, já mascarados.</summary>
    public ObservableCollection<FindingViewModel> Findings { get; } = [];

    /// <summary>Extensões vigiadas pela política, para exibição.</summary>
    public string MonitoredExtensions { get; private set; } = string.Empty;

    /// <summary>Pastas vigiadas pela política, para exibição.</summary>
    public string MonitoredPaths { get; private set; } = string.Empty;

    /// <summary>Categorias ativas na política, para exibição.</summary>
    public string ActiveCategories { get; private set; } = string.Empty;

    /// <summary>Resumo dos limites da política, para exibição.</summary>
    public string PolicySummary { get; private set; } = string.Empty;

    /// <summary>Caminho do policy.json em uso.</summary>
    public string PolicyPath => (_policyStore as LocalPolicyStore)?.PolicyFilePath ?? AgentPaths.PolicyFile;

    /// <summary>Caminho do queue.jsonl em uso.</summary>
    public string QueuePath => (_auditSink as LocalQueueAuditSink)?.QueueFilePath ?? AgentPaths.QueueFile;

    /// <summary>
    /// Deixa a janela pronta para uso assim que abre: política carregada,
    /// escopo preenchido e fila com o histórico. Uma tela vazia esperando o
    /// primeiro arquivo não mostra que o agente já está funcionando.
    /// </summary>
    public async Task InitializeAsync()
    {
        await ReloadPolicyAsync().ConfigureAwait(true);
        await ReloadQueueAsync().ConfigureAwait(true);
    }

    /// <summary>Recarrega a política e o resumo do escopo.</summary>
    public async Task ReloadPolicyAsync()
    {
        try
        {
            _policy = await _policyStore.LoadAsync(CancellationToken.None).ConfigureAwait(true);

            MonitoredExtensions = string.Join("  ", _policy.MonitoredScopes.Extensions.Order());
            MonitoredPaths = string.Join(
                Environment.NewLine,
                _policy.MonitoredScopes.DestinationPaths.DefaultIfEmpty("(nenhuma pasta específica)"));
            ActiveCategories = string.Join(", ", _policy.ActiveCategories.Select(CategoryLabels.Describe));
            PolicySummary =
                $"Versão {_policy.Version}  ·  limite {_policy.MaxFileSizeMb} MB  ·  "
                + $"prazo {_policy.InspectionTimeoutSeconds} s  ·  "
                + $"mídia removível {(_policy.MonitoredScopes.RemovableDrives ? "sim" : "não")}  ·  "
                + $"rede {(_policy.MonitoredScopes.NetworkPaths ? "sim" : "não")}";

            // A opção de nuvem aponta para dentro de uma pasta monitorada, que é
            // como um cliente de sincronização aparece no endpoint: uma pasta
            // local comum, vigiada pelo caminho e não por uma regra própria.
            var cloudRoot = _policy.MonitoredScopes.DestinationPaths.FirstOrDefault()
                ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "SafeUpload");

            Destinations[2].Path = Path.Combine(cloudRoot, "OneDrive");
        }
        catch (Exception ex)
        {
            // RN-009 chega aqui quando alguém edita o policy.json à mão.
            MonitoredExtensions = "—";
            MonitoredPaths = "—";
            ActiveCategories = "—";
            PolicySummary = $"Política inválida: {ex.Message}";
        }

        OnPropertyChanged(nameof(MonitoredExtensions));
        OnPropertyChanged(nameof(MonitoredPaths));
        OnPropertyChanged(nameof(ActiveCategories));
        OnPropertyChanged(nameof(PolicySummary));
    }

    /// <summary>Relê o queue.jsonl e recarrega a grade.</summary>
    public async Task ReloadQueueAsync()
    {
        var events = await _auditSink.ReadRecentAsync(200, CancellationToken.None).ConfigureAwait(true);

        Queue.Clear();
        foreach (var auditEvent in events)
        {
            Queue.Add(new QueueRowViewModel(auditEvent));
        }
    }

    /// <summary>
    /// Julga um arquivo com o contexto montado na tela.
    /// </summary>
    public async Task InspectAsync(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            StatusMessage = "Arquivo não encontrado.";
            return;
        }

        SelectedFilePath = filePath;
        StatusMessage = SimulateStall
            ? "Analisando com travamento simulado; o prazo da política corta em 5 s..."
            : "Analisando...";

        var info = new FileInfo(filePath);
        var operation = new FileOperation(
            info.FullName,
            info.Name,
            info.Extension.ToLowerInvariant(),
            info.Length,
            info.LastWriteTimeUtc,
            string.IsNullOrWhiteSpace(ProcessName) ? "explorer.exe" : ProcessName.Trim(),
            Environment.ProcessId,
            Destination.Path,
            Destination.Kind);

        if (SimulateStall)
        {
            // Um veredito em cache responderia antes de a extração começar, e o
            // travamento nunca aconteceria. Como o objetivo aqui é justamente
            // ver o prazo agir, o simulador força uma análise nova.
            _cache.Clear();
        }

        var service = SimulateStall ? _stalledInspection : _inspection;
        var result = await service.InspectAsync(operation, CancellationToken.None).ConfigureAwait(true);

        ShowResult(operation, result);
        await ReloadQueueAsync().ConfigureAwait(true);

        // RN-005 — bloqueio sempre notifica. É a única saída para o usuário
        // descobrir por que a operação não passou.
        if (result.IsBlocked)
        {
            await _onBlocked(result, operation).ConfigureAwait(true);
        }
    }

    private void ShowResult(FileOperation operation, InspectionResult result)
    {
        HasResult = true;
        ResultFileName = operation.FileName;
        VerdictText = VerdictLabels.Describe(result.Verdict);
        VerdictBrush = BrushFor(result);
        ResultElapsed = $"{result.ElapsedMs} ms";
        ResultFromCache = result.FromCache;
        ResultPolicyVersion = $"política v{result.PolicyVersion}";
        ResultReason = ReasonLabels.Describe(result.Reason);

        Findings.Clear();
        foreach (var finding in result.Findings)
        {
            Findings.Add(new FindingViewModel(
                CategoryLabels.Describe(finding.Category),
                finding.MaskedSnippet));
        }

        StatusMessage = result.InScope
            ? $"{VerdictText} — {operation.FileName}"
            : $"Fora do escopo monitorado — {operation.FileName}";
    }

    /// <summary>
    /// A cor do veredito sai dos tokens da paleta, os mesmos do painel web:
    /// vermelho para bloqueio, verde para aprovação, âmbar para liberado sem
    /// inspeção. O âmbar importa: liberado sem inspeção não é aprovado, e a cor
    /// não pode sugerir que o arquivo foi examinado e considerado limpo.
    /// </summary>
    private static Brush BrushFor(InspectionResult result) => result.Verdict switch
    {
        Verdict.Blocked => Token("Danger"),
        Verdict.Approved => Token("Success"),
        _ => Token("Warning")
    };

    private static Brush Token(string key) =>
        System.Windows.Application.Current?.TryFindResource(key) as Brush ?? Brushes.Gray;

    /// <summary>
    /// Cria, na pasta monitorada, os arquivos do roteiro de demonstração: um
    /// limpo, um com CPF e um acima do limite de tamanho.
    /// </summary>
    private async Task CreateSampleFilesAsync()
    {
        try
        {
            var folder = _policy?.MonitoredScopes.DestinationPaths.FirstOrDefault()
                ?? Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    "SafeUpload", "Escopo Monitorado");

            Directory.CreateDirectory(folder);

            await File.WriteAllTextAsync(
                Path.Combine(folder, "relatorio-limpo.txt"),
                "Relatório trimestral" + Environment.NewLine + "42 páginas, revisão 3." + Environment.NewLine)
                .ConfigureAwait(true);

            await File.WriteAllTextAsync(
                Path.Combine(folder, "cadastro-com-cpf.txt"),
                "Cadastro do cliente" + Environment.NewLine + "CPF: 529.982.247-25" + Environment.NewLine)
                .ConfigureAwait(true);

            var large = Path.Combine(folder, "arquivo-grande.txt");
            if (!File.Exists(large) || new FileInfo(large).Length < 25L * 1024 * 1024)
            {
                // 25 MB, acima do limite de 20 MB da política.
                var block = new string('a', 1024 * 1024);
                await using var writer = new StreamWriter(large, append: false);
                for (var i = 0; i < 25; i++)
                {
                    await writer.WriteAsync(block).ConfigureAwait(true);
                }
            }

            StatusMessage = $"Arquivos de exemplo criados em {folder}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Não foi possível criar os exemplos: {ex.Message}";
        }
    }
}

/// <summary>Um destino oferecido pelo simulador.</summary>
/// <param name="Label">Nome mostrado no seletor.</param>
/// <param name="Kind">Natureza do destino, que a política avalia.</param>
/// <param name="InitialPath">Caminho inicial associado.</param>
public sealed record DestinationOption(string Label, DestinationKind Kind, string InitialPath)
{
    /// <summary>Caminho de destino usado na operação.</summary>
    public string Path { get; set; } = InitialPath;

    /// <inheritdoc />
    public override string ToString() => Label;
}

/// <summary>Um achado mostrado na tela, já mascarado.</summary>
/// <param name="Category">Nome da categoria em português.</param>
/// <param name="MaskedSnippet">Trecho mascarado.</param>
public sealed record FindingViewModel(string Category, string MaskedSnippet);
