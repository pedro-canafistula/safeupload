using System.Collections.ObjectModel;
using SafeUpload.Agent.App.Mvvm;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.App.ViewModels;

/// <summary>
/// A tela de histórico: a trilha de auditoria completa, só leitura.
///
/// Não há filtro nem botão. A trilha é o registro do que o agente decidiu, e
/// oferecer ao usuário meios de recortá-la ou reordená-la sugeriria que ele
/// tem alguma influência sobre ela. Quem investiga de verdade usa o Centro de
/// Administração, que recebe estes mesmos eventos.
/// </summary>
public sealed class HistoryViewModel : ObservableObject
{
    private const int MaxEvents = 500;

    private readonly IAuditSink _auditSink;

    /// <summary>Compõe a tela sobre a trilha de auditoria.</summary>
    public HistoryViewModel(IAuditSink auditSink) =>
        _auditSink = auditSink ?? throw new ArgumentNullException(nameof(auditSink));

    /// <summary>Eventos gravados, do mais recente para o mais antigo.</summary>
    public ObservableCollection<HistoryRowViewModel> Events { get; } = [];

    /// <summary>Verdadeiro quando a trilha ainda está vazia.</summary>
    public bool IsEmpty => Events.Count == 0;

    /// <summary>Carrega o histórico gravado.</summary>
    public async Task LoadAsync()
    {
        var events = await _auditSink.ReadRecentAsync(MaxEvents, CancellationToken.None).ConfigureAwait(true);

        Events.Clear();
        foreach (var auditEvent in events)
        {
            Events.Add(new HistoryRowViewModel(auditEvent));
        }

        OnPropertyChanged(nameof(IsEmpty));
    }

    /// <summary>
    /// Insere um evento recém-gravado no topo.
    ///
    /// Precisa ser chamado na thread da interface, pelo mesmo motivo do
    /// status: quem intercepta é um FileSystemWatcher, em thread de fundo.
    /// </summary>
    public void Prepend(AuditEvent auditEvent)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);

        Events.Insert(0, new HistoryRowViewModel(auditEvent));
        OnPropertyChanged(nameof(IsEmpty));
    }
}

/// <summary>
/// Uma linha do histórico.
///
/// Tudo o que aparece aqui é metadado ou trecho já mascarado pelo domínio
/// (RN-007). Não existe caminho por onde o valor original chegasse a esta
/// classe: o <see cref="AuditEvent"/> não tem campo capaz de carregá-lo.
/// </summary>
public sealed class HistoryRowViewModel
{
    /// <summary>Traduz um evento gravado para a linha da grade.</summary>
    public HistoryRowViewModel(AuditEvent auditEvent)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);

        OccurredAt = auditEvent.OccurredAtUtc.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss");
        FileName = auditEvent.FileName;
        Extension = auditEvent.Extension;
        Size = FormatSize(auditEvent.SizeBytes);
        Destination = auditEvent.DestinationPath;
        Process = auditEvent.ProcessName;
        Status = StatusPill.For(auditEvent.Verdict);

        Categories = auditEvent.Categories.Count == 0
            ? "—"
            : string.Join(", ", auditEvent.Categories.Select(CategoryLabels.Describe));

        MaskedSnippets = auditEvent.MaskedSnippets.Count == 0
            ? "—"
            : string.Join("   ", auditEvent.MaskedSnippets);

        Reason = auditEvent.NotInspectedReason is null
            ? "—"
            : ReasonLabels.Describe(auditEvent.NotInspectedReason);
    }

    /// <summary>Data e hora locais da decisão.</summary>
    public string OccurredAt { get; }

    /// <summary>Nome do arquivo.</summary>
    public string FileName { get; }

    /// <summary>Extensão do arquivo.</summary>
    public string Extension { get; }

    /// <summary>Tamanho legível.</summary>
    public string Size { get; }

    /// <summary>Destino da operação.</summary>
    public string Destination { get; }

    /// <summary>Processo de origem.</summary>
    public string Process { get; }

    /// <summary>Pílula do resultado.</summary>
    public StatusPill Status { get; }

    /// <summary>Categorias detectadas.</summary>
    public string Categories { get; }

    /// <summary>Trechos mascarados registrados.</summary>
    public string MaskedSnippets { get; }

    /// <summary>Motivo de não inspeção, quando houver.</summary>
    public string Reason { get; }

    private static string FormatSize(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:0.#} KB",
        _ => $"{bytes / (1024.0 * 1024.0):0.#} MB"
    };
}
