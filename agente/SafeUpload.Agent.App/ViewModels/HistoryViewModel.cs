using System.Collections.ObjectModel;
using SafeUpload.Agent.App.Mvvm;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.App.ViewModels;

/// <summary>
/// A tela de histórico: até 500 eventos recentes autorizados pelo serviço, só leitura.
///
/// Não há filtro nem botão. A trilha é o registro do que o agente decidiu, e
/// oferecer ao usuário meios de recortá-la ou reordená-la sugeriria que ele
/// tem alguma influência sobre ela. Quem investiga de verdade usa o Centro de
/// Administração, que recebe estes mesmos eventos.
/// </summary>
public sealed class HistoryViewModel : ObservableObject
{
    private string _emptyMessage = "Aguardando o histórico do serviço";
    public string EmptyMessage
    {
        get => _emptyMessage;
        private set => SetProperty(ref _emptyMessage, value);
    }

    /// <summary>Eventos gravados, do mais recente para o mais antigo.</summary>
    public ObservableCollection<HistoryRowViewModel> Events { get; } = [];

    /// <summary>Verdadeiro quando a trilha ainda está vazia.</summary>
    public bool IsEmpty => Events.Count == 0;

    /// <summary>Substitui o histórico sem produzir notificações de bloqueio.</summary>
    public void ApplyHistory(HistoryNotification history)
    {
        if (!history.Available) { SetUnavailable(); return; }
        Events.Clear();
        foreach (var auditEvent in history.Events.DistinctBy(e => e.EventId).Take(HistoryNotification.MaximumEvents))
        {
            Events.Add(new HistoryRowViewModel(auditEvent));
        }

        OnPropertyChanged(nameof(IsEmpty));
        EmptyMessage = history.Truncated ? "Parte do histórico não pôde ser exibida" : "Nenhuma operação disponível para esta sessão";
        AvailabilityMessage = history.Truncated ? "Exibindo parte das operações disponíveis para esta sessão." :
            "Operações recentes desta sessão, da mais recente para a mais antiga.";
    }

    private string _availabilityMessage = "Aguardando o histórico do serviço";
    public string AvailabilityMessage
    {
        get => _availabilityMessage;
        private set => SetProperty(ref _availabilityMessage, value);
    }
    public void SetUnavailable()
    {
        EmptyMessage = "Histórico indisponível; aguardando o serviço";
        AvailabilityMessage = Events.Count == 0 ? EmptyMessage : "Serviço indisponível. Exibindo o último histórico recebido.";
    }

    /// <summary>
    /// Insere um evento recém-gravado no topo.
    ///
    /// Precisa ser chamado na thread da interface, pelo mesmo motivo do
    /// status: quem intercepta é um FileSystemWatcher, em thread de fundo.
    /// </summary>
    public bool Prepend(AuditEvent auditEvent)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);

        if (Events.Any(row => row.EventId == auditEvent.EventId)) return false;

        Events.Insert(0, new HistoryRowViewModel(auditEvent));
        while (Events.Count > HistoryNotification.MaximumEvents) Events.RemoveAt(Events.Count - 1);
        OnPropertyChanged(nameof(IsEmpty));
        return true;
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
        EventId = auditEvent.EventId;

        OccurredAt = auditEvent.OccurredAtUtc.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss");
        FileName = AuditSubject.Describe(auditEvent);
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
    public Guid EventId { get; }

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
