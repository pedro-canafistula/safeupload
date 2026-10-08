using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Service.Clipboard;

/// <summary>
/// Atende os dois pedidos do canal de clipboard.
///
/// <para>É a camada entre o pipe e <see cref="ClipboardRules"/>: lê a política,
/// pede a decisão às regras, guarda o estado da cópia e conta. Não conhece o
/// pipe, de modo que dá para testar tudo sem abrir um.</para>
///
/// <para><b>Fase 1 — medir, sem interferir.</b> O serviço classifica e conta,
/// mas não grava evento de auditoria, não notifica e não bloqueia. O pedido
/// <c>paste</c> chega aqui como uma sonda de foco ("o usuário foi para este
/// processo com o clipboard sujo"), e o veredito que volta não tem efeito
/// nenhum no aplicativo. Na Fase 3 o mesmo pedido passa a ser feito no Ctrl+V
/// e o veredito passa a valer.</para>
///
/// <para><b>A falha sempre libera (RN-013).</b> Política que não carrega,
/// cópia que o serviço não conhece, canal desligado: em todos, a resposta é
/// "limpo" ou "pode colar".</para>
///
/// <para><b>O texto copiado não é registrado em lugar nenhum (RN-006).</b>
/// Ele entra aqui, é varrido e descartado. Os logs têm contagens, categorias e
/// nomes de processo, nunca o texto nem o trecho achado.</para>
/// </summary>
public sealed class ClipboardService
{
    private readonly IPolicyStore _policyStore;
    private readonly ClipboardCopyStore _copies;
    private readonly ClipboardMetrics _metrics;
    private readonly ILogger<ClipboardService> _logger;

    /// <summary>Compõe o serviço.</summary>
    public ClipboardService(
        IPolicyStore policyStore,
        ClipboardCopyStore copies,
        ClipboardMetrics metrics,
        ILogger<ClipboardService> logger)
    {
        _policyStore = policyStore ?? throw new ArgumentNullException(nameof(policyStore));
        _copies = copies ?? throw new ArgumentNullException(nameof(copies));
        _metrics = metrics ?? throw new ArgumentNullException(nameof(metrics));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>Os contadores atuais.</summary>
    public ClipboardMetricsSnapshot Metrics => _metrics.Snapshot();

    /// <summary>
    /// Decide um pedido já validado pelo protocolo.
    /// </summary>
    /// <param name="request">O pedido.</param>
    /// <param name="sessionId">Sessão do Windows de quem perguntou, se conhecida.</param>
    /// <param name="cancellationToken">Cancelamento.</param>
    public async Task<ClipboardResponse> HandleAsync(
        ClipboardRequest request,
        uint? sessionId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        Policy policy;

        try
        {
            policy = await _policyStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Só o tipo da exceção: a mensagem de uma política inválida pode
            // citar caminhos, e o canal não precisa disso para falhar aberto.
            _logger.LogWarning(
                "Politica indisponivel no canal de clipboard ({Tipo}). Liberando.",
                ex.GetType().Name);

            return FailOpen(request.Type);
        }

        return request.Type == ClipboardProtocol.ClassifyType
            ? Classify(request, sessionId, policy)
            : Paste(request, sessionId, policy);
    }

    private ClipboardResponse Classify(ClipboardRequest request, uint? sessionId, Policy policy)
    {
        var classification = ClipboardRules.Classify(
            request.Text ?? string.Empty,
            request.TextLength,
            request.SourceProcess,
            policy);

        // Registra sempre, inclusive com o canal desligado: uma cópia limpa
        // precisa substituir a suja que estava em vigor, e a política pode ter
        // mudado entre uma cópia e outra.
        var copy = _copies.Register(sessionId, classification.Dirty, request.SourceProcess);

        if (classification.Reason != ClipboardCopyReason.ChannelOff)
        {
            _metrics.RecordCopy(classification.Dirty);

            if (classification.Dirty)
            {
                var snapshot = _metrics.Snapshot();

                _logger.LogInformation(
                    "Clipboard sujo: motivo {Motivo}, categorias [{Categorias}], origem {Origem}. " +
                    "Copias {Copias}, sujas {Sujas}.",
                    classification.Reason,
                    string.Join(", ", classification.Categories),
                    request.SourceProcess ?? "(desconhecida)",
                    snapshot.Copies,
                    snapshot.DirtyCopies);
            }
        }

        return new ClipboardResponse(
            ClipboardProtocol.ClassifyType,
            CopyId: copy.CopyId,
            Dirty: classification.Dirty,
            Categories: classification.Categories,
            Findings: classification.Findings.Select(static f => f.MaskedSnippet).ToList());
    }

    private ClipboardResponse Paste(ClipboardRequest request, uint? sessionId, Policy policy)
    {
        var copy = request.CopyId is null ? null : _copies.TryGet(sessionId, request.CopyId);

        // Cópia desconhecida: o serviço reiniciou, o identificador é de outra
        // sessão ou uma cópia nova já o substituiu. Sem saber o que está no
        // clipboard, libera.
        if (copy is null || !copy.Dirty)
        {
            return new ClipboardResponse(
                ClipboardProtocol.PasteType,
                CopyId: request.CopyId,
                Verdict: ClipboardPasteVerdict.Allow);
        }

        var verdict = ClipboardRules.DecidePaste(
            copy.Dirty,
            copy.SourceProcess,
            request.DestinationProcess,
            policy.EffectiveClipboard);

        _metrics.RecordFocusWhileDirty(verdict);

        if (verdict != ClipboardPasteVerdict.Allow)
        {
            var snapshot = _metrics.Snapshot();

            _logger.LogInformation(
                "Foco em destino de saida com o clipboard sujo: {Destino} (origem {Origem}, veredito {Veredito}). " +
                "Total {Total} de {Trocas} trocas de foco.",
                request.DestinationProcess ?? "(desconhecido)",
                copy.SourceProcess ?? "(desconhecida)",
                verdict,
                snapshot.FocusOnEgressWhileDirty,
                snapshot.FocusChangesWhileDirty);
        }

        return new ClipboardResponse(
            ClipboardProtocol.PasteType,
            CopyId: copy.CopyId,
            Verdict: verdict);
    }

    private static ClipboardResponse FailOpen(string type) =>
        new(type, Verdict: ClipboardPasteVerdict.Allow);
}
