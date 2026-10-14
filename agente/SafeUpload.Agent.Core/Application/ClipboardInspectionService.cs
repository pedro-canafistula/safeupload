using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Application;

/// <summary>
/// O motor do canal de clipboard: atende os pedidos do aplicativo.
///
/// <para>Lê a política, pede a decisão a <see cref="ClipboardRules"/>, guarda o
/// estado da cópia e conta. Não conhece o pipe nem registra log: devolve a
/// resposta e, quando há algo a registrar, uma <see cref="ClipboardObservation"/>.
/// Quem registra é a ponte no serviço. É a mesma divisão do canal web
/// (<see cref="WebInspectionService"/> no Core, a ponte no serviço), e por isso
/// mora aqui, e não no serviço.</para>
///
/// <para><b>Medir, sem interferir.</b> Hoje o canal classifica e conta, mas
/// não grava evento de auditoria, não avisa e não bloqueia. O pedido
/// <c>paste</c> chega como uma sonda de foco ("o usuário foi para este
/// processo com o clipboard sujo"), e o veredito que volta não tem efeito no
/// aplicativo.</para>
///
/// <para><b>A falha sempre libera (RN-013).</b> Política que não carrega,
/// cópia que o canal não conhece, canal desligado: em todos, a resposta é
/// "limpo", "pode colar" ou "desligado".</para>
///
/// <para><b>O texto copiado não sai daqui (RN-006).</b> Ele entra, é varrido e
/// descartado. Nem a resposta nem a observação têm onde guardá-lo.</para>
/// </summary>
public sealed class ClipboardInspectionService
{
    /// <summary>
    /// Quanto tempo uma política carregada vale para este canal, quando o
    /// serviço a põe atrás de um <see cref="Infrastructure.CachedPolicyStore"/>.
    /// O mesmo intervalo do canal web.
    /// </summary>
    public static readonly TimeSpan PolicyLifetime = TimeSpan.FromSeconds(30);

    private readonly IPolicyStore _policyStore;
    private readonly ClipboardCopyStore _copies;
    private readonly ClipboardMetrics _metrics;

    /// <summary>Compõe o motor.</summary>
    public ClipboardInspectionService(
        IPolicyStore policyStore,
        ClipboardCopyStore copies,
        ClipboardMetrics metrics)
    {
        _policyStore = policyStore ?? throw new ArgumentNullException(nameof(policyStore));
        _copies = copies ?? throw new ArgumentNullException(nameof(copies));
        _metrics = metrics ?? throw new ArgumentNullException(nameof(metrics));
    }

    /// <summary>Os contadores atuais.</summary>
    public ClipboardMetricsSnapshot Metrics => _metrics.Snapshot();

    /// <summary>
    /// Decide um pedido já validado pelo protocolo.
    /// </summary>
    /// <param name="request">O pedido.</param>
    /// <param name="sessionId">Sessão do Windows de quem perguntou, se conhecida.</param>
    /// <param name="cancellationToken">Cancelamento.</param>
    public async Task<ClipboardOutcome> HandleAsync(
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
            return new ClipboardOutcome(
                FailOpen(request.Type),
                new ClipboardObservation(
                    ClipboardObservationKind.PolicyUnavailable,
                    _metrics.Snapshot(),
                    FailureType: ex.GetType().Name));
        }

        return request.Type switch
        {
            ClipboardProtocol.ClassifyType => Classify(request, sessionId, policy),
            ClipboardProtocol.PasteType => Paste(request, sessionId, policy),
            _ => State(policy)
        };
    }

    private static ClipboardOutcome State(Policy policy) =>
        new(new ClipboardResponse(ClipboardProtocol.StateType, Enabled: policy.EffectiveClipboard.IsEnabled));

    private ClipboardOutcome Classify(ClipboardRequest request, uint? sessionId, Policy policy)
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

        bool enabled = classification.Reason != ClipboardCopyReason.ChannelOff;
        ClipboardObservation? observation = null;

        if (enabled)
        {
            _metrics.RecordCopy(classification.Dirty);

            if (classification.Dirty)
            {
                observation = new ClipboardObservation(
                    ClipboardObservationKind.DirtyCopy,
                    _metrics.Snapshot(),
                    SourceProcess: request.SourceProcess,
                    Reason: classification.Reason,
                    Categories: classification.Categories);
            }
        }

        var response = new ClipboardResponse(
            ClipboardProtocol.ClassifyType,
            CopyId: copy.CopyId,
            Dirty: classification.Dirty,
            Categories: classification.Categories,
            Findings: classification.Findings.Select(static f => f.MaskedSnippet).ToList(),
            Enabled: enabled);

        return new ClipboardOutcome(response, observation);
    }

    private ClipboardOutcome Paste(ClipboardRequest request, uint? sessionId, Policy policy)
    {
        var copy = request.CopyId is null ? null : _copies.TryGet(sessionId, request.CopyId);

        // Cópia desconhecida: o serviço reiniciou, o identificador é de outra
        // sessão ou uma cópia nova já o substituiu. Sem saber o que está no
        // clipboard, libera.
        if (copy is null || !copy.Dirty)
        {
            return new ClipboardOutcome(new ClipboardResponse(
                ClipboardProtocol.PasteType,
                CopyId: request.CopyId,
                Verdict: ClipboardPasteVerdict.Allow));
        }

        var verdict = ClipboardRules.DecidePaste(
            copy.Dirty,
            copy.SourceProcess,
            request.DestinationProcess,
            policy.EffectiveClipboard);

        _metrics.RecordFocusWhileDirty(verdict);

        ClipboardObservation? observation = verdict == ClipboardPasteVerdict.Allow
            ? null
            : new ClipboardObservation(
                ClipboardObservationKind.EgressFocusWhileDirty,
                _metrics.Snapshot(),
                SourceProcess: copy.SourceProcess,
                DestinationProcess: request.DestinationProcess,
                Verdict: verdict);

        return new ClipboardOutcome(
            new ClipboardResponse(ClipboardProtocol.PasteType, CopyId: copy.CopyId, Verdict: verdict),
            observation);
    }

    // Sem política, a resposta libera e diz "desligado" a quem pergunta pelo
    // canal ou classifica: o aplicativo para de mandar texto enquanto a
    // política estiver quebrada, em vez de mandar para nada ser feito com ele.
    private static ClipboardResponse FailOpen(string type) =>
        type == ClipboardProtocol.PasteType
            ? new ClipboardResponse(type, Verdict: ClipboardPasteVerdict.Allow)
            : new ClipboardResponse(type, Verdict: ClipboardPasteVerdict.Allow, Enabled: false);
}
